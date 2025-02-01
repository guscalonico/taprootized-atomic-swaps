extern crate config as exconfig;
use crate::swap_participant::secp256k1::Scalar;

use anyhow::{anyhow, Context, Result};
use bdk_bitcoind_rpc::bitcoincore_rpc::{Client, RpcApi};
use bdk_wallet::descriptor::IntoWalletDescriptor;
use bdk_wallet::{rusqlite, KeychainKind, PersistedWallet, SignOptions, LocalOutput};
use ethers::prelude::{LocalWallet, SignerMiddleware};
use ethers::providers::{Middleware, Provider as EthereumClient, Provider, StreamExt, Ws};
use ethers::signers::{LocalWallet as EthereumWallet, Signer};
use ethers::types::U256;
use ethers::types::{Address as EthereumAddress, TxHash};
use ethers::utils::Units::Gwei;
use miniscript::bitcoin::key::{Keypair, Secp256k1};
use miniscript::bitcoin::secp256k1::{self, All, PublicKey, SecretKey};
use miniscript::bitcoin::{self, Address, Amount, CompressedPublicKey, FeeRate, PrivateKey, Txid};
use miniscript::descriptor::{TapTree, Tr};
use miniscript::policy::Concrete;
use miniscript::Descriptor;
use num::{bigint::Sign, BigInt, BigUint, One, ToPrimitive, Zero};
use rand::rngs::ThreadRng;
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{Read, Write};
use std::ops::{Add, Div, Mul};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{io, thread};

use rapidsnark::{groth16_prover, groth16_verifier};
use wallet_helpers::load_wallet;
use witness_calculator::WitnessCalculator;

use crate::config::{CircomConfig, Config, SwapParams, WalletsConfig};
use crate::depositor_contract::{Depositor as DepositorContract, Depositor};

/// Index of the pubkey's X last element in the Atomic-swap ZK proof public signals.
const PUBSIGNALS_PUBKEY_X_END: usize = 3;

/// Index of the pubkey's Y last element in the Atomic-swap ZK proof public signals.
const PUBSIGNALS_PUBKEY_Y_END: usize = 7;

/// Index of the secret hash last in the Atomic-swap ZK proof public signals.
const PUBSIGNALS_SECRET_HASH_INDEX: usize = 8;

/// Number of the BDK wallet's sync tries to find the taproot atomic-swap transaction on-chain that
/// has been published by a counterparty.
const MAX_NUMBER_OF_ATTEMPTS_TO_SYNC: usize = 300;

/// Delay between attempts to sync the BDK wallet to find the taproot atomic-swap transaction.
const DELAY_BETWEEN_SYNC_ATTEMPT_SEC: u64 = 5;

pub struct ParticipantKeys {
    pub bitcoin: Keypair,
    pub ethereum: Keypair,
}

impl ParticipantKeys {
    pub fn from_config(config: &WalletsConfig, secp_ctx: &Secp256k1<All>) -> Self {
        Self {
            bitcoin: Keypair::from_secret_key(secp_ctx, &config.bitcoin_private_key),
            ethereum: Keypair::from_secret_key(secp_ctx, &config.ethereum_private_key),
        }
    }
}

pub struct SwapParticipant {
    name: String,
    keys: ParticipantKeys,

    db_key_path: String,

    swap_params: SwapParams,

    /// Swap secret that it needed to spend locked money from either Bitcoin or Ethereum
    /// atomic-swap.
    ///
    /// It is [`Some`] only after either [`Self::new_atomic_swap`] for swap initiator or after
    /// counterparty noticed initiator withdrawal transaction.
    swap_secret: Option<[u8; 32]>,

    /// Posidon hash of the swap secret.
    ///
    /// It is [`Some`] only after either [`Self::new_atomic_swap`] for swap initiator or
    /// [`Self::accept_atomic_swap`] for swap counterparty.
    swap_secret_hash: Option<[u8; 32]>,

    /// Counterparty's Bitcoin public key that is used as a revocation key in Taprootized
    /// atomic-swap transaction.
    ///
    /// It is [`Some`] only after [`Self::accept_atomic_swap`] and only for counterparty.
    counterparty_bitcoin_pubkey: Option<PublicKey>,

    atomic_swap_contract_address: EthereumAddress,
    circom: CircomConfig,
    bitcoin_client: Client,
    ethereum_client: EthereumClient<Ws>,

    bitcoin_wallet: PersistedWallet<rusqlite::Connection>,
    ethereum_wallet: EthereumWallet,
}

unsafe impl Send for SwapParticipant {}
unsafe impl Sync for SwapParticipant {}

impl SwapParticipant {
    pub async fn from_config(
        name: String,
        config: &Config,
        wallets_config: &WalletsConfig,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Self> {
        let keys = ParticipantKeys::from_config(wallets_config, secp_ctx);
        let db_key_path = wallets_config.db_path.clone();

        let ethereum_client = config
            .ethereum_client()
            .await
            .context("failed to initialize Ethereum RPC client")?;

        let chain_id = ethereum_client.get_chainid().await?;

        let ethereum_wallet =
            EthereumWallet::from_bytes(&wallets_config.ethereum_private_key.secret_bytes())?
                .with_chain_id(chain_id.as_u64());

        let (bitcoin_wallet, bitcoin_client) = config
            .bitcoin_wallet(wallets_config.bitcoin_private_key, &wallets_config.db_path)
            .context("failed to initialize Bitcoin wallet with its RPC client")?;

        println!("Initialized new participant with wallets: ");
        println!("Bitcoin P2WPKH address");
        println!("Ethereum address: {}", ethereum_wallet.address());

        Ok(Self {
            name,
            keys,
            db_key_path,
            counterparty_bitcoin_pubkey: None,
            swap_secret: None,
            swap_secret_hash: None,
            swap_params: config.swap_params.clone(),
            atomic_swap_contract_address: config.atomic_swap_contract_address,
            circom: config.circom.clone(),
            bitcoin_client,
            ethereum_client,
            bitcoin_wallet,
            ethereum_wallet,
        })
    }

    pub fn bitcoin_public_key(&self) -> secp256k1::PublicKey {
        self.keys.bitcoin.public_key()
    }

    pub fn ethereum_address(&self) -> EthereumAddress {
        self.ethereum_wallet.address()
    }

    pub fn new_atomic_swap(
        &mut self,
        sats_to_swap: u64,
        counterparty_bitcoin_pubkey: secp256k1::PublicKey,
        rng: &mut ThreadRng,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<(String, String, secp256k1::PublicKey)> {
        println!("\n= {} starts atomic-swap", self.name);

        let swap_secret = secp256k1::SecretKey::new(rng);
        self.swap_secret = Some(swap_secret.secret_bytes());

        println!("| Swap k secret: {}", swap_secret.display_secret());

        println!("| Calculating zero-knowledge proof...");
        let (proof, pubsignals) = self
            .generate_swap_proof(swap_secret)
            .context("failed to generate atomic-swap proof")?;

        let (swap_pubkey, swap_secret_hash) =
            parse_atomic_swap_proof_pubsignals(pubsignals.clone())?;
        self.swap_secret_hash = Some(swap_secret_hash);

        println!("| Swap k public: {}", swap_pubkey);
        println!("| Swap secret's hash: {}", hex::encode(swap_secret_hash));

        let swap_pubkey = swap_secret.public_key(secp_ctx);
        let escrow_pubkey = swap_pubkey
            .combine(&counterparty_bitcoin_pubkey)
            .expect("It's impossible to fail for 2 different public keys");

        let tx_id = self
            .send_atomic_swap_tx_to_bitcoin(sats_to_swap, escrow_pubkey, secp_ctx)
            .context("failed to send swap tx to Bitcoin")?;
        println!(
            "| Taprootized atomic-swap transaction has been sent to Bitcoin: {}",
            tx_id
        );

        Ok((proof, pubsignals, escrow_pubkey))
    }

    pub async fn accept_atomic_swap(
        &mut self,
        proof: String,
        pubsignals: String,
        counterparty_bitcoin_pubkey: PublicKey,
        counterparty_ethereum_address: EthereumAddress,
    ) -> Result<()> {
        println!("\n= {} accepts atomic-swap", self.name);

        self.counterparty_bitcoin_pubkey = Some(counterparty_bitcoin_pubkey);

        println!("| Verifying zero-knowledge proof...");
        if !self.verify_swap_proof(proof, pubsignals.clone())? {
            return Err(anyhow!("invalid atomic-swap proof"));
        }

        let (swap_pubkey, swap_secret_hash) = parse_atomic_swap_proof_pubsignals(pubsignals)?;
        self.swap_secret_hash = Some(swap_secret_hash);

        let swap_transaction_found = self
            .check_atomic_swap_tx_appeared_on_bitcoin(swap_pubkey, counterparty_bitcoin_pubkey)
            .context("failed to check if atomic-swap transaction appeared in Bitcoin")?;

        if !swap_transaction_found {
            return Err(anyhow!(
                "taproot atomic-swap transaction hasn't appeared; swap_pubkey: {swap_pubkey}"
            ));
        }

        let tx_id = self
            .send_atomic_swap_tx_to_ethereum(swap_secret_hash, counterparty_ethereum_address)
            .await?;

        println!(
            "| Atomic-swap transaction has been sent to Ethereum: {}",
            tx_id
        );

        Ok(())
    }

    pub async fn listen_to_deposit_events(self) -> Result<()> {
        let Some(swap_secret_hash) = self.swap_secret_hash else {
            return Err(anyhow!("swap secret hash is absent"));
        };

        let Some(swap_secret) = self.swap_secret else {
            return Err(anyhow!("swap secret is absent"));
        };

        let start_block = self.ethereum_client.get_block_number().await?;
        let contract = self.deposit_contract();
        let events = contract.deposited_filter().from_block(start_block);

        let mut deposits = events.subscribe().await?;
        // TODO: Here we also MUST wait for the CSV of our atomic-swap transaction in Bitcoin.
        // If we can spend the Bitcoin transaction with revocation (internal) key - we must do it.
        while let Some(log) = deposits.next().await {
            let deposit = log?;

            if deposit.secret_hash == swap_secret_hash {
                break;
            }
        }

        let tx_id = self.withdraw_money_from_swap_contract(swap_secret).await?;
        println!(
            "\n= {} has spent locked money on Ethereum in: {}",
            self.name, tx_id
        );

        Ok(())
    }

    pub async fn listen_to_withdraw_events(self) -> Result<()> {
        let Some(swap_secret_hash) = self.swap_secret_hash else {
            return Err(anyhow!("swap secret hash is absent"));
        };

        let Some(counterparty_bitcoin_pubkey) = self.counterparty_bitcoin_pubkey else {
            return Err(anyhow!("counterparty bitcoin pubkey is absent"));
        };

        let start_block = self.ethereum_client.get_block_number().await?;
        let contract = self.deposit_contract();
        let events = contract.withdrawn_filter().from_block(start_block - 5);

        let mut swap_secret = [0u8; 32];

        let mut withdrawals = events.subscribe().await?;

        // TODO: Here we also MUST wait for the CSV of our atomic-swap transaction in Bitcoin.
        // If we can spend the Bitcoin transaction with revocation (internal) key - we must do it.
        while let Some(log) = withdrawals.next().await {
            let withdrawal = log?;

            if withdrawal.secret_hash == swap_secret_hash {
                withdrawal.secret.to_big_endian(&mut swap_secret);
                break;
            }
        }

        let tx_id = self.withdraw_money_from_taprootized_swap_tx(
            counterparty_bitcoin_pubkey,
            secp256k1::SecretKey::from_slice(&swap_secret)
                .expect("It's impossible to fail for [u8;32]"),
        )?;
        println!(
            "\n= {} has spent locked money on Bitcoin in: {}",
            self.name, tx_id
        );

        Ok(())
    }
}

impl SwapParticipant {
    fn generate_swap_proof(&self, swap_secret: secp256k1::SecretKey) -> Result<(String, String)> {
        let swap_secret_bigint = BigInt::from_bytes_be(Sign::Plus, &swap_secret.secret_bytes());
        let swap_secret_u64array = u256_to_u64array(swap_secret_bigint)
            .expect("Secret is always lseq than u256")
            .iter()
            .map(|val| BigInt::from(*val))
            .collect();

        let mut prover_inputs = HashMap::new();
        prover_inputs.insert("secret".to_string(), swap_secret_u64array);

        let mut witness_calculator =
            WitnessCalculator::new(self.circom.witnes_calculator_path.clone())
                .map_err(|err| anyhow!(err.to_string()))?;

        // This process takes most of the time of the proof generation because of WASM. The C
        // binding can be used to speed it up.
        let witness = witness_calculator
            .calculate_witness(prover_inputs, true)
            .map_err(|err| anyhow!(err.to_string()))?;

        let mut proving_key_file = File::open(self.circom.proving_key_path.clone())
            .context("failed to open proving key file")?;
        let mut proving_key = Vec::new();
        proving_key_file
            .read_to_end(&mut proving_key)
            .context("failed to read proving key file")?;

        let proof =
            groth16_prover(&proving_key, &witness).context("failed to generate groth16 proof")?;

        Ok(proof)
    }

    fn verify_swap_proof(&self, proof: String, pubsignals_json: String) -> Result<bool> {
        let mut verification_key_file = File::open(self.circom.verification_key_path.clone())
            .context("failed to open verification key file")?;
        let mut verification_key = Vec::new();
        verification_key_file
            .read_to_end(&mut verification_key)
            .context("failed to read verification key file")?;

        let is_proof_valid = groth16_verifier(
            &verification_key,
            proof.as_bytes(),
            pubsignals_json.as_bytes(),
        )
        .context("failed to verify proof")?;

        Ok(is_proof_valid)
    }

    fn deposit_contract(&self) -> Depositor<SignerMiddleware<Provider<Ws>, LocalWallet>> {
        let signer = Arc::new(SignerMiddleware::new(
            self.ethereum_client.clone(),
            self.ethereum_wallet.clone(),
        ));

        DepositorContract::new(self.atomic_swap_contract_address, signer)
    }

    async fn withdraw_money_from_swap_contract(&self, swap_secret: [u8; 32]) -> Result<TxHash> {
        let contract = self.deposit_contract();

        let contract_call = contract.withdraw(U256::from(swap_secret));
        let pending_tx = contract_call.send().await?;

        Ok(pending_tx.tx_hash())
    }

    fn withdraw_money_from_taprootized_swap_tx(
        &self,
        counterparty_bitcoin_pubkey: PublicKey,
        swap_secret: SecretKey,
    ) -> Result<Txid> {
        let network = self.bitcoin_wallet.network();
        let escrow_privkey = PrivateKey::new(
            swap_secret
                .add_tweak(&Scalar::from_be_bytes(
                    self.keys.bitcoin.secret_key().secret_bytes(),
                )?)
                .expect("It's impossible to fail for 2 different public keys"),
            network,
        );
        let revocation_pubkey = bitcoin::PublicKey::new(counterparty_bitcoin_pubkey);

        let taproot_descriptor = Descriptor::Tr(Tr::from_str(&format!(
            "{},and_v(v:pk({},older({})))",
            escrow_privkey, revocation_pubkey, self.swap_params.bitcoin_csv_delay
        ))?);

        let (mut wallet, _) =
            load_wallet(&self.db_key_path, network, Some(taproot_descriptor), None)?;

        let wallet_policy = wallet.policies(KeychainKind::External)?.unwrap();
        let mut path = BTreeMap::new();
        // We need to use the first leaf of the script path spend, hence the second policy
        // If you're not sure what's happening here, no worries, this is bit tricky :)
        // You can learn more here: https://docs.rs/bdk/latest/bdk/wallet/tx_builder/struct.TxBuilder.html#method.policy_path
        path.insert(wallet_policy.id, vec![0]);

        let mut psbt = {
            //Partially Signed Bitcoin Transaction
            let mut builder = wallet.build_tx();

            let compressed_pubkey = CompressedPublicKey(self.keys.bitcoin.public_key());
            let recepient_address =
                bitcoin::Address::p2wpkh(&compressed_pubkey, self.bitcoin_wallet.network());

            let feerate = self
                .bitcoin_client
                .estimate_smart_fee(2, None)
                .map(|fee_result| fee_result.fee_rate.map(|amount| amount.to_sat()))
                .unwrap_or_else(|err| {
                    println!("\nFailed to estimate Bitcoin feerate for withdraw: {}", err);
                    print!("Input your feerate sat/vByte (e.g. '60'): ");

                    io::stdout().flush().unwrap();
                    let mut input_feerate = String::new();
                    io::stdin()
                        .read_line(&mut input_feerate)
                        .expect("Failed to read line");
                    let feerate: u32 = input_feerate.trim().parse().expect("Input not an integer");

                    bitcoin::FeeRate::from_sat_per_vb(feerate.into())
                        .map(|fee| fee.to_sat_per_kwu())
                })
                .expect("Could not calculate feerate");

            builder
                .fee_rate(FeeRate::from_sat_per_kwu(feerate))
                .drain_wallet()
                .drain_to(recepient_address.script_pubkey())
                .policy_path(path, KeychainKind::External);

            builder.finish()?
        };

        let is_finalized = wallet.sign(&mut psbt, SignOptions::default())?;

        if !is_finalized {
            return Err(anyhow!("failed to sign and finalize a transaction"));
        }

        let txid = psbt.unsigned_tx.compute_txid();

        self.bitcoin_client
            .send_raw_transaction(&psbt.extract_tx()?)?;

        Ok(txid)
    }

    async fn send_atomic_swap_tx_to_ethereum(
        &self,
        swap_secret_hash: [u8; 32],
        counterparty_ethereum_address: EthereumAddress,
    ) -> Result<TxHash> {
        let contract = self.deposit_contract();

        let wei_to_send = U256::from(self.swap_params.gwei_to_swap).mul(10u32.pow(Gwei.as_num()));
        let mut contract_call = contract.deposit(
            counterparty_ethereum_address,
            swap_secret_hash,
            U256::from(self.swap_params.ethereum_timelock_secs),
        );
        contract_call.tx.set_value(wei_to_send);
        let pending_tx = contract_call.send().await?;

        Ok(pending_tx.tx_hash())
    }

    fn send_atomic_swap_tx_to_bitcoin(
        &mut self,
        sats_to_swap: u64,
        escrow_pubkey: secp256k1::PublicKey,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Txid> {
        let revocation_pubkey = self.keys.bitcoin.public_key();

        let taptree_policy_str = &format!(
            "and(older({}),pk({}))",
            self.swap_params.bitcoin_csv_delay, revocation_pubkey
        );
        let taptree_policy = Concrete::<String>::from_str(taptree_policy_str)?.compile()?;
        let taptree = TapTree::Leaf(Arc::new(taptree_policy));

        let taproot_descriptor = Descriptor::new_tr(escrow_pubkey.to_string(), Some(taptree))?
            .to_string()
            .into_wallet_descriptor(secp_ctx, self.bitcoin_wallet.network())?
            .0;

        // We need it to easy get the address from the descriptor
        let (wallet, _) = load_wallet(
            &self.db_key_path,
            self.bitcoin_wallet.network(),
            Some(taproot_descriptor),
            None,
        )?;

        //TODO: double check address index used
        let taproot_address = wallet.peek_address(KeychainKind::External, 0).address;

        let tx_id = self
            .send_sats_to_specified_address(sats_to_swap, taproot_address.clone())
            .context(format!(
                "failed to send {} satoshis to {}",
                sats_to_swap, taproot_address
            ))?;

        Ok(tx_id)
    }

    fn send_sats_to_specified_address(
        &mut self,
        sats_amount: u64,
        address: Address,
    ) -> Result<Txid> {
        let _ok = self.bitcoin_wallet.start_full_scan().build().chain_tip();

        let mut psbt = {
            let mut tx_builder = self.bitcoin_wallet.build_tx();

            let feerate = self
                .bitcoin_client
                .estimate_smart_fee(2, None)
                .map(|fee_result| fee_result.fee_rate.map(|amount| amount.to_sat()))
                .unwrap_or_else(|err| {
                    println!("| Failed to estimate Bitcoin feerate: {}", err);
                    print!("| Input your feerate sat/vByte (e.g. '60'): ");

                    io::stdout().flush().unwrap();
                    let mut input_feerate = String::new();
                    io::stdin()
                        .read_line(&mut input_feerate)
                        .expect("Failed to read line");
                    let feerate: u32 = input_feerate.trim().parse().expect("Input not an integer");

                    bitcoin::FeeRate::from_sat_per_vb(feerate.into())
                        .map(|fee| fee.to_sat_per_kwu())
                })
                .ok_or(anyhow!("Could not calculate feerate"))?;

            tx_builder
                .fee_rate(FeeRate::from_sat_per_kwu(feerate))
                .add_recipient(address.script_pubkey(), Amount::from_sat(sats_amount));
            tx_builder.finish()?
        };

        let is_finalized = self
            .bitcoin_wallet
            .sign(&mut psbt, SignOptions::default())?;

        if !is_finalized {
            return Err(anyhow!("failed to sign and finalize a transaction"));
        }

        let txid = psbt.unsigned_tx.compute_txid();

        self.bitcoin_client
            .send_raw_transaction(&psbt.extract_tx()?)?;

        Ok(txid)
    }

    fn check_atomic_swap_tx_appeared_on_bitcoin(
        &self,
        swap_pubkey: PublicKey,
        revocation_pubkey_raw: PublicKey,
    ) -> Result<bool> {
        let escrow_pubkey = bitcoin::PublicKey::new(
            swap_pubkey
                .combine(&self.bitcoin_public_key())
                .expect("It's impossible to fail for 2 different public keys"),
        );
        let revocation_pubkey = bitcoin::PublicKey::new(revocation_pubkey_raw);
        let taproot_descriptor = Descriptor::Tr(Tr::from_str(&format!(
            "{},and_v(v:pk({},older({})))",
            escrow_pubkey, revocation_pubkey, self.swap_params.bitcoin_csv_delay
        ))?);

        let (wallet, _) = load_wallet(
            &self.db_key_path,
            self.bitcoin_wallet.network(),
            Some(taproot_descriptor),
            None,
        )?;

        let mut unspent_utxos: Vec<LocalOutput> = vec![];
        for _ in 0..=MAX_NUMBER_OF_ATTEMPTS_TO_SYNC {
            wallet
                .start_full_scan()
                .build()
                .chain_tip()
                .context("failed to sync a BDK wallet")?;

            unspent_utxos = wallet.list_unspent().collect();

            if !unspent_utxos.is_empty() {
                // The wallet has only a taproot descriptor, so it is our transaction.
                return Ok(true);
            }

            thread::sleep(Duration::from_secs(DELAY_BETWEEN_SYNC_ATTEMPT_SEC))
        }

        Ok(false)
    }
}

fn parse_atomic_swap_proof_pubsignals(pubsignals_json: String) -> Result<(PublicKey, [u8; 32])> {
    let pubsignals: Vec<String> = serde_json::from_str(pubsignals_json.as_str())?;

    let pubkey = parse_pubkey_from_str_vec(pubsignals.clone())
        .context("failed to parse pubkey from pubsignals")?;

    let poseidon_hash =
        parse_poseidon_hash_from_str(pubsignals[PUBSIGNALS_SECRET_HASH_INDEX].clone())
            .context("failed to parse poseidon hash from pubsignals")?;

    Ok((pubkey, poseidon_hash))
}

fn parse_poseidon_hash_from_str(hash_str: String) -> Result<[u8; 32]> {
    let hash = BigUint::from_str(hash_str.as_str())
        .context("failed to parse BigUint from string")?
        .to_bytes_be()
        .as_slice()
        .try_into()?;

    Ok(hash)
}

fn parse_pubkey_from_str_vec(pubsignals: Vec<String>) -> Result<PublicKey> {
    let key_x = parse_scalar_from_str_slice(pubsignals[0..=PUBSIGNALS_PUBKEY_X_END].to_vec())?;
    let key_y = parse_scalar_from_str_slice(
        pubsignals[PUBSIGNALS_PUBKEY_X_END + 1..=PUBSIGNALS_PUBKEY_Y_END].to_vec(),
    )?;

    // Public key prefix 0x04
    let mut key_raw = vec![0x4];
    key_raw.append(&mut key_x.to_bytes_be().1.to_vec());
    key_raw.append(&mut key_y.to_bytes_be().1.to_vec());

    Ok(PublicKey::from_str(
        hex::encode(key_raw.as_slice()).as_str(),
    )?)
}

fn parse_scalar_from_str_slice(scalar_raw: Vec<String>) -> Result<BigInt> {
    if scalar_raw.len() != 4 {
        return Err(anyhow!("invalid number of scalar parts to parse"));
    }

    let mut scalar_u64_array = [0u64; 4];
    for i in 0..4 {
        scalar_u64_array[i] = u64::from_str(scalar_raw[i].as_str())?
    }

    Ok(u64array_to_u256(scalar_u64_array))
}

fn u256_to_u64array(mut input: BigInt) -> Option<[u64; 4]> {
    let mut result = [0u64; 4];

    let u64_max = BigInt::from(u64::MAX) + BigInt::one();

    for x in result.iter_mut() {
        let rem = input.clone() % u64_max.clone();
        *x = rem.to_u64().expect("mod of u64 can't be gr than u64");
        input = input.div(u64_max.clone())
    }

    if input != BigInt::zero() {
        return None;
    }

    Some(result)
}

fn u64array_to_u256(input: [u64; 4]) -> BigInt {
    let mut result = BigInt::from(input[3]);

    let u64_max = BigInt::from(u64::MAX) + BigInt::one();

    for i in (0..=2).rev() {
        result = result.mul(u64_max.clone());
        result = result.add(BigInt::from(input[i]));
    }

    result
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use num::BigInt;

    use crate::swap_participant::{u256_to_u64array, u64array_to_u256};

    #[test]
    fn test_u256_to_u64array() {
        do_test_u256_to_u64array(
            BigInt::from_str(
                "112874956271937818984300676023995443620017137826812392247603206681821520986618",
            )
            .unwrap(),
            vec![
                5264901914485981690,
                2440863701439358041,
                12221174418977567583,
                17982017980625340069,
            ],
        );
        do_test_u256_to_u64array(BigInt::from_str("1").unwrap(), vec![1, 0, 0, 0]);
        do_test_u256_to_u64array(BigInt::from_str("0").unwrap(), vec![0, 0, 0, 0]);
        do_test_u256_to_u64array(
            BigInt::from_str("9134136032198266807219851950679215").unwrap(),
            vec![5858208856384070831, 495162506494374, 0, 0],
        );
    }

    fn do_test_u256_to_u64array(expected_u256: BigInt, expected_u64array: Vec<u64>) {
        assert_eq!(expected_u64array.len(), 4);

        let u64array = u256_to_u64array(expected_u256.clone()).unwrap();

        assert_eq!(u64array[0], expected_u64array[0]);
        assert_eq!(u64array[1], expected_u64array[1]);
        assert_eq!(u64array[2], expected_u64array[2]);
        assert_eq!(u64array[3], expected_u64array[3]);

        let u256 = u64array_to_u256(u64array);

        assert_eq!(u256, expected_u256);
    }
}
