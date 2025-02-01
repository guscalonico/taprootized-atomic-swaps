use anyhow::{Context, Result};
use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::PersistedWallet;
use core::option::Option::None;
use ethers::prelude::Ws;
use ethers::providers::Provider as EthereumClient;
use ethers::types::Address as EthereumAddress;
use miniscript::bitcoin::{
    secp256k1::{SecretKey as SecpSecretKey},
    Network,
};
use std::path::PathBuf;
use wallet_helpers::{generate_descriptor, load_wallet};

#[derive(serde::Deserialize)]
pub struct Config {
    pub atomic_swap_contract_address: EthereumAddress,
    pub ethereum_ws_rpc_url: String,
    pub bitcoin_rpc: BitcoinRpcConfig,
    pub circom: CircomConfig,

    pub swap_params: SwapParams,

    #[serde(rename = "alice")]
    pub alice_config: WalletsConfig,
    #[serde(rename = "bob")]
    pub bob_config: WalletsConfig,
}

impl Config {
    /// Return the [`bdk_wallet::PersistedWallet<Connection>`] that can be used to operate with UTXOs and the
    /// [`BitcoinClient`] for retrieving the available UTXOs from the Bitcoin network.
    pub fn bitcoin_wallet(
        &self,
        secret_key: SecpSecretKey,
        db_path: &str,
    ) -> Result<(PersistedWallet<Connection>, Client)> {
        let network = self.bitcoin_rpc.network;

        let (descriptor, change_descriptor) = generate_descriptor(&secret_key, network)?;
        log::debug!("descriptors: {descriptor} {change_descriptor}");

        let (wallet, _is_new) =
            load_wallet(db_path, network, Some(descriptor), Some(change_descriptor))
                .context("Failed to initialize bdk_wallet")?;

        let bitcoin_client = self
            .bitcoin_client()
            .context("failed to initialize Bitcoin RPC client")?;

        Ok((wallet, bitcoin_client))
    }

    /// Returns the [`ethers::providers::Provider`] that can be used to send transactions to
    /// the Ethereum network.
    pub async fn ethereum_client(&self) -> Result<EthereumClient<Ws>> {
        let provider = EthereumClient::<Ws>::connect(self.ethereum_ws_rpc_url.clone()).await?;

        Ok(provider)
    }

    /// Returns the [`bdk::blockchain::RpcBlockchain`] for the wallet. It will be used there to
    /// retrieve the UTXOs from Bitcoin.
    fn bitcoin_client(&self) -> Result<Client> {
        let url = &self.bitcoin_rpc.url.clone();
        let btc_rpc_config = &self.bitcoin_rpc;
        let auth = match (
            &btc_rpc_config.rpc_cookie,
            &btc_rpc_config.rpc_user,
            &btc_rpc_config.rpc_pass,
        ) {
            (None, None, None) => Auth::None,
            (Some(path), _, _) => Auth::CookieFile(path.clone()),
            (_, Some(user), Some(pass)) => Auth::UserPass(user.clone(), pass.clone()),
            (_, Some(_), None) => panic!("rpc auth: missing rpc_pass"),
            (_, None, Some(_)) => panic!("rpc auth: missing rpc_user"),
        };
        let rpc_client = Client::new(url, auth)?;
        log::info!(
            "Connected to Bitcoin Core RPC at {:?}",
            rpc_client.get_blockchain_info().unwrap()
        );
        Ok(rpc_client)
    }
}

#[derive(Clone, serde::Deserialize)]
pub struct SwapParams {
    pub sats_to_swap: u64,
    pub gwei_to_swap: u64,
    pub bitcoin_csv_delay: u32,
    pub ethereum_timelock_secs: u64,
}

#[derive(serde::Deserialize)]
pub struct WalletsConfig {
    pub bitcoin_private_key: SecpSecretKey,
    pub ethereum_private_key: SecpSecretKey,
    pub db_path: String,
}

#[derive(serde::Deserialize)]
pub struct BitcoinRpcConfig {
    pub url: String,
    pub rpc_cookie: Option<PathBuf>,
    pub rpc_user: Option<String>,
    pub rpc_pass: Option<String>,
    pub network: Network,
}

#[derive(Clone, serde::Deserialize)]
pub struct CircomConfig {
    pub witnes_calculator_path: PathBuf,
    pub proving_key_path: PathBuf,
    pub verification_key_path: PathBuf,
}
