extern crate bdk_wallet;
extern crate miniscript;
extern crate anyhow;

use anyhow::{Context, Result};
use bdk_wallet::{
    KeychainKind, PersistedWallet, Wallet,
    rusqlite::Connection,
    template::{Bip86, DescriptorTemplate},
};
use miniscript::{
    Descriptor, DescriptorPublicKey,
    bitcoin::{Network, bip32::Xpriv, secp256k1::SecretKey},
};
use anyhow::anyhow;

pub fn generate_descriptor(
    secret_key: &SecretKey,
    network: Network,
) -> Result<(
    Descriptor<DescriptorPublicKey>,
    Descriptor<DescriptorPublicKey>,
)> {
    let xprv = Xpriv::new_master(network, &secret_key.secret_bytes()).unwrap();

    let (descriptor, _, _) = Bip86(xprv, KeychainKind::External)
        .build(Network::Signet)
        .context("Failed to build external descriptor")?;

    let (change_descriptor, _, _) = Bip86(xprv, KeychainKind::Internal)
        .build(Network::Signet)
        .context("Failed to build internal descriptor")?;

    Ok((descriptor, change_descriptor))
}

pub fn load_wallet(
    db_path: &str,
    network: Network,
    external_descriptor: Option<Descriptor<DescriptorPublicKey>>,
    internal_descriptor: Option<Descriptor<DescriptorPublicKey>>,
) -> Result<(PersistedWallet<Connection>, bool)> {
    let mut conn = Connection::open(db_path)?;

    let wallet_opt = Wallet::load()
        .descriptor(KeychainKind::External, external_descriptor.clone())
        .descriptor(KeychainKind::Internal, internal_descriptor.clone())
        .extract_keys()
        .check_network(network)
        .load_wallet(&mut conn)?;

    let (wallet, is_new_wallet) = if let Some(loaded_wallet) = wallet_opt {
        (loaded_wallet, false)
    } else {
        let external_descriptor = external_descriptor.ok_or(anyhow!("No external descriptor present"))?;
        let internal_descriptor = internal_descriptor.ok_or(anyhow!("No external descriptor present"))?;
        (
            Wallet::create(external_descriptor, internal_descriptor)
                .network(Network::Signet)
                .create_wallet(&mut conn)?,
            true,
        )
    };

    Ok((wallet, is_new_wallet))
}
