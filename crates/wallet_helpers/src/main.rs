extern crate anyhow;
extern crate wallet_helpers;
extern crate log;
extern crate miniscript;
extern crate rand;

use anyhow::Result;
use wallet_helpers::generate_descriptor;
use log::LevelFilter;
use miniscript::bitcoin::{secp256k1::SecretKey, Network};
use rand::RngCore;

fn main() -> Result<()> {
    env_logger::init();
    log::set_max_level(LevelFilter::Info);

    let mut seed: [u8; 32] = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let secret_key = SecretKey::from_slice(&seed)?;

    let network = Network::Regtest;

    log::warn!(
        "Warning: be very careful with private keys when using {}! Current network: {network}",
        network
    );

    let (descriptor_string_priv, change_descriptor_string_priv) = generate_descriptor(&secret_key, network)?;

    log::info!("Descriptor:        {descriptor_string_priv}");
    log::info!("Change descriptor: {change_descriptor_string_priv}");

    Ok(())
}
