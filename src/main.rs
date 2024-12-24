extern crate config as exconfig;

use bdk::bitcoin::secp256k1::Secp256k1;
use eyre::{Context, Result};
use std::env;
use std::path::PathBuf;
use swap_participant::SwapParticipant;
mod config;
mod depositor_contract;
mod swap_participant;

#[tokio::main]
async fn main() -> Result<()> {
    if env::args().len() != 2 {
        eprintln!(
            "Usage: {} <path-to-config-file>",
            env::args().next().unwrap()
        );
        std::process::exit(1);
    }
    let path_to_config = PathBuf::from(env::args().nth(1).unwrap());
    let cfg = exconfig::Config::builder()
        .add_source(exconfig::File::from(path_to_config))
        .build()?
        .try_deserialize()
        .wrap_err("failed to parse config")?;

    let secp_ctx = Secp256k1::new();
    let rng = &mut rand::thread_rng();

    let mut alice =
        SwapParticipant::from_config("Alice".to_string(), &cfg, &cfg.alice_config, &secp_ctx)
            .await
            .wrap_err("failed to initialize Alice")?;
    let alice_bitcoin_public_key = alice.bitcoin_public_key();
    let alice_ethereum_address = alice.ethereum_address();

    let mut bob = SwapParticipant::from_config("Bob".to_string(), &cfg, &cfg.bob_config, &secp_ctx)
        .await
        .wrap_err("failed to initialize Bob")?;

    //Getting escrow pubkey for hashing and integration purposes
    let (proof, pubsignals, _escrow_pubkey) = alice.new_atomic_swap(
        cfg.swap_params.sats_to_swap,
        bob.bitcoin_public_key(),
        rng,
        &secp_ctx,
    )?;

    tokio::spawn(async {
        alice
            .listen_to_deposit_events()
            .await
            .map_err(|err| panic!("{err}"))
    });

    bob.accept_atomic_swap(
        proof,
        pubsignals,
        alice_bitcoin_public_key,
        alice_ethereum_address,
    )
    .await?;

    bob.listen_to_withdraw_events().await?;

    Ok(())
}
