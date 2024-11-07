use std::{path::Path, process::ExitCode};
use tokio::runtime::Runtime;

use safe::{registers::XorNameBuilder, Multiaddr, Result, Safe, SecretKey};

async fn run() -> Result<()> {
    let mut peers = Vec::new();

    // let addr: Multiaddr = "/ip4/127.0.0.1/udp/55048/quic-v1/p2p/12D3KooWSRJn7T7BuexATPuMAdEej6wYh73w8ffwivZGZQYWJR22".parse().unwrap(); // local testnet
    let addr: Multiaddr = "/ip4/37.233.101.38/udp/36592/quic-v1/p2p/12D3KooWRbcM42CaWcndyr9h5NQNGo75H3acWring99CRyPzQZGc".parse().unwrap(); // my VPS peer on Beta network
    peers.push(addr);

    // Safe::init_logging()?;

    println!("Connecting with peers: {:?} ...", &peers);
    let mut s = Safe::connect(peers, None, Path::new("./_wallet").to_path_buf()).await?;
    println!("Safenet connected.");

    println!("Creating random register ...");
    let reg = s
        .register_create(&[], XorNameBuilder::random().build(), None)
        .await?;
    println!("Register: {:?}", reg);

    Ok(())
}

fn main() -> ExitCode {
    Runtime::new().unwrap().block_on(async {
        if let Err(e) = run().await {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        }
    })
}
