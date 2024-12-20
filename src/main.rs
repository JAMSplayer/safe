use std::{path::Path, process::ExitCode};
use tokio::runtime::Runtime;

use safe::{registers::XorNameBuilder, Multiaddr, Result, Safe, SecretKey};

async fn run() -> Result<()> {
    let mut peers = Vec::new();

    let addr: Multiaddr =
        "/ip4/127.0.0.1/udp/52658/quic-v1/p2p/12D3KooWLY8HWd1BZMDt6exXA6ssiL9rVCdU5pNKsPH2S3FB5hon"
            .parse()
            .unwrap(); // local testnet
    peers.push(addr);

    Safe::init_logging()?;

    println!("Connecting with peers: {:?} ...", &peers);
    let mut s = Safe::connect(peers, false, None).await?;
    s = s.login_with_eth(Some(String::from(
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )))?;
    println!("Safenet connected.");

    println!("Address: {}", s.address()?.to_string());

    println!("Creating random register ...");
    let reg = s
        .register_create(vec![], XorNameBuilder::random().build(), None)
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
