use std::{path::Path, process::ExitCode};
use tokio::runtime::Runtime;

use safe::{registers::XorNameBuilder, Multiaddr, Result, Safe, SecretKey};

async fn run() -> Result<()> {
    let mut peers = Vec::new();

//    let addr: Multiaddr = "/ip4/127.0.0.1/udp/44203/quic-v1/p2p/12D3KooWFK7wZyDWKqK8GJq7P9rKmZcKAywgQKTDCeNjBdnPbaMC".parse().unwrap(); // my VPS peer on Beta network
    let addr: Multiaddr =
        "/ip4/127.0.0.1/udp/52658/quic-v1/p2p/12D3KooWLY8HWd1BZMDt6exXA6ssiL9rVCdU5pNKsPH2S3FB5hon"
            .parse()
            .unwrap(); // local testnet
    peers.push(addr);

    Safe::init_logging()?;

//    let sk_rnd_str = SecretKey::random().to_hex();
//    println!("SK: {}", &sk_rnd_str);
//    let mut sk = SecretKey::from_hex(&sk_rnd_str).unwrap(); // random sk

//    let mut sk = SecretKey::from_hex("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap(); // EVM private key bytes. Does not work, produces InvalidBytes error.

//    let mut sk = SecretKey::from_hex("160922b4d2b35fec6b7a36a54c9793bea0fdef00c2630b4361e7a92546f05993").unwrap(); // BLS secret key bytes

    println!("Connecting with peers: {:?} ...", &peers);
//    let mut s = Safe::connect(peers, false, Some(sk)).await?;
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
