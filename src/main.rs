use std::process::ExitCode;
use tokio::runtime::Runtime;

use safe::{Multiaddr, Result, Safe, SecretKey};

async fn run() -> Result<()> {
    let mut peers = Vec::new();

//	let addr: Multiaddr = "/ip4/127.0.0.1/udp/55048/quic-v1/p2p/12D3KooWSRJn7T7BuexATPuMAdEej6wYh73w8ffwivZGZQYWJR22".parse().unwrap();
//	peers.push(addr);

    let s: Safe = Safe::connect(peers, Some(SecretKey::random())).await?;

//    Err(safe::Error::Custom("errrrr".to_string()))
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
