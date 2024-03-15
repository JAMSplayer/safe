use tokio::runtime::Runtime;

use safe::{Multiaddr, Result, Safe, SecretKey};

async fn run() -> Result<()> {
    let mut peers = Vec::new();
    //	let addr: Multiaddr = "/ip4/127.0.0.1/tcp/35441/p2p/12D3KooWMNzC2ngpTL8itJ7LkaP1eHYxBkER6xvoAgLq9khNScHh".parse().unwrap();
    //	peers.push(addr);

    let s: Safe = Safe::connect(peers, Some(SecretKey::random())).await?;

    //	let result = s.connect(peers, Some(SecretKey::random()));
    //	let result = s.connect(peers, None);
    //	println!("{:?}", result);
    Ok(())
}

fn main() {
    Runtime::new().unwrap().block_on(async {
        run().await;
    });
}
