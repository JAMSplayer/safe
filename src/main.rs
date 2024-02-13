use safe::{Safe, SecretKey};

fn main() {
    let s: Safe = Safe::default();

    let peers = Vec::new();

    // let result = s.connect(peers, Some(SecretKey::random()));
    let result = s.connect(peers, None);
    println!("{:?}", result);
}
