use std::{path::Path, process::ExitCode};
use tokio::runtime::Runtime;

use safeapi::{Safe, XorNameBuilder, Multiaddr, Result, SecretKey, Network};

async fn run() -> Result<()> {

//    let network = Network::Alpha;
//    let network = Network::Mainnet;
    let network = Network::Local(vec![
        "/ip4/127.0.0.1/udp/42376/quic-v1/p2p/12D3KooWEdFwKJgDh7Ga92oZTVEzyzV9HWfWTNaPtK9FoFo8MkMK"
        .to_string()
    ]);


    println!("\n\nConnecting network: {:?} ...", network);
    let mut s = Safe::connect(network, None, "ERROR".into()).await?;
    s.login_with_eth(Some(String::from(
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )))?;
    println!("\n\nSafenet connected.");

    println!("\n\nAddress: {}", s.address()?.to_string());
    println!("\n\nBalance: {:?}", s.balance().await?);

    println!("\n\nCreating random reg ...");
    let reg_xorname = XorNameBuilder::random().build();
    println!("\n\nReg xorname: {:?}", &reg_xorname);
    s.reg_create(&[1,1,1,1,1], &reg_xorname) // TODO: file GitHub issue on not able to save empty data
        .await?;
    println!("\n\nReg created.");
    println!("\n\nBalance: {:?}", s.balance().await?);

    println!("\n\nReading reg {} ...", reg_xorname);
    let data = s.read_reg(&reg_xorname, None).await?;
    println!("\n\nReg data: {:?} ...", data);

    println!("\n\nUpdating reg {} ...", reg_xorname);
    s.reg_write(&[1,2,3,4,5], &reg_xorname).await?;
    println!("\n\nReg updated.");
    println!("\n\nBalance: {:?}", s.balance().await?);

    println!("\n\nReading updated reg {} ...", reg_xorname);
    let data = s.read_reg(&reg_xorname, None).await?;
    println!("\n\nNew reg data: {:?} ...", data);

    println!("\n\nUploading data...");
    let data_xorname = s.upload(&[9, 8, 7, 6, 5, 4, 3, 2, 1]).await?;
    println!("\n\nUploaded.");
    println!("\n\nBalance: {:?}", s.balance().await?);

    println!("\n\nDownloading data {} ...", data_xorname);
    let data = s.download(data_xorname).await?;
    println!("\n\nDownloaded data: {:?} ...", data);

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
