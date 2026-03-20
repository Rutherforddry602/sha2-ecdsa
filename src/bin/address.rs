use bitcoin::network::Network;
use clap::Parser;
use sha2_ecdsa::script::{build_redeem_script, p2sh_address};

#[derive(Parser)]
#[command(name = "address", about = "Generate the P2SH address for SHA256-ECDSA polyglot spending")]
struct Args {
    /// Bitcoin network
    #[arg(long, default_value = "regtest")]
    network: String,
}

fn main() {
    let args = Args::parse();

    let network = match args.network.as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        other => panic!("Unknown network: {}", other),
    };

    let redeem_script = build_redeem_script();
    eprintln!("RedeemScript:  {} (OP_SHA256 OP_SWAP OP_CHECKSIG)", hex::encode(redeem_script.as_bytes()));

    let address = p2sh_address(&redeem_script, network);
    println!("{}", address);
}
