use bitcoin::address::Address;
use bitcoin::network::Network;
use bitcoin::script::ScriptBuf;
use bitcoin::{Amount, OutPoint, Txid, TxOut};
use clap::Parser;
use std::str::FromStr;

use sha2_ecdsa::spend::{build_spending_tx, tx_to_hex};

#[derive(Parser)]
#[command(name = "spend", about = "Build a spending transaction using a polyglot hash preimage")]
struct Args {
    /// 16-byte preimage in hex
    #[arg(long)]
    preimage: String,

    /// UTXO txid to spend
    #[arg(long)]
    txid: String,

    /// UTXO vout index
    #[arg(long)]
    vout: u32,

    /// Destination address (omit if using --op-return)
    #[arg(long)]
    dest: Option<String>,

    /// Amount to send in satoshis (omit if using --op-return)
    #[arg(long, default_value = "0")]
    amount: u64,

    /// OP_RETURN data (UTF-8 string)
    #[arg(long)]
    op_return: Option<String>,

    /// Bitcoin network
    #[arg(long, default_value = "regtest")]
    network: String,
}

fn main() {
    let args = Args::parse();

    let preimage_bytes = hex::decode(&args.preimage).expect("Invalid hex preimage");
    assert_eq!(preimage_bytes.len(), 16, "Preimage must be exactly 16 bytes");
    let mut preimage = [0u8; 16];
    preimage.copy_from_slice(&preimage_bytes);

    let network = match args.network.as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        other => panic!("Unknown network: {}", other),
    };

    let polyglot_hash = sha256_16(&preimage);

    let txid = Txid::from_str(&args.txid).expect("Invalid txid");
    let utxo = OutPoint::new(txid, args.vout);

    // Build outputs
    let outputs = if let Some(ref data) = args.op_return {
        let data_bytes = data.as_bytes();
        assert!(data_bytes.len() <= 80, "OP_RETURN data must be <= 80 bytes");
        let mut script = vec![0x6a]; // OP_RETURN
        // push data
        if data_bytes.len() < 0x4c {
            script.push(data_bytes.len() as u8);
        } else {
            script.push(0x4c); // OP_PUSHDATA1
            script.push(data_bytes.len() as u8);
        }
        script.extend_from_slice(data_bytes);

        eprintln!("OP_RETURN:    \"{}\"", data);
        vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(script),
        }]
    } else {
        let dest_str = args.dest.expect("Must provide --dest or --op-return");
        let dest: Address<_> = dest_str.parse().expect("Invalid destination address");
        let dest = dest.require_network(network).expect("Address network mismatch");
        eprintln!("Dest:         {}", dest_str);
        eprintln!("Amount:       {} sats", args.amount);
        vec![TxOut {
            value: Amount::from_sat(args.amount),
            script_pubkey: dest.script_pubkey(),
        }]
    };

    eprintln!("Preimage:     {}", hex::encode(preimage));
    eprintln!("Polyglot sig: {}", hex::encode(polyglot_hash));
    eprintln!("UTXO:         {}:{}", args.txid, args.vout);

    let tx = build_spending_tx(&preimage, &polyglot_hash, utxo, outputs);

    let raw_hex = tx_to_hex(&tx);
    eprintln!("Tx size:      {} bytes", raw_hex.len() / 2);
    println!("{}", raw_hex);
}

fn sha256_16(data: &[u8]) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash};
    let hash = sha256::Hash::hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_byte_array());
    out
}
