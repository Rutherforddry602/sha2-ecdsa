use bitcoin::address::Address;
use bitcoin::hashes::{hash160, Hash};
use bitcoin::network::Network;
use bitcoin::script::ScriptBuf;
use bitcoin::opcodes::all::*;

/// Build the redeemScript: OP_SHA256 OP_SWAP OP_CHECKSIG
///
/// Stack: [pubkey, preimage] (preimage on top)
/// 1. OP_SHA256: SHA256(preimage) → [pubkey, sig]
/// 2. OP_SWAP: → [sig, pubkey]
/// 3. OP_CHECKSIG: verify sig against pubkey → true/false
///
/// The SHA256(preimage) IS the signature (a polyglot: valid hash AND valid DER sig).
/// The pubkey is recovered via ECDSA key recovery from (r, s, sighash).
pub fn build_redeem_script() -> ScriptBuf {
    bitcoin::script::Builder::new()
        .push_opcode(OP_SHA256)
        .push_opcode(OP_SWAP)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Compute the P2SH address for the given redeemScript
pub fn p2sh_address(redeem_script: &ScriptBuf, network: Network) -> Address {
    let script_hash = hash160::Hash::hash(redeem_script.as_bytes());
    let script_pubkey = ScriptBuf::new_p2sh(&script_hash.into());
    Address::from_script(&script_pubkey, network).expect("valid P2SH address")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redeem_script_structure() {
        let script = build_redeem_script();
        let bytes = script.as_bytes();

        assert_eq!(bytes.len(), 3);
        assert_eq!(bytes[0], 0xa8); // OP_SHA256
        assert_eq!(bytes[1], 0x7c); // OP_SWAP
        assert_eq!(bytes[2], 0xac); // OP_CHECKSIG
    }

    #[test]
    fn test_p2sh_address_regtest() {
        let script = build_redeem_script();
        let addr = p2sh_address(&script, Network::Regtest);
        assert!(addr.to_string().starts_with("2"));
    }

    #[test]
    fn test_p2sh_address_mainnet() {
        let script = build_redeem_script();
        let addr = p2sh_address(&script, Network::Bitcoin);
        assert!(addr.to_string().starts_with("3"));
    }
}
