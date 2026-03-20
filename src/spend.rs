use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::absolute::LockTime;
use bitcoin::script::ScriptBuf;
use bitcoin::{OutPoint, Sequence, Witness};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, PublicKey, Secp256k1};

use crate::script::build_redeem_script;

/// Parse a 32-byte polyglot hash into DER signature components.
/// Returns (r_bytes, s_bytes, sighash_type).
pub fn parse_der_signature(hash: &[u8; 32]) -> (Vec<u8>, Vec<u8>, u8) {
    assert_eq!(hash[0], 0x30, "not a SEQUENCE");
    assert_eq!(hash[1], 0x1D, "wrong length");
    assert_eq!(hash[2], 0x02, "not INTEGER for r");

    let rl = hash[3] as usize;
    let r = hash[4..4 + rl].to_vec();

    assert_eq!(hash[4 + rl], 0x02, "not INTEGER for s");
    let sl = hash[5 + rl] as usize;
    let s = hash[6 + rl..6 + rl + sl].to_vec();

    let sighash = hash[31];
    (r, s, sighash)
}

/// Compute the legacy sighash for a P2SH spend.
///
/// For SIGHASH_NONE (0x02): outputs are empty, other inputs' sequences are 0.
pub fn compute_sighash(
    tx: &Transaction,
    input_index: usize,
    script_code: &ScriptBuf,
    sighash_type: u32,
) -> [u8; 32] {
    // Build the sighash preimage manually for legacy transactions
    let mut preimage = Vec::new();

    // nVersion
    preimage.extend_from_slice(&tx.version.0.to_le_bytes());

    // Number of inputs
    let input_count = tx.input.len();
    push_compact_size(&mut preimage, input_count as u64);

    let anyone_can_pay = (sighash_type & 0x80) != 0;
    let base_type = sighash_type & 0x1f;

    if anyone_can_pay {
        // Only serialize the input being signed
        serialize_input(&mut preimage, &tx.input[input_index], script_code, true);
    } else {
        for (i, input) in tx.input.iter().enumerate() {
            if i == input_index {
                serialize_input(&mut preimage, input, script_code, true);
            } else {
                let seq = if base_type == 2 || base_type == 3 {
                    // SIGHASH_NONE or SIGHASH_SINGLE: other inputs get sequence 0
                    Sequence::ZERO
                } else {
                    input.sequence
                };
                let mut modified = input.clone();
                modified.sequence = seq;
                serialize_input(&mut preimage, &modified, &ScriptBuf::new(), false);
            }
        }
    }

    // Outputs
    match base_type {
        2 => {
            // SIGHASH_NONE: no outputs
            push_compact_size(&mut preimage, 0);
        }
        3 => {
            // SIGHASH_SINGLE: outputs up to and including input_index
            if input_index >= tx.output.len() {
                // SIGHASH_SINGLE bug: hash is 0x0100...00
                let mut result = [0u8; 32];
                result[0] = 1;
                return result;
            }
            push_compact_size(&mut preimage, (input_index + 1) as u64);
            for (i, output) in tx.output.iter().enumerate() {
                if i < input_index {
                    // Empty output: -1 value, empty script
                    preimage.extend_from_slice(&(-1i64 as u64).to_le_bytes());
                    push_compact_size(&mut preimage, 0);
                } else if i == input_index {
                    preimage.extend_from_slice(&output.value.to_sat().to_le_bytes());
                    push_compact_size(&mut preimage, output.script_pubkey.len() as u64);
                    preimage.extend_from_slice(output.script_pubkey.as_bytes());
                }
            }
        }
        _ => {
            // SIGHASH_ALL: all outputs
            push_compact_size(&mut preimage, tx.output.len() as u64);
            for output in &tx.output {
                preimage.extend_from_slice(&output.value.to_sat().to_le_bytes());
                push_compact_size(&mut preimage, output.script_pubkey.len() as u64);
                preimage.extend_from_slice(output.script_pubkey.as_bytes());
            }
        }
    }

    // nLockTime
    preimage.extend_from_slice(&tx.lock_time.to_consensus_u32().to_le_bytes());

    // Sighash type
    preimage.extend_from_slice(&sighash_type.to_le_bytes());

    // Double SHA256
    let hash = sha256d::Hash::hash(&preimage);
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_byte_array());
    result
}

fn serialize_input(buf: &mut Vec<u8>, input: &TxIn, script: &ScriptBuf, include_script: bool) {
    // txid (32 bytes, internal byte order)
    buf.extend_from_slice(input.previous_output.txid.as_ref());
    // vout
    buf.extend_from_slice(&input.previous_output.vout.to_le_bytes());
    // scriptSig
    if include_script {
        push_compact_size(buf, script.len() as u64);
        buf.extend_from_slice(script.as_bytes());
    } else {
        push_compact_size(buf, 0);
    }
    // sequence
    buf.extend_from_slice(&input.sequence.0.to_le_bytes());
}

fn push_compact_size(buf: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffffffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

/// Recover the public key from a signature (r, s) and sighash message.
/// Tries both recovery IDs (0 and 1) and returns the first that works.
pub fn recover_pubkey(r: &[u8], s: &[u8], sighash: &[u8; 32]) -> PublicKey {
    let secp = Secp256k1::new();

    // Build compact signature (64 bytes: r padded to 32 + s padded to 32)
    let mut compact = [0u8; 64];
    // r: right-aligned in first 32 bytes
    let r_offset = 32 - r.len();
    compact[r_offset..32].copy_from_slice(r);
    // s: right-aligned in last 32 bytes
    let s_offset = 64 - s.len();
    compact[s_offset..64].copy_from_slice(s);

    let msg = Message::from_digest(*sighash);

    for rec_id in 0..4 {
        let rid = RecoveryId::from_i32(rec_id).unwrap();
        if let Ok(sig) = RecoverableSignature::from_compact(&compact, rid) {
            if let Ok(pubkey) = secp.recover_ecdsa(&msg, &sig) {
                // Verify it actually works
                let regular_sig = sig.to_standard();
                if secp.verify_ecdsa(&msg, &regular_sig, &pubkey).is_ok() {
                    return pubkey;
                }
            }
        }
    }
    panic!("Failed to recover public key from signature");
}

/// Build a complete spending transaction.
///
/// Returns the signed transaction ready for broadcast.
pub fn build_spending_tx(
    preimage: &[u8; 16],
    polyglot_hash: &[u8; 32],
    utxo: OutPoint,
    outputs: Vec<TxOut>,
) -> Transaction {
    let (r, s, sighash_type) = parse_der_signature(polyglot_hash);

    let redeem_script = build_redeem_script();

    // Build unsigned transaction
    let mut tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: utxo,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: outputs,
    };

    // Compute sighash
    let sighash = compute_sighash(&tx, 0, &redeem_script, sighash_type as u32);

    // Recover public key
    let pubkey = recover_pubkey(&r, &s, &sighash);
    let pubkey_bytes = pubkey.serialize(); // 33 bytes compressed

    // Build scriptSig: <pubkey> <preimage> <redeemScript>
    // Stack after P2SH peels redeemScript: [pubkey, preimage] (preimage on top)
    // RedeemScript: OP_SHA256 → SHA256(preimage)=sig, OP_SWAP, OP_CHECKSIG
    let mut script_sig = bitcoin::script::Builder::new();
    script_sig = script_sig
        .push_slice(&pubkey_bytes)               // recovered public key
        .push_slice(preimage)                    // preimage (SHA256 of this = the signature)
        .push_slice::<&bitcoin::script::PushBytes>(redeem_script.as_bytes().try_into().unwrap()); // serialized redeemScript
    tx.input[0].script_sig = script_sig.into_script();

    tx
}

/// Serialize a transaction to hex for broadcast.
pub fn tx_to_hex(tx: &Transaction) -> String {
    hex::encode(serialize(tx))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREIMAGE_HEX: &str = "00000000000000000200a8013bbb8678";
    const HASH_HEX: &str = "301d020a7993dad81d0e10285a7e020f682a7033db72199360c2dc3599f2d302";

    fn get_test_hash() -> [u8; 32] {
        let bytes = hex::decode(HASH_HEX).unwrap();
        let mut h = [0u8; 32];
        h.copy_from_slice(&bytes);
        h
    }

    #[test]
    fn test_parse_der_signature() {
        let hash = get_test_hash();
        let (r, s, sighash) = parse_der_signature(&hash);

        assert_eq!(hex::encode(&r), "7993dad81d0e10285a7e");
        assert_eq!(hex::encode(&s), "682a7033db72199360c2dc3599f2d3");
        assert_eq!(sighash, 0x02); // SIGHASH_NONE
        assert_eq!(r.len(), 10);
        assert_eq!(s.len(), 15);
    }

    #[test]
    fn test_recover_pubkey_from_known_message() {
        let hash = get_test_hash();
        let (r, s, _) = parse_der_signature(&hash);

        // Use an arbitrary message for recovery test
        let msg_bytes = [0x01u8; 32];
        let pubkey = recover_pubkey(&r, &s, &msg_bytes);

        // Verify the recovered key actually verifies the signature
        let secp = Secp256k1::new();
        let msg = Message::from_digest(msg_bytes);

        let mut compact = [0u8; 64];
        compact[32 - r.len()..32].copy_from_slice(&r);
        compact[64 - s.len()..64].copy_from_slice(&s);

        // Find which recovery ID works
        for rec_id in 0..4 {
            let rid = RecoveryId::from_i32(rec_id).unwrap();
            if let Ok(rec_sig) = RecoverableSignature::from_compact(&compact, rid) {
                let sig = rec_sig.to_standard();
                if secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok() {
                    return; // success
                }
            }
        }
        panic!("Could not verify recovered pubkey");
    }
}
