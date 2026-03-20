/// Check if a 32-byte SHA256 hash is a valid BIP 66 strict DER-encoded
/// Bitcoin ECDSA signature (31 bytes DER + 1 byte sighash type).
pub fn is_valid_der_signature(hash: &[u8; 32]) -> bool {
    // Byte 0: SEQUENCE tag
    if hash[0] != 0x30 {
        return false;
    }

    // Byte 1: total length of remaining DER = 29
    if hash[1] != 0x1D {
        return false;
    }

    // Byte 2: INTEGER tag for r
    if hash[2] != 0x02 {
        return false;
    }

    // Byte 3: r length
    let rl = hash[3] as usize;
    if rl < 1 || rl > 24 {
        return false;
    }

    let sl = 25 - rl;

    // Check INTEGER tag for s at correct position
    let s_tag_pos = 4 + rl;
    if hash[s_tag_pos] != 0x02 {
        return false;
    }

    // Check s length
    if hash[s_tag_pos + 1] as usize != sl {
        return false;
    }

    // Byte 31: valid sighash type
    let sighash = hash[31];
    if !matches!(sighash, 0x01..=0x03 | 0x81..=0x83) {
        return false;
    }

    // BIP 66: r value validation
    let r_start = 4;
    if !is_valid_der_integer(&hash[r_start..r_start + rl]) {
        return false;
    }

    // BIP 66: s value validation
    let s_start = s_tag_pos + 2;
    if !is_valid_der_integer(&hash[s_start..s_start + sl]) {
        return false;
    }

    true
}

/// Check BIP 66 DER integer encoding rules:
/// - Not empty
/// - Not negative (MSB of first byte must be 0, or first byte is 0x00 padding)
/// - No unnecessary leading zeros
/// - Not zero
fn is_valid_der_integer(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }

    // Negative check: first byte >= 0x80 means negative
    if bytes[0] >= 0x80 {
        return false;
    }

    // Unnecessary leading zero: 0x00 followed by byte < 0x80
    if bytes[0] == 0x00 {
        if bytes.len() < 2 || bytes[1] < 0x80 {
            return false;
        }
    }

    // Zero check: all bytes zero
    if bytes.iter().all(|&b| b == 0) {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_signature_structure() {
        // Construct a valid 32-byte DER signature manually
        // rl=12, sl=13 -> 30 1D 02 0C [12 r bytes] 02 0D [13 s bytes] 01
        let mut hash = [0u8; 32];
        hash[0] = 0x30; // SEQUENCE
        hash[1] = 0x1D; // length 29
        hash[2] = 0x02; // INTEGER r
        hash[3] = 0x0C; // rl = 12
        hash[4] = 0x01; // r first byte (positive, non-zero)
        // r bytes 5..16 can be anything
        hash[16] = 0x02; // INTEGER s (at position 4 + 12 = 16)
        hash[17] = 0x0D; // sl = 13
        hash[18] = 0x01; // s first byte (positive, non-zero)
        // s bytes 19..31 can be anything
        hash[31] = 0x01; // SIGHASH_ALL
        assert!(is_valid_der_signature(&hash));
    }

    #[test]
    fn test_invalid_sequence_tag() {
        let mut hash = [0u8; 32];
        hash[0] = 0x31; // wrong tag
        assert!(!is_valid_der_signature(&hash));
    }

    #[test]
    fn test_invalid_length() {
        let mut hash = [0u8; 32];
        hash[0] = 0x30;
        hash[1] = 0x1E; // wrong length (should be 0x1D)
        assert!(!is_valid_der_signature(&hash));
    }

    #[test]
    fn test_invalid_sighash() {
        let mut hash = [0u8; 32];
        hash[0] = 0x30;
        hash[1] = 0x1D;
        hash[2] = 0x02;
        hash[3] = 0x0C;
        hash[4] = 0x01;
        hash[16] = 0x02;
        hash[17] = 0x0D;
        hash[18] = 0x01;
        hash[31] = 0x00; // invalid sighash
        assert!(!is_valid_der_signature(&hash));
    }

    #[test]
    fn test_negative_r() {
        let mut hash = [0u8; 32];
        hash[0] = 0x30;
        hash[1] = 0x1D;
        hash[2] = 0x02;
        hash[3] = 0x0C;
        hash[4] = 0x80; // negative r
        hash[16] = 0x02;
        hash[17] = 0x0D;
        hash[18] = 0x01;
        hash[31] = 0x01;
        assert!(!is_valid_der_signature(&hash));
    }

    #[test]
    fn test_unnecessary_leading_zero_r() {
        let mut hash = [0u8; 32];
        hash[0] = 0x30;
        hash[1] = 0x1D;
        hash[2] = 0x02;
        hash[3] = 0x0C; // rl = 12
        hash[4] = 0x00; // leading zero
        hash[5] = 0x01; // but next byte < 0x80 -> unnecessary
        hash[16] = 0x02;
        hash[17] = 0x0D;
        hash[18] = 0x01;
        hash[31] = 0x01;
        assert!(!is_valid_der_signature(&hash));
    }

    #[test]
    fn test_valid_leading_zero_r() {
        let mut hash = [0u8; 32];
        hash[0] = 0x30;
        hash[1] = 0x1D;
        hash[2] = 0x02;
        hash[3] = 0x0C; // rl = 12
        hash[4] = 0x00; // leading zero
        hash[5] = 0x80; // next byte >= 0x80 -> necessary padding
        hash[16] = 0x02;
        hash[17] = 0x0D;
        hash[18] = 0x01;
        hash[31] = 0x01;
        assert!(is_valid_der_signature(&hash));
    }

    #[test]
    fn test_zero_r_value() {
        let mut hash = [0u8; 32];
        hash[0] = 0x30;
        hash[1] = 0x1D;
        hash[2] = 0x02;
        hash[3] = 0x0C;
        // all r bytes are 0 -> invalid
        hash[16] = 0x02;
        hash[17] = 0x0D;
        hash[18] = 0x01;
        hash[31] = 0x01;
        assert!(!is_valid_der_signature(&hash));
    }

    #[test]
    fn test_rl_boundaries() {
        // rl=1, sl=24
        let mut hash = [0u8; 32];
        hash[0] = 0x30;
        hash[1] = 0x1D;
        hash[2] = 0x02;
        hash[3] = 0x01; // rl = 1
        hash[4] = 0x01; // r value (single byte, positive, non-zero)
        hash[5] = 0x02; // INTEGER s at position 4+1=5
        hash[6] = 0x18; // sl = 24
        hash[7] = 0x01; // s first byte
        hash[31] = 0x01;
        assert!(is_valid_der_signature(&hash));

        // rl=24, sl=1
        let mut hash = [0u8; 32];
        hash[0] = 0x30;
        hash[1] = 0x1D;
        hash[2] = 0x02;
        hash[3] = 0x18; // rl = 24
        hash[4] = 0x01; // r first byte
        hash[28] = 0x02; // INTEGER s at position 4+24=28
        hash[29] = 0x01; // sl = 1
        hash[30] = 0x01; // s value (single byte, non-zero)
        hash[31] = 0x01;
        assert!(is_valid_der_signature(&hash));
    }

    #[test]
    fn test_all_valid_sighash_types() {
        let mut hash = [0u8; 32];
        hash[0] = 0x30;
        hash[1] = 0x1D;
        hash[2] = 0x02;
        hash[3] = 0x0C;
        hash[4] = 0x01;
        hash[16] = 0x02;
        hash[17] = 0x0D;
        hash[18] = 0x01;

        for sighash in [0x01, 0x02, 0x03, 0x81, 0x82, 0x83] {
            hash[31] = sighash;
            assert!(is_valid_der_signature(&hash), "sighash 0x{:02x} should be valid", sighash);
        }

        for sighash in [0x00, 0x04, 0x80, 0x84, 0xFF] {
            hash[31] = sighash;
            assert!(!is_valid_der_signature(&hash), "sighash 0x{:02x} should be invalid", sighash);
        }
    }
}
