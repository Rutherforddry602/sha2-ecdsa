use sha2_ecdsa::der_check::is_valid_der_signature;

fn cpu_sha256(data: &[u8; 16]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let mut w = [0u32; 64];
    w[0] = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    w[1] = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    w[2] = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    w[3] = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    w[4] = 0x80000000;
    w[15] = 128;

    for i in 16..64 {
        let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
        let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
        w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
    }

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
        (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g; g = f; f = e; e = d.wrapping_add(t1);
        d = c; c = b; b = a; a = t1.wrapping_add(t2);
    }
    h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);

    let mut out = [0u8; 32];
    for i in 0..8 { out[i*4..i*4+4].copy_from_slice(&h[i].to_be_bytes()); }
    out
}

fn main() {
    let prefix = [0u8; 8];

    // Test 1: verify SHA256 against known value
    let input = [0u8; 16];
    let hash = cpu_sha256(&input);
    eprintln!("SHA256(16 zero bytes) = {}", hex::encode(hash));

    // Test 2: count partial matches in first N hashes
    let n: u64 = 100_000_000;
    let mut count_0x30 = 0u64;
    let mut count_30_1d = 0u64;
    let mut count_30_1d_02 = 0u64;
    let mut count_struct = 0u64; // all structural bytes match
    let mut count_full = 0u64;   // full DER valid

    for counter in 0..n {
        let mut preimage = [0u8; 16];
        preimage[..8].copy_from_slice(&prefix);
        preimage[8..].copy_from_slice(&counter.to_be_bytes());
        let hash = cpu_sha256(&preimage);

        if hash[0] == 0x30 {
            count_0x30 += 1;
            if hash[1] == 0x1D {
                count_30_1d += 1;
                if hash[2] == 0x02 {
                    count_30_1d_02 += 1;
                    let rl = hash[3] as usize;
                    if rl >= 1 && rl <= 24 {
                        if hash[4 + rl] == 0x02 && hash[5 + rl] as usize == 25 - rl {
                            count_struct += 1;
                            if is_valid_der_signature(&hash) {
                                count_full += 1;
                                eprintln!("FOUND at counter {}: {}", counter, hex::encode(hash));
                            }
                        }
                    }
                }
            }
        }

        if counter > 0 && counter % 10_000_000 == 0 {
            eprintln!("[{}/{}M] 0x30={} 30_1d={} 30_1d_02={} struct={} full={}",
                counter / 1_000_000, n / 1_000_000,
                count_0x30, count_30_1d, count_30_1d_02, count_struct, count_full);
        }
    }

    eprintln!("\n=== Final stats over {} attempts ===", n);
    eprintln!("hash[0]==0x30:   {} (expected ~{}, ratio {:.3})", count_0x30, n/256, count_0x30 as f64 / (n as f64 / 256.0));
    eprintln!("+ hash[1]==0x1D: {} (expected ~{}, ratio {:.3})", count_30_1d, n/256/256, count_30_1d as f64 / (n as f64 / 65536.0));
    eprintln!("+ hash[2]==0x02: {} (expected ~{}, ratio {:.3})", count_30_1d_02, n/256/256/256, count_30_1d_02 as f64 / (n as f64 / 16777216.0));
    eprintln!("+ structural:    {} (expected ~{:.1})", count_struct, n as f64 * 24.0 / 256.0_f64.powi(6));
    eprintln!("+ full DER:      {}", count_full);
    let expected_full = n as f64 * 24.0 * 6.0 * 0.496 * 0.496 / 256.0_f64.powi(7);
    eprintln!("Expected full:   {:.4}", expected_full);
}
