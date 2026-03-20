#include <metal_stdlib>
using namespace metal;

// SHA-256 constants
constant uint K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

constant uint H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

inline uint rotr(uint x, uint n) { return (x >> n) | (x << (32 - n)); }
inline uint ch(uint x, uint y, uint z) { return (x & y) ^ (~x & z); }
inline uint maj(uint x, uint y, uint z) { return (x & y) ^ (x & z) ^ (y & z); }
inline uint sig0(uint x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
inline uint sig1(uint x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
inline uint ssig0(uint x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
inline uint ssig1(uint x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

// SHA-256 single block compression
void sha256_compress(thread uint* state, thread uint* W) {
    // Extend 16 words to 64
    for (int i = 16; i < 64; i++) {
        W[i] = ssig1(W[i-2]) + W[i-7] + ssig0(W[i-15]) + W[i-16];
    }

    uint a = state[0], b = state[1], c = state[2], d = state[3];
    uint e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; i++) {
        uint t1 = h + sig1(e) + ch(e, f, g) + K[i] + W[i];
        uint t2 = sig0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// Check if 32-byte hash is a valid BIP 66 DER signature + sighash
bool check_der_valid(thread uchar* hash) {
    // Early exit: SEQUENCE tag (fails 255/256)
    if (hash[0] != 0x30) return false;

    // Total length = 29
    if (hash[1] != 0x1D) return false;

    // INTEGER tag for r
    if (hash[2] != 0x02) return false;

    // r length
    uint rl = hash[3];
    if (rl < 1 || rl > 24) return false;

    uint sl = 25 - rl;

    // INTEGER tag for s
    if (hash[4 + rl] != 0x02) return false;

    // s length
    if (hash[5 + rl] != sl) return false;

    // Sighash type (byte 31)
    uchar sh = hash[31];
    if (sh != 0x01 && sh != 0x02 && sh != 0x03 &&
        sh != 0x81 && sh != 0x82 && sh != 0x83) return false;

    // r value: not negative (first byte < 0x80)
    if (hash[4] >= 0x80) return false;

    // r value: no unnecessary leading zero
    if (hash[4] == 0x00) {
        if (rl < 2 || hash[5] < 0x80) return false;
    }

    // r value: not zero (check if all bytes are zero)
    bool r_nonzero = false;
    for (uint i = 0; i < rl; i++) {
        if (hash[4 + i] != 0) { r_nonzero = true; break; }
    }
    if (!r_nonzero) return false;

    // s value: not negative
    uint s_start = 6 + rl;
    if (hash[s_start] >= 0x80) return false;

    // s value: no unnecessary leading zero
    if (hash[s_start] == 0x00) {
        if (sl < 2 || hash[s_start + 1] < 0x80) return false;
    }

    // s value: not zero
    bool s_nonzero = false;
    for (uint i = 0; i < sl; i++) {
        if (hash[s_start + i] != 0) { s_nonzero = true; break; }
    }
    if (!s_nonzero) return false;

    return true;
}

// Main kernel: search for 16-byte preimages whose SHA256 is a valid DER signature
kernel void grind_sha2_ecdsa(
    device const uchar* prefix         [[buffer(0)]],   // 8-byte prefix
    device const ulong* batch_start    [[buffer(1)]],   // starting counter
    device atomic_uint* result_flag    [[buffer(2)]],   // 0 = no result, 1 = found
    device ulong* result_counter       [[buffer(3)]],   // winning counter value
    uint gid                           [[thread_position_in_grid]]
) {
    // Early termination if another thread already found a result
    if (atomic_load_explicit(result_flag, memory_order_relaxed) != 0) return;

    ulong counter = *batch_start + (ulong)gid;

    // Build 16-byte preimage: prefix[8] || counter[8] (big-endian)
    uchar preimage[16];
    for (int i = 0; i < 8; i++) preimage[i] = prefix[i];
    for (int i = 0; i < 8; i++) preimage[8 + i] = (uchar)(counter >> (56 - i * 8));

    // Build SHA-256 message block (single 64-byte block)
    // Message: 16 bytes data + 0x80 + 39 bytes zero + 8 bytes length (128 bits)
    uint W[64];
    W[0] = ((uint)preimage[0] << 24) | ((uint)preimage[1] << 16) |
           ((uint)preimage[2] << 8)  | (uint)preimage[3];
    W[1] = ((uint)preimage[4] << 24) | ((uint)preimage[5] << 16) |
           ((uint)preimage[6] << 8)  | (uint)preimage[7];
    W[2] = ((uint)preimage[8] << 24) | ((uint)preimage[9] << 16) |
           ((uint)preimage[10] << 8) | (uint)preimage[11];
    W[3] = ((uint)preimage[12] << 24) | ((uint)preimage[13] << 16) |
           ((uint)preimage[14] << 8) | (uint)preimage[15];
    W[4] = 0x80000000; // padding bit
    for (int i = 5; i < 15; i++) W[i] = 0;
    W[15] = 128; // message length in bits

    // SHA-256 compression
    uint state[8];
    for (int i = 0; i < 8; i++) state[i] = H0[i];
    sha256_compress(state, W);

    // Convert state to bytes (big-endian)
    uchar hash[32];
    for (int i = 0; i < 8; i++) {
        hash[i*4 + 0] = (uchar)(state[i] >> 24);
        hash[i*4 + 1] = (uchar)(state[i] >> 16);
        hash[i*4 + 2] = (uchar)(state[i] >> 8);
        hash[i*4 + 3] = (uchar)(state[i]);
    }

    // Check DER validity
    if (check_der_valid(hash)) {
        // Atomically claim the result slot
        uint expected = 0;
        if (atomic_compare_exchange_weak_explicit(result_flag, &expected, 1,
                memory_order_relaxed, memory_order_relaxed)) {
            *result_counter = counter;
        }
    }
}
