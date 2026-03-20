#include <cstdint>
#include <cstdio>

// SHA-256 constants
__constant__ uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

__device__ __forceinline__ uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

__device__ void sha256_compress(uint32_t state[8], uint32_t W[64]) {
    // Extend 16 words to 64
    #pragma unroll
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(W[i-15], 7) ^ rotr(W[i-15], 18) ^ (W[i-15] >> 3);
        uint32_t s1 = rotr(W[i-2], 17) ^ rotr(W[i-2], 19) ^ (W[i-2] >> 10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    #pragma unroll
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + W[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

__device__ bool check_der_valid(uint8_t hash[32]) {
    // SEQUENCE tag
    if (hash[0] != 0x30) return false;
    // Total length = 29
    if (hash[1] != 0x1D) return false;
    // INTEGER tag for r
    if (hash[2] != 0x02) return false;

    uint32_t rl = hash[3];
    if (rl < 1 || rl > 24) return false;

    uint32_t sl = 25 - rl;

    // INTEGER tag for s
    if (hash[4 + rl] != 0x02) return false;
    // s length
    if (hash[5 + rl] != sl) return false;

    // Sighash type
    uint8_t sh = hash[31];
    if (sh != 0x01 && sh != 0x02 && sh != 0x03 &&
        sh != 0x81 && sh != 0x82 && sh != 0x83) return false;

    // r: not negative
    if (hash[4] >= 0x80) return false;
    // r: no unnecessary leading zero
    if (hash[4] == 0x00 && (rl < 2 || hash[5] < 0x80)) return false;
    // r: not zero
    bool r_nz = false;
    for (uint32_t i = 0; i < rl; i++) {
        if (hash[4 + i] != 0) { r_nz = true; break; }
    }
    if (!r_nz) return false;

    // s: not negative
    uint32_t ss = 6 + rl;
    if (hash[ss] >= 0x80) return false;
    // s: no unnecessary leading zero
    if (hash[ss] == 0x00 && (sl < 2 || hash[ss + 1] < 0x80)) return false;
    // s: not zero
    bool s_nz = false;
    for (uint32_t i = 0; i < sl; i++) {
        if (hash[ss + i] != 0) { s_nz = true; break; }
    }
    if (!s_nz) return false;

    return true;
}

extern "C"
__global__ void __launch_bounds__(256, 4)
grind_sha2_ecdsa(
    const uint8_t* __restrict__ prefix,     // 8 bytes
    const uint64_t* __restrict__ batch_start,
    uint32_t* __restrict__ result_flag,     // atomic: 0=none, 1=found
    uint64_t* __restrict__ result_counter
) {
    uint64_t gid = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
    uint64_t counter = *batch_start + gid;

    // Early termination
    if (atomicAdd(result_flag, 0) != 0) return;

    // Build 16-byte preimage
    uint8_t pre[16];
    for (int i = 0; i < 8; i++) pre[i] = prefix[i];
    for (int i = 0; i < 8; i++) pre[8 + i] = (uint8_t)(counter >> (56 - i * 8));

    // Build message schedule (single 64-byte block)
    uint32_t W[64];
    W[0] = ((uint32_t)pre[0] << 24) | ((uint32_t)pre[1] << 16) |
           ((uint32_t)pre[2] << 8)  | (uint32_t)pre[3];
    W[1] = ((uint32_t)pre[4] << 24) | ((uint32_t)pre[5] << 16) |
           ((uint32_t)pre[6] << 8)  | (uint32_t)pre[7];
    W[2] = ((uint32_t)pre[8] << 24) | ((uint32_t)pre[9] << 16) |
           ((uint32_t)pre[10] << 8) | (uint32_t)pre[11];
    W[3] = ((uint32_t)pre[12] << 24) | ((uint32_t)pre[13] << 16) |
           ((uint32_t)pre[14] << 8) | (uint32_t)pre[15];
    W[4] = 0x80000000;
    for (int i = 5; i < 15; i++) W[i] = 0;
    W[15] = 128;

    // SHA-256 compression
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    sha256_compress(state, W);

    // Convert to bytes
    uint8_t hash[32];
    for (int i = 0; i < 8; i++) {
        hash[i*4 + 0] = (uint8_t)(state[i] >> 24);
        hash[i*4 + 1] = (uint8_t)(state[i] >> 16);
        hash[i*4 + 2] = (uint8_t)(state[i] >> 8);
        hash[i*4 + 3] = (uint8_t)(state[i]);
    }

    if (check_der_valid(hash)) {
        uint32_t old = atomicCAS(result_flag, 0, 1);
        if (old == 0) {
            *result_counter = counter;
        }
    }
}

// Host-callable wrapper to launch the kernel
extern "C"
void launch_grind_sha2_ecdsa(
    const uint8_t* d_prefix,
    const uint64_t* d_batch_start,
    uint32_t* d_result_flag,
    uint64_t* d_result_counter,
    uint32_t grid_size,
    uint32_t block_size
) {
    grind_sha2_ecdsa<<<grid_size, block_size>>>(
        d_prefix, d_batch_start, d_result_flag, d_result_counter
    );
}
