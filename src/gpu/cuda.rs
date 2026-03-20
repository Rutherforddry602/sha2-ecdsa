use crate::der_check::is_valid_der_signature;
use crate::gpu::MineResult;
use std::ffi::c_void;
use std::ptr;

const THREADS_PER_BLOCK: u32 = 256;

extern "C" {
    fn cudaMalloc(devPtr: *mut *mut c_void, size: usize) -> i32;
    fn cudaFree(devPtr: *mut c_void) -> i32;
    fn cudaMemcpy(dst: *mut c_void, src: *const c_void, count: usize, kind: i32) -> i32;
    fn cudaDeviceSynchronize() -> i32;
    fn cudaGetLastError() -> i32;

    fn launch_grind_sha2_ecdsa(
        d_prefix: *const u8,
        d_batch_start: *const u64,
        d_result_flag: *mut u32,
        d_result_counter: *mut u64,
        grid_size: u32,
        block_size: u32,
    );
}

// cudaMemcpyKind
const MEMCPY_HOST_TO_DEVICE: i32 = 1;
const MEMCPY_DEVICE_TO_HOST: i32 = 2;

pub struct CudaMiner {
    d_prefix: *mut c_void,
    d_batch_start: *mut c_void,
    d_result_flag: *mut c_void,
    d_result_counter: *mut c_void,
}

impl CudaMiner {
    pub fn new(prefix: &[u8; 8]) -> Self {
        let mut d_prefix: *mut c_void = ptr::null_mut();
        let mut d_batch_start: *mut c_void = ptr::null_mut();
        let mut d_result_flag: *mut c_void = ptr::null_mut();
        let mut d_result_counter: *mut c_void = ptr::null_mut();

        unsafe {
            assert_eq!(cudaMalloc(&mut d_prefix, 8), 0, "cudaMalloc prefix failed");
            assert_eq!(cudaMalloc(&mut d_batch_start, 8), 0, "cudaMalloc batch_start failed");
            assert_eq!(cudaMalloc(&mut d_result_flag, 4), 0, "cudaMalloc result_flag failed");
            assert_eq!(cudaMalloc(&mut d_result_counter, 8), 0, "cudaMalloc result_counter failed");

            assert_eq!(
                cudaMemcpy(d_prefix, prefix.as_ptr() as *const c_void, 8, MEMCPY_HOST_TO_DEVICE),
                0, "cudaMemcpy prefix failed"
            );
        }

        CudaMiner {
            d_prefix,
            d_batch_start,
            d_result_flag,
            d_result_counter,
        }
    }

    pub fn mine_batch(
        &self,
        prefix: &[u8; 8],
        batch_start: u64,
        batch_size: u64,
    ) -> Option<MineResult> {
        let zero_flag: u32 = 0;

        unsafe {
            cudaMemcpy(
                self.d_batch_start,
                &batch_start as *const u64 as *const c_void,
                8,
                MEMCPY_HOST_TO_DEVICE,
            );
            cudaMemcpy(
                self.d_result_flag,
                &zero_flag as *const u32 as *const c_void,
                4,
                MEMCPY_HOST_TO_DEVICE,
            );

            let grid_size = ((batch_size + THREADS_PER_BLOCK as u64 - 1) / THREADS_PER_BLOCK as u64) as u32;

            launch_grind_sha2_ecdsa(
                self.d_prefix as *const u8,
                self.d_batch_start as *const u64,
                self.d_result_flag as *mut u32,
                self.d_result_counter as *mut u64,
                grid_size,
                THREADS_PER_BLOCK,
            );

            cudaDeviceSynchronize();
            let err = cudaGetLastError();
            assert_eq!(err, 0, "CUDA error after sync: {}", err);

            let mut h_flag: u32 = 0;
            cudaMemcpy(
                &mut h_flag as *mut u32 as *mut c_void,
                self.d_result_flag,
                4,
                MEMCPY_DEVICE_TO_HOST,
            );

            if h_flag != 0 {
                let mut counter: u64 = 0;
                cudaMemcpy(
                    &mut counter as *mut u64 as *mut c_void,
                    self.d_result_counter,
                    8,
                    MEMCPY_DEVICE_TO_HOST,
                );

                let mut preimage = [0u8; 16];
                preimage[..8].copy_from_slice(prefix);
                preimage[8..].copy_from_slice(&counter.to_be_bytes());

                let hash = cpu_sha256(&preimage);
                if is_valid_der_signature(&hash) {
                    return Some(MineResult {
                        counter,
                        preimage,
                        hash,
                    });
                } else {
                    eprintln!("GPU reported match at counter {} but CPU verification failed!", counter);
                }
            }
        }

        None
    }
}

impl Drop for CudaMiner {
    fn drop(&mut self) {
        unsafe {
            cudaFree(self.d_prefix);
            cudaFree(self.d_batch_start);
            cudaFree(self.d_result_flag);
            cudaFree(self.d_result_counter);
        }
    }
}

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
    for i in 0..8 {
        out[i*4..i*4+4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}
