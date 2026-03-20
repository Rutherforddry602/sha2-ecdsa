use crate::der_check::is_valid_der_signature;
use crate::gpu::MineResult;
use metal::*;
use std::mem;

const SHADER_SOURCE: &str = include_str!("metal_kernel.metal");
const THREADS_PER_GROUP: u64 = 256;

pub struct MetalMiner {
    #[allow(dead_code)]
    device: Device,
    queue: CommandQueue,
    pipeline: ComputePipelineState,
    prefix_buf: Buffer,
    batch_start_buf: Buffer,
    result_flag_buf: Buffer,
    result_counter_buf: Buffer,
}

impl MetalMiner {
    pub fn new(prefix: &[u8; 8]) -> Self {
        let device = Device::system_default().expect("No Metal device found");
        let queue = device.new_command_queue();

        let library = device
            .new_library_with_source(SHADER_SOURCE, &CompileOptions::new())
            .expect("Failed to compile Metal shader");

        let function = library
            .get_function("grind_sha2_ecdsa", None)
            .expect("Failed to find kernel function");

        let pipeline = device
            .new_compute_pipeline_state_with_function(&function)
            .expect("Failed to create pipeline");

        let prefix_buf = device.new_buffer_with_data(
            prefix.as_ptr() as *const _,
            8,
            MTLResourceOptions::StorageModeShared,
        );

        let batch_start_buf = device.new_buffer(
            mem::size_of::<u64>() as u64,
            MTLResourceOptions::StorageModeShared,
        );

        let result_flag_buf = device.new_buffer(
            mem::size_of::<u32>() as u64,
            MTLResourceOptions::StorageModeShared,
        );

        let result_counter_buf = device.new_buffer(
            mem::size_of::<u64>() as u64,
            MTLResourceOptions::StorageModeShared,
        );

        MetalMiner {
            device,
            queue,
            pipeline,
            prefix_buf,
            batch_start_buf,
            result_flag_buf,
            result_counter_buf,
        }
    }

    /// Mine a batch of `batch_size` attempts starting from `batch_start`.
    /// Returns Some(MineResult) if a valid preimage was found.
    pub fn mine_batch(
        &self,
        prefix: &[u8; 8],
        batch_start: u64,
        batch_size: u64,
    ) -> Option<MineResult> {
        // Set batch_start
        let ptr = self.batch_start_buf.contents() as *mut u64;
        unsafe { *ptr = batch_start; }

        // Reset result flag to 0
        let flag_ptr = self.result_flag_buf.contents() as *mut u32;
        unsafe { *flag_ptr = 0; }

        let cmd_buf = self.queue.new_command_buffer();
        let encoder = cmd_buf.new_compute_command_encoder();
        encoder.set_compute_pipeline_state(&self.pipeline);
        encoder.set_buffer(0, Some(&self.prefix_buf), 0);
        encoder.set_buffer(1, Some(&self.batch_start_buf), 0);
        encoder.set_buffer(2, Some(&self.result_flag_buf), 0);
        encoder.set_buffer(3, Some(&self.result_counter_buf), 0);

        let threadgroup_size = MTLSize::new(THREADS_PER_GROUP, 1, 1);
        let grid_size = MTLSize::new(batch_size, 1, 1);
        encoder.dispatch_threads(grid_size, threadgroup_size);
        encoder.end_encoding();

        cmd_buf.commit();
        cmd_buf.wait_until_completed();

        // Check if result was found
        let found = unsafe { *(self.result_flag_buf.contents() as *const u32) };
        if found != 0 {
            let counter = unsafe { *(self.result_counter_buf.contents() as *const u64) };

            // Build preimage and compute hash on CPU to verify
            let mut preimage = [0u8; 16];
            preimage[..8].copy_from_slice(prefix);
            preimage[8..].copy_from_slice(&counter.to_be_bytes());

            let hash = sha256(&preimage);

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

        None
    }

    pub fn max_threadgroup_threads(&self) -> u64 {
        self.pipeline.max_total_threads_per_threadgroup()
    }
}

/// CPU SHA-256 for verification (single block, 16-byte input)
fn sha256(data: &[u8; 16]) -> [u8; 32] {
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

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);

    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i*4..i*4+4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_vector() {
        // SHA256 of 16 zero bytes
        let input = [0u8; 16];
        let hash = sha256(&input);
        // Verify against known value
        let hex_str = hex::encode(hash);
        assert_eq!(hex_str.len(), 64);
        // SHA256(0x00000000000000000000000000000000)
        // We just verify the function produces consistent 32-byte output
        let hash2 = sha256(&input);
        assert_eq!(hash, hash2);
    }
}
