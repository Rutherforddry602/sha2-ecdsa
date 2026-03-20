use clap::Parser;
use sha2_ecdsa::cluster::protocol::*;
use sha2_ecdsa::cluster::worker::WorkerClient;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "worker", about = "GPU cluster worker for SHA2-ECDSA grinding")]
struct Args {
    /// Coordinator URL
    #[arg(long)]
    coordinator: String,

    /// Attempts per GPU batch within a work chunk
    #[arg(long, default_value = "16777216")]
    batch_size: u64,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let client = WorkerClient::new(&args.coordinator);
    eprintln!("Worker {} connecting to {}", client.worker_id, args.coordinator);

    loop {
        // Fetch work
        let assignment = match client.get_work().await {
            Ok(Some(a)) => a,
            Ok(None) => {
                eprintln!("Solution found, stopping.");
                return;
            }
            Err(e) => {
                eprintln!("Error fetching work: {}. Retrying in 2s...", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                continue;
            }
        };

        eprintln!("Got work: range_start={} range_size={}", assignment.range_start, assignment.range_size);

        // Grind this chunk
        let chunk_start = Instant::now();
        let mut found = None;

        #[cfg(target_os = "macos")]
        {
            use sha2_ecdsa::gpu::metal::MetalMiner;
            let miner = MetalMiner::new(&assignment.prefix);
            let mut offset = 0u64;
            while offset < assignment.range_size {
                let batch = args.batch_size.min(assignment.range_size - offset);
                if let Some(result) = miner.mine_batch(
                    &assignment.prefix,
                    assignment.range_start + offset,
                    batch,
                ) {
                    found = Some(FoundPreimage {
                        preimage_hex: hex::encode(result.preimage),
                        hash_hex: hex::encode(result.hash),
                        counter: result.counter,
                    });
                    break;
                }
                offset += batch;
            }
        }

        #[cfg(all(feature = "cuda", not(target_os = "macos")))]
        {
            use sha2_ecdsa::gpu::cuda::CudaMiner;
            let miner = CudaMiner::new(&assignment.prefix);
            let mut offset = 0u64;
            while offset < assignment.range_size {
                let batch = args.batch_size.min(assignment.range_size - offset);
                if let Some(result) = miner.mine_batch(
                    &assignment.prefix,
                    assignment.range_start + offset,
                    batch,
                ) {
                    found = Some(FoundPreimage {
                        preimage_hex: hex::encode(result.preimage),
                        hash_hex: hex::encode(result.hash),
                        counter: result.counter,
                    });
                    break;
                }
                offset += batch;
            }
        }

        let elapsed = chunk_start.elapsed().as_secs_f64();
        let hashrate = assignment.range_size as f64 / elapsed / 1e9;

        let result = WorkResult {
            worker_id: client.worker_id.clone(),
            found: found.clone(),
            attempts: assignment.range_size,
            hashrate_ghs: hashrate,
        };

        match client.post_result(result).await {
            Ok(done) => {
                if found.is_some() {
                    eprintln!("=== SOLUTION SUBMITTED ===");
                    return;
                }
                if done {
                    eprintln!("Solution found by another worker, stopping.");
                    return;
                }
                eprintln!("  Completed chunk: {:.2} GH/s", hashrate);
            }
            Err(e) => {
                eprintln!("Error posting result: {}", e);
            }
        }
    }
}
