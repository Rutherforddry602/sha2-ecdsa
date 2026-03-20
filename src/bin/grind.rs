use clap::Parser;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "grind", about = "Find a 16-byte preimage whose SHA256 is a valid DER ECDSA signature")]
struct Args {
    /// 8-byte prefix in hex (default: all zeros)
    #[arg(long, default_value = "0000000000000000")]
    prefix: String,

    /// Starting counter value
    #[arg(long, default_value = "0")]
    start: u64,

    /// Attempts per GPU batch (default: 1<<24 = ~16M)
    #[arg(long, default_value = "16777216")]
    batch_size: u64,
}

fn main() {
    let args = Args::parse();

    let prefix_bytes = hex::decode(&args.prefix).expect("Invalid hex prefix");
    assert_eq!(prefix_bytes.len(), 8, "Prefix must be exactly 8 bytes (16 hex chars)");
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&prefix_bytes);

    eprintln!("SHA2-ECDSA Grinder");
    eprintln!("Prefix: {}", args.prefix);
    eprintln!("Start:  {}", args.start);
    eprintln!("Batch:  {}", args.batch_size);

    #[cfg(target_os = "macos")]
    {
        use sha2_ecdsa::gpu::metal::MetalMiner;

        let miner = MetalMiner::new(&prefix);
        eprintln!("GPU: Metal (max threads/group: {})", miner.max_threadgroup_threads());
        eprintln!("Grinding...\n");

        run_grinding_loop(&miner, &prefix, args.start, args.batch_size);
    }

    #[cfg(all(feature = "cuda", not(target_os = "macos")))]
    {
        use sha2_ecdsa::gpu::cuda::CudaMiner;

        let miner = CudaMiner::new(&prefix);
        eprintln!("GPU: CUDA");
        eprintln!("Grinding...\n");

        run_grinding_loop(&miner, &prefix, args.start, args.batch_size);
    }

    #[cfg(all(not(target_os = "macos"), not(feature = "cuda")))]
    {
        eprintln!("No GPU backend available. Build with --features cuda on Linux, or run on macOS for Metal.");
        std::process::exit(1);
    }
}

#[cfg(target_os = "macos")]
fn run_grinding_loop(
    miner: &sha2_ecdsa::gpu::metal::MetalMiner,
    prefix: &[u8; 8],
    start: u64,
    batch_size: u64,
) {
    let mut counter = start;
    let mut total_attempts: u64 = 0;
    let global_start = Instant::now();
    let mut report_time = Instant::now();

    loop {
        if let Some(result) = miner.mine_batch(prefix, counter, batch_size) {
            let elapsed = global_start.elapsed().as_secs_f64();
            println!("\n=== FOUND ===");
            println!("Preimage: {}", hex::encode(result.preimage));
            println!("Hash:     {}", hex::encode(result.hash));
            println!("Counter:  {}", result.counter);
            println!("Total attempts: {}", total_attempts + (result.counter - counter));
            println!("Elapsed: {:.1}s", elapsed);
            println!("Avg rate: {:.2} GH/s", total_attempts as f64 / elapsed / 1e9);
            return;
        }

        counter += batch_size;
        total_attempts += batch_size;

        if report_time.elapsed().as_secs() >= 2 {
            let elapsed = global_start.elapsed().as_secs_f64();
            let rate = total_attempts as f64 / elapsed / 1e9;
            eprintln!(
                "  {} attempts ({:.2} GH/s) counter={}",
                total_attempts, rate, counter
            );
            report_time = Instant::now();
        }
    }
}

#[cfg(all(feature = "cuda", not(target_os = "macos")))]
fn run_grinding_loop(
    miner: &sha2_ecdsa::gpu::cuda::CudaMiner,
    prefix: &[u8; 8],
    start: u64,
    batch_size: u64,
) {
    let mut counter = start;
    let mut total_attempts: u64 = 0;
    let global_start = Instant::now();
    let mut report_time = Instant::now();

    loop {
        if let Some(result) = miner.mine_batch(prefix, counter, batch_size) {
            let elapsed = global_start.elapsed().as_secs_f64();
            println!("\n=== FOUND ===");
            println!("Preimage: {}", hex::encode(result.preimage));
            println!("Hash:     {}", hex::encode(result.hash));
            println!("Counter:  {}", result.counter);
            println!("Total attempts: {}", total_attempts + (result.counter - counter));
            println!("Elapsed: {:.1}s", elapsed);
            println!("Avg rate: {:.2} GH/s", total_attempts as f64 / elapsed / 1e9);
            return;
        }

        counter += batch_size;
        total_attempts += batch_size;

        if report_time.elapsed().as_secs() >= 2 {
            let elapsed = global_start.elapsed().as_secs_f64();
            let rate = total_attempts as f64 / elapsed / 1e9;
            eprintln!(
                "  {} attempts ({:.2} GH/s) counter={}",
                total_attempts, rate, counter
            );
            report_time = Instant::now();
        }
    }
}
