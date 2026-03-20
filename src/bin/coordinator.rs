use clap::Parser;
use sha2_ecdsa::cluster::coordinator::{build_router, CoordinatorState};
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "coordinator", about = "GPU cluster coordinator for SHA2-ECDSA grinding")]
struct Args {
    /// 8-byte prefix in hex
    #[arg(long, default_value = "0000000000000000")]
    prefix: String,

    /// Listen port
    #[arg(long, default_value = "8080")]
    port: u16,

    /// Attempts per work chunk assigned to workers
    #[arg(long, default_value = "1000000000")]
    chunk_size: u64,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let prefix_bytes = hex::decode(&args.prefix).expect("Invalid hex prefix");
    assert_eq!(prefix_bytes.len(), 8, "Prefix must be exactly 8 bytes");
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&prefix_bytes);

    let state = Arc::new(CoordinatorState::new(prefix, args.chunk_size));
    let app = build_router(state.clone());

    let addr = format!("0.0.0.0:{}", args.port);
    eprintln!("Coordinator listening on {}", addr);
    eprintln!("Prefix: {}", args.prefix);
    eprintln!("Chunk size: {} ({:.1}B attempts per work unit)", args.chunk_size, args.chunk_size as f64 / 1e9);

    // Status printer
    let state2 = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            let total = state2.total_attempts.load(std::sync::atomic::Ordering::Relaxed);
            let elapsed = state2.start_time.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 { total as f64 / elapsed / 1e9 } else { 0.0 };
            let found = state2.solution_found.load(std::sync::atomic::Ordering::Relaxed);
            eprintln!(
                "[status] attempts={} rate={:.2} GH/s elapsed={:.0}s found={}",
                total, rate, elapsed, found
            );
            if found { break; }
        }
    });

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
