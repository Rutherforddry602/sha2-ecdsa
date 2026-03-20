use crate::cluster::protocol::*;
use axum::{extract::State, routing::{get, post}, Json, Router};
use std::sync::{atomic::{AtomicBool, AtomicU64, Ordering}, Arc, Mutex};
use std::time::Instant;

pub struct CoordinatorState {
    pub prefix: [u8; 8],
    pub chunk_size: u64,
    pub next_range_start: AtomicU64,
    pub total_attempts: AtomicU64,
    pub total_hashrate_ghs: Mutex<f64>,
    pub active_workers: AtomicU64,
    pub solution_found: AtomicBool,
    pub solution: Mutex<Option<FoundPreimage>>,
    pub start_time: Instant,
}

impl CoordinatorState {
    pub fn new(prefix: [u8; 8], chunk_size: u64) -> Self {
        CoordinatorState {
            prefix,
            chunk_size,
            next_range_start: AtomicU64::new(0),
            total_attempts: AtomicU64::new(0),
            total_hashrate_ghs: Mutex::new(0.0),
            active_workers: AtomicU64::new(0),
            solution_found: AtomicBool::new(false),
            solution: Mutex::new(None),
            start_time: Instant::now(),
        }
    }
}

async fn get_work(State(state): State<Arc<CoordinatorState>>) -> Json<Option<WorkAssignment>> {
    if state.solution_found.load(Ordering::Relaxed) {
        return Json(None);
    }

    let range_start = state.next_range_start.fetch_add(state.chunk_size, Ordering::Relaxed);

    Json(Some(WorkAssignment {
        prefix: state.prefix,
        range_start,
        range_size: state.chunk_size,
    }))
}

async fn post_result(
    State(state): State<Arc<CoordinatorState>>,
    Json(result): Json<WorkResult>,
) -> Json<bool> {
    state.total_attempts.fetch_add(result.attempts, Ordering::Relaxed);
    *state.total_hashrate_ghs.lock().unwrap() = result.hashrate_ghs;

    if let Some(found) = result.found {
        state.solution_found.store(true, Ordering::Relaxed);
        *state.solution.lock().unwrap() = Some(found.clone());

        let elapsed = state.start_time.elapsed().as_secs_f64();
        let total = state.total_attempts.load(Ordering::Relaxed);
        eprintln!("\n=== SOLUTION FOUND ===");
        eprintln!("Preimage: {}", found.preimage_hex);
        eprintln!("Hash:     {}", found.hash_hex);
        eprintln!("Counter:  {}", found.counter);
        eprintln!("Total attempts: {}", total);
        eprintln!("Elapsed: {:.1}s", elapsed);
        eprintln!("======================\n");
    }

    Json(state.solution_found.load(Ordering::Relaxed))
}

async fn get_status(State(state): State<Arc<CoordinatorState>>) -> Json<ClusterStatus> {
    let solution = state.solution.lock().unwrap().clone();
    Json(ClusterStatus {
        total_attempts: state.total_attempts.load(Ordering::Relaxed),
        total_hashrate_ghs: *state.total_hashrate_ghs.lock().unwrap(),
        active_workers: state.active_workers.load(Ordering::Relaxed) as usize,
        solution_found: state.solution_found.load(Ordering::Relaxed),
        solution,
    })
}

pub fn build_router(state: Arc<CoordinatorState>) -> Router {
    Router::new()
        .route("/work", get(get_work))
        .route("/result", post(post_result))
        .route("/status", get(get_status))
        .with_state(state)
}
