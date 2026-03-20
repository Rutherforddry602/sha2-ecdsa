use serde::{Deserialize, Serialize};

/// Work assignment from coordinator to worker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkAssignment {
    pub prefix: [u8; 8],
    pub range_start: u64,
    pub range_size: u64,
}

/// Result from worker to coordinator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkResult {
    pub worker_id: String,
    pub found: Option<FoundPreimage>,
    pub attempts: u64,
    pub hashrate_ghs: f64,
}

/// A valid preimage that was found
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundPreimage {
    pub preimage_hex: String,
    pub hash_hex: String,
    pub counter: u64,
}

/// Cluster status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterStatus {
    pub total_attempts: u64,
    pub total_hashrate_ghs: f64,
    pub active_workers: usize,
    pub solution_found: bool,
    pub solution: Option<FoundPreimage>,
}
