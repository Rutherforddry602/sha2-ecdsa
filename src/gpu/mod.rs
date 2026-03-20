#[cfg(target_os = "macos")]
pub mod metal;

#[cfg(feature = "cuda")]
pub mod cuda;

/// Result from a GPU mining batch
pub struct MineResult {
    /// The counter value that produced a valid DER signature
    pub counter: u64,
    /// The 16-byte preimage (prefix || counter)
    pub preimage: [u8; 16],
    /// The 32-byte SHA256 hash (valid DER signature)
    pub hash: [u8; 32],
}
