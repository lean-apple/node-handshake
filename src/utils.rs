use openssl::sha::sha256;
use rand::{thread_rng, Rng};
use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the current standard UNIX timestamp in seconds
pub fn calculate_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Back to the past")
        .as_secs() as i64
}

/// Generates random nonce from common random generator
// TODO: use a better security crate
pub fn generate_nonce() -> u64 {
    let mut rng = thread_rng();
    rng.gen::<u64>()
}

// First 4 bytes of the double hash
pub const CHECKSUM_SIZE: usize = 4;

/// Calculate the checksum for the Bitcoin message from the payload/data
/// Bitcoin checksums are created by hashing data through SHA256 twice  
/// and only the first 4 bytes are used
pub fn calculate_checksum(data: Vec<u8>) -> [u8; CHECKSUM_SIZE] {
    let hash = sha256(&sha256(&data)[..]);
    let mut checksum = [0u8; CHECKSUM_SIZE];
    checksum.copy_from_slice(&hash[..CHECKSUM_SIZE]);
    checksum
}
