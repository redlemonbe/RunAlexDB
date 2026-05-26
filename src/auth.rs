//! MySQL native_password authentication (SHA1 scramble).

use sha1::{Digest, Sha1};

/// Generate 20-byte random scramble for the handshake.
pub fn generate_scramble() -> [u8; 20] {
    use rand::RngCore;
    let mut s = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut s);
    // MySQL scramble bytes must not include 0x00
    for b in s.iter_mut() {
        if *b == 0 { *b = 1; }
    }
    s
}

/// Verify a `mysql_native_password` response.
/// response = SHA1(SHA1(password)) XOR SHA1(scramble || SHA1(SHA1(password)))
pub fn verify_native_password(password: &str, scramble: &[u8], response: &[u8]) -> bool {
    if response.is_empty() {
        return password.is_empty();
    }
    let hash1 = sha1(password.as_bytes());
    let hash2 = sha1(&hash1);

    let mut combined = Vec::with_capacity(scramble.len() + 20);
    combined.extend_from_slice(scramble);
    combined.extend_from_slice(&hash2);
    let expected_xor = sha1(&combined);

    if response.len() != 20 { return false; }
    let recovered: Vec<u8> = response.iter().zip(expected_xor.iter())
        .map(|(r, e)| r ^ e)
        .collect();
    recovered == hash1
}

fn sha1(data: &[u8]) -> Vec<u8> {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().to_vec()
}

/// Verify using a pre-computed SHA1(SHA1(password)) hash (stored in user table).
/// Avoids recomputing the hash on every login.
pub fn verify_native_password_hash(hash2: &[u8], scramble: &[u8], response: &[u8]) -> bool {
    if response.is_empty() {
        return hash2.iter().all(|&b| b == 0);
    }
    if response.len() != 20 { return false; }

    let mut combined = Vec::with_capacity(scramble.len() + 20);
    combined.extend_from_slice(scramble);
    combined.extend_from_slice(hash2);
    let expected_xor = {
        let mut h = Sha1::new();
        h.update(&combined);
        h.finalize().to_vec()
    };

    let hash1_from_client: Vec<u8> = response.iter().zip(expected_xor.iter())
        .map(|(r, e)| r ^ e)
        .collect();

    // Verify: SHA1(hash1_from_client) == hash2
    let mut h = Sha1::new();
    h.update(&hash1_from_client);
    let check = h.finalize().to_vec();
    check == hash2
}
