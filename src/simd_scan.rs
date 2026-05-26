//! SIMD-accelerated scan primitives for RunAlexDB v0.3.0.
//!
//! * hash_query()   — hardware CRC32 (SSE4.2) for query cache keying
//! * scan_eq_i64()  — AVX2 4-wide equality scan for WHERE col = N
//! * scan_gt_i64()  — AVX2 4-wide greater-than scan for WHERE col > N
//! * scan_lt_i64()  — AVX2 4-wide less-than scan for WHERE col < N

/// Hash a SQL string using hardware CRC32 (SSE4.2) when available,
/// falling back to FNV-1a on other architectures.
#[inline]
pub fn hash_query(sql: &[u8]) -> u64 {
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("sse4.2") {
        return unsafe { crc32_sse42(sql) };
    }
    fnv1a(sql)
}

/// SSE4.2 CRC32 — processes 8 bytes per instruction.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2")]
unsafe fn crc32_sse42(data: &[u8]) -> u64 {
    use std::arch::x86_64::_mm_crc32_u64;
    let mut crc: u64 = !0u64;
    let mut i = 0;
    while i + 8 <= data.len() {
        let word = u64::from_le_bytes(*(data.as_ptr().add(i) as *const [u8; 8]));
        crc = _mm_crc32_u64(crc, word);
        i += 8;
    }
    while i < data.len() {
        crc = _mm_crc32_u64(crc, *data.as_ptr().add(i) as u64);
        i += 1;
    }
    !crc
}

fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

// ── AVX2 column-store scans ───────────────────────────────────────────────

/// Equality scan. Returns sorted row indices where data[i] == target.
pub fn scan_eq_i64(data: &[i64], target: i64) -> Vec<usize> {
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx2") {
        return unsafe { scan_eq_avx2(data, target) };
    }
    data.iter().enumerate().filter(|(_, &v)| v == target).map(|(i, _)| i).collect()
}

/// Greater-than scan. Returns indices where data[i] > target.
pub fn scan_gt_i64(data: &[i64], target: i64) -> Vec<usize> {
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx2") {
        return unsafe { scan_gt_avx2(data, target) };
    }
    data.iter().enumerate().filter(|(_, &v)| v > target).map(|(i, _)| i).collect()
}

/// Less-than scan. Returns indices where data[i] < target.
pub fn scan_lt_i64(data: &[i64], target: i64) -> Vec<usize> {
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx2") {
        return unsafe { scan_lt_avx2(data, target) };
    }
    data.iter().enumerate().filter(|(_, &v)| v < target).map(|(i, _)| i).collect()
}

// ── AVX2 implementations ──────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scan_eq_avx2(data: &[i64], target: i64) -> Vec<usize> {
    use std::arch::x86_64::*;
    let splat = _mm256_set1_epi64x(target);
    let mut out = Vec::with_capacity(32);
    let n4 = data.len() / 4 * 4;
    let mut i = 0;
    while i < n4 {
        let v = _mm256_loadu_si256(data.as_ptr().add(i) as *const __m256i);
        let cmp = _mm256_cmpeq_epi64(v, splat);
        // movemask_epi8: 8 bits per i64 lane (0xFF = match)
        let mask = _mm256_movemask_epi8(cmp) as u32;
        if mask != 0 {
            if mask & 0x0000_00FF != 0 { out.push(i);     }
            if mask & 0x0000_FF00 != 0 { out.push(i + 1); }
            if mask & 0x00FF_0000 != 0 { out.push(i + 2); }
            if mask & 0xFF00_0000 != 0 { out.push(i + 3); }
        }
        i += 4;
    }
    while i < data.len() { if data[i] == target { out.push(i); } i += 1; }
    out
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scan_gt_avx2(data: &[i64], target: i64) -> Vec<usize> {
    use std::arch::x86_64::*;
    let splat = _mm256_set1_epi64x(target);
    let mut out = Vec::with_capacity(32);
    let n4 = data.len() / 4 * 4;
    let mut i = 0;
    while i < n4 {
        let v = _mm256_loadu_si256(data.as_ptr().add(i) as *const __m256i);
        let cmp = _mm256_cmpgt_epi64(v, splat);
        let mask = _mm256_movemask_epi8(cmp) as u32;
        if mask != 0 {
            if mask & 0x0000_00FF != 0 { out.push(i);     }
            if mask & 0x0000_FF00 != 0 { out.push(i + 1); }
            if mask & 0x00FF_0000 != 0 { out.push(i + 2); }
            if mask & 0xFF00_0000 != 0 { out.push(i + 3); }
        }
        i += 4;
    }
    while i < data.len() { if data[i] > target { out.push(i); } i += 1; }
    out
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scan_lt_avx2(data: &[i64], target: i64) -> Vec<usize> {
    use std::arch::x86_64::*;
    // a < b  iff  b > a
    let splat = _mm256_set1_epi64x(target);
    let mut out = Vec::with_capacity(32);
    let n4 = data.len() / 4 * 4;
    let mut i = 0;
    while i < n4 {
        let v = _mm256_loadu_si256(data.as_ptr().add(i) as *const __m256i);
        let cmp = _mm256_cmpgt_epi64(splat, v);  // target > v  iff  v < target
        let mask = _mm256_movemask_epi8(cmp) as u32;
        if mask != 0 {
            if mask & 0x0000_00FF != 0 { out.push(i);     }
            if mask & 0x0000_FF00 != 0 { out.push(i + 1); }
            if mask & 0x00FF_0000 != 0 { out.push(i + 2); }
            if mask & 0xFF00_0000 != 0 { out.push(i + 3); }
        }
        i += 4;
    }
    while i < data.len() { if data[i] < target { out.push(i); } i += 1; }
    out
}

// ── String column scans ───────────────────────────────────────────────────

/// Equality scan over a string column store. Returns sorted row indices where data[i] == target.
/// Uses an AVX2 fast path for targets ≤ 32 bytes (compares first 32 bytes in one SIMD op,
/// then falls back to byte comparison for the remainder). Scalar fallback on non-AVX2.
pub fn scan_eq_str(data: &[String], target: &str) -> Vec<usize> {
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx2") && !target.is_empty() && target.len() <= 32 {
        return unsafe { scan_eq_str_avx2(data, target) };
    }
    data.iter()
        .enumerate()
        .filter(|(_, s)| s.as_str() == target)
        .map(|(i, _)| i)
        .collect()
}

/// LIKE prefix scan: returns indices where data[i] starts with prefix.
pub fn scan_prefix_str(data: &[String], prefix: &str) -> Vec<usize> {
    data.iter()
        .enumerate()
        .filter(|(_, s)| s.as_str().starts_with(prefix))
        .map(|(i, _)| i)
        .collect()
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scan_eq_str_avx2(data: &[String], target: &str) -> Vec<usize> {
    use std::arch::x86_64::*;
    let tb = target.as_bytes();
    let tlen = tb.len();
    // Build a 32-byte pattern padded with zeros
    let mut pat = [0u8; 32];
    pat[..tlen].copy_from_slice(tb);
    let vpat = _mm256_loadu_si256(pat.as_ptr() as *const __m256i);
    let mut out = Vec::with_capacity(16);
    for (i, s) in data.iter().enumerate() {
        let sb = s.as_bytes();
        if sb.len() != tlen { continue; }
        // For strings ≤ 32 bytes: build same padded buf and compare all 32 bytes
        let mut buf = [0u8; 32];
        buf[..tlen].copy_from_slice(sb);
        let vbuf = _mm256_loadu_si256(buf.as_ptr() as *const __m256i);
        let cmp = _mm256_cmpeq_epi8(vbuf, vpat);
        let mask = _mm256_movemask_epi8(cmp) as u32;
        // All tlen bytes must match; bits beyond tlen are 0==0 so they also match
        if mask == 0xFFFF_FFFFu32 {
            out.push(i);
        }
    }
    out
}
