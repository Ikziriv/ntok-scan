//! Favicon hashing — Shodan's `http.favicon.hash` trick. Fetch
//! `/favicon.ico`, mmh3 it the way Shodan does (over python-style
//! base64), and look the hash up in a table of known product icons.
//! Catches infrastructure the page source never mentions.

use std::collections::HashMap;
use std::sync::OnceLock;
use tokio_util::sync::CancellationToken;

const FAVICON_DB: &str = include_str!("../../data/favicon-hashes.json");

/// mmh3 hash → product name, vendored from nuclei-templates'
/// favicon-detect matchers.
fn table() -> &'static HashMap<i32, String> {
    static T: OnceLock<HashMap<i32, String>> = OnceLock::new();
    T.get_or_init(|| serde_json::from_str(FAVICON_DB).expect("favicon-hashes.json parses"))
}

/// Product name for a favicon hash, if known.
pub fn lookup(hash: i32) -> Option<&'static str> {
    table().get(&hash).map(String::as_str)
}

/// Fetch `/favicon.ico` for the profiled origin and mmh3 its bytes the
/// Shodan way: `mmh3(base64.encodebytes(raw))`. Any failure → `None`.
pub async fn fetch_hash(
    site: &super::http::Site,
    final_url: &url::Url,
    cancel: CancellationToken,
) -> Option<i32> {
    let u = final_url.join("/favicon.ico").ok()?;
    let (status, raw) = site.fetch_bytes(&u, cancel).await.ok()?;
    if status != 200 || raw.is_empty() {
        return None;
    }
    Some(mmh3_32(&b64_py(&raw), 0))
}

/// MurmurHash3 x86_32, seed-parameterised. Shodan hashes with seed 0
/// and prints the result as a signed i32.
fn mmh3_32(data: &[u8], seed: u32) -> i32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let mut h = seed;
    let (blocks, tail) = data.as_chunks::<4>();
    for blk in blocks {
        let mut k = u32::from_le_bytes(*blk);
        k = k.wrapping_mul(C1);
        k = k.rotate_left(15);
        k = k.wrapping_mul(C2);
        h ^= k;
        h = h.rotate_left(13);
        h = h.wrapping_mul(5).wrapping_add(0xe654_6b64);
    }
    let mut k = 0u32;
    for (i, &b) in tail.iter().enumerate() {
        k |= (b as u32) << (8 * i);
    }
    if !tail.is_empty() {
        k = k.wrapping_mul(C1);
        k = k.rotate_left(15);
        k = k.wrapping_mul(C2);
        h ^= k;
    }
    h ^= data.len() as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h as i32
}

/// `base64.encodebytes` — standard base64 wrapped at 76 columns with a
/// trailing newline. Shodan's favicon hash includes the wrapping.
fn b64_py(data: &[u8]) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = Vec::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        s.push(T[(n >> 18) as usize & 63]);
        s.push(T[(n >> 12) as usize & 63]);
        s.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63]
        } else {
            b'='
        });
        s.push(if c.len() > 2 {
            T[n as usize & 63]
        } else {
            b'='
        });
    }
    let mut out = Vec::with_capacity(s.len() + s.len() / 76 + 1);
    for line in s.chunks(76) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mmh3_matches_reference() {
        // python: mmh3.hash(b"foo") == -156908512
        assert_eq!(mmh3_32(b"foo", 0), -156908512);
        assert_eq!(mmh3_32(b"", 0), 0);
    }

    #[test]
    fn b64_py_wraps_at_76() {
        let out = b64_py(&[b'x'; 60]);
        // 60 bytes → 80 b64 chars wrapped at 76: "eHh4"*19 + \n + "eHh4" + \n
        let s = String::from_utf8(out).unwrap();
        assert_eq!(s, format!("{}\n{}\n", "eHh4".repeat(19), "eHh4"));
    }

    #[test]
    fn table_loads() {
        assert!(table().len() > 500);
        assert_eq!(lookup(81586312), Some("Jenkins"));
    }
}
