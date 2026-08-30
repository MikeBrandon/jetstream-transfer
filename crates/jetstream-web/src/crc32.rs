//! CRC-32 (IEEE), used to verify browser uploads end to end.
//!
//! # Why not BLAKE3
//!
//! The native protocol hashes every chunk with BLAKE3, and the browser path
//! cannot. A page served over plain HTTP is not a secure context, so
//! `crypto.subtle` is unavailable — and even with HTTPS it only offers SHA-2,
//! never BLAKE3. Getting BLAKE3 into a browser means shipping a WebAssembly
//! build, which is a wasm toolchain in the build pipeline and a second artifact
//! to keep in step, for a path that exists so a phone can send a holiday photo.
//!
//! # Why CRC-32 is nevertheless the right answer here
//!
//! Be precise about what needs defending. On the native path the sender may be
//! hostile, so chunk hashes must be cryptographic. On the browser path *the
//! sender is the user*, sitting at their own phone, uploading their own file.
//! There is no second party to authenticate — the browser cannot hold a key,
//! which is the entire reason this path exists.
//!
//! What remains is **corruption**: a flipped bit on flaky Wi-Fi, a truncated
//! chunk, or a proxy mangling a request. TCP's 16-bit checksum misses roughly
//! one error in 65,000. CRC-32 catches every burst error up to 32 bits and all
//! but one in four billion otherwise, and runs at hundreds of MB/s in plain
//! JavaScript with a 256-entry table.
//!
//! So: real end-to-end corruption detection, no toolchain, no WASM. What it is
//! *not* is a security guarantee, and nothing in this crate pretends otherwise —
//! see [`Staging::finish_file_chunkwise`](jetstream_core::staging::Staging::finish_file_chunkwise).

/// Standard CRC-32 (polynomial `0xEDB88320`, reflected), matching zlib, PNG, and
/// the `crc32` implementation in the browser client.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;

    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            // Branchless: the mask is all-ones when the low bit is set.
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }

    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Values cross-checked against zlib, so the JavaScript side has a fixed
    /// reference to agree with. A CRC that is self-consistent but not the
    /// standard one would pass a round-trip test and fail against the browser.
    #[test]
    fn matches_the_standard_crc32() {
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
        assert_eq!(crc32(b"abc"), 0x3524_41C2);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b"The quick brown fox jumps over the lazy dog"), 0x414F_A339);
    }

    #[test]
    fn detects_a_single_flipped_bit() {
        // The actual job: catching one bad bit in a megabyte.
        let mut data = vec![0x5Au8; 1 << 20];
        let good = crc32(&data);

        data[500_000] ^= 0b0000_0001;
        assert_ne!(crc32(&data), good);
    }

    #[test]
    fn detects_truncation_and_reordering() {
        let data = b"chunk payload that arrived intact";

        assert_ne!(crc32(data), crc32(&data[..data.len() - 1]), "truncation");

        let mut swapped = data.to_vec();
        swapped.swap(0, 1);
        assert_ne!(crc32(data), crc32(&swapped), "reordering");
    }

    #[test]
    fn is_stable_across_calls() {
        let data = vec![0xABu8; 4096];
        assert_eq!(crc32(&data), crc32(&data));
    }
}
