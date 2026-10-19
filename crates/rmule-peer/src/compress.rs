//! Private zlib helper for compressed part transfer (`OP_COMPRESSEDPART`).
//!
//! eMule peer parts use a standard zlib stream, confirmed against aMule
//! `DownloadClient.cpp::ProcessBlockPacket` @ `377ec8d9` (`uncompress`).
//! `flate2` (miniz_oxide backend) stays a private dependency — the public API
//! exposes only rmule-owned types, mirroring `rmule-ed2k`'s server-frame
//! helper (`docs/reference/notes/packet-framing.md`).

use std::io::Read;

use flate2::Compression;
use flate2::read::ZlibDecoder;
use thiserror::Error;

/// Why a compressed part could not be inflated. Non-terminal at the session
/// level (cycle 6): the part is released for retry and the connection stays
/// open, mirroring `rmule-ed2k`'s `CompressedFrameSkipped`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum InflateFailed {
    /// The bytes are not a zlib stream at all.
    #[error("compressed part is not a valid zlib stream")]
    Corrupt,
    /// Inflation ran past the ceiling — refused there rather than after,
    /// so a zip bomb never gets the memory.
    #[error("inflated part exceeds the {ceiling}-byte ceiling")]
    TooLarge {
        /// The ceiling that was hit.
        ceiling: usize,
    },
    /// The peer declared an `nBlockSize` beyond what any zlib stream for a
    /// `ceiling`-byte block can occupy (the ceiling plus compressBound-style
    /// slack); the block is refused before a single byte is buffered.
    #[error("declared compressed length {declared} exceeds the {ceiling}-byte input ceiling")]
    DeclaredTooLarge {
        /// The length the peer declared.
        declared: u32,
        /// The largest input any block of this size could need.
        ceiling: usize,
    },
    /// The session already holds its maximum number of mid-accumulation
    /// compressed blocks; the newest block is refused so a hostile peer
    /// cannot multiply buffers across offsets or files.
    #[error("too many compressed blocks mid-accumulation")]
    TooManyInFlight,
}

/// Inflate a complete zlib-compressed part block, bounding the output to
/// `size_ceiling` bytes so a malformed or hostile stream cannot allocate
/// without limit (mirrors aMule's decompressed-size cap on the server path).
pub(crate) fn inflate(compressed: &[u8], size_ceiling: usize) -> Result<Vec<u8>, InflateFailed> {
    let mut out = Vec::new();
    ZlibDecoder::new(compressed)
        .take(size_ceiling as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| InflateFailed::Corrupt)?;
    if out.len() > size_ceiling {
        return Err(InflateFailed::TooLarge {
            ceiling: size_ceiling,
        });
    }
    Ok(out)
}

/// The zlib stream a served block crosses in (`OP_COMPRESSEDPART`), when one
/// is shorter than the block (ADR-0031): a first pass at level 1, so a block
/// that does not shrink — most media — costs a fifth of a full pass and is
/// `None`; a block that does is deflated again at level 6, and the shorter
/// stream is kept.
pub(crate) fn deflate_smaller(plain: &[u8]) -> Option<Vec<u8>> {
    let fast = Some(deflate(plain, Compression::fast())).filter(|fast| fast.len() < plain.len())?;
    let full = deflate(plain, Compression::new(6));
    Some(if full.len() < fast.len() { full } else { fast })
}

/// `plain` as one standard zlib stream at `level`.
fn deflate(plain: &[u8], level: Compression) -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    use std::io::Write;
    let mut enc = ZlibEncoder::new(Vec::new(), level);
    enc.write_all(plain)
        .expect("zlib write to a Vec is infallible");
    enc.finish().expect("zlib finish to a Vec is infallible")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inflate_round_trips_zlib_compressed_bytes() {
        let plain = b"the quick brown fox ".repeat(50);
        let stream = deflate_smaller(&plain).expect("repeated text shrinks");
        assert_eq!(inflate(&stream, plain.len()).unwrap(), plain);
    }

    #[test]
    fn a_block_that_shrinks_crosses_no_longer_than_level_six_makes_it_and_one_that_does_not_goes_plain()
     {
        // Bytes that deflate well, and bytes that do not: a xorshift stream.
        let text = b"a served block of source text, ".repeat(6000);
        let mut x = 0x2545_F491_4F6C_DD1D_u64;
        let noise: Vec<u8> = (0..184_320)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();

        let stream = deflate_smaller(&text).expect("text shrinks");
        assert!(stream.len() <= deflate(&text, Compression::new(6)).len());
        assert_eq!(inflate(&stream, text.len()).unwrap(), text);
        assert_eq!(deflate_smaller(&noise), None);
    }

    #[test]
    fn inflate_rejects_corrupt_stream() {
        assert_eq!(
            inflate(b"not a zlib stream", 1024),
            Err(InflateFailed::Corrupt)
        );
    }

    #[test]
    fn inflate_rejects_output_over_ceiling() {
        let plain = vec![0u8; 10_000]; // compresses tiny, inflates past the cap
        assert_eq!(
            inflate(&deflate_smaller(&plain).unwrap(), 4096),
            Err(InflateFailed::TooLarge { ceiling: 4096 })
        );
    }
}
