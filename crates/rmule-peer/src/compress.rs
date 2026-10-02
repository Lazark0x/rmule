//! Private zlib helper for compressed part transfer (`OP_COMPRESSEDPART`).
//!
//! eMule peer parts use a standard zlib stream, confirmed against aMule
//! `DownloadClient.cpp::ProcessBlockPacket` @ `377ec8d9` (`uncompress`).
//! `flate2` (miniz_oxide backend) stays a private dependency — the public API
//! exposes only rmule-owned types, mirroring `rmule-ed2k`'s server-frame
//! helper (`docs/reference/notes/packet-framing.md`).

use std::io::Read;

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

/// Deflate bytes into a standard zlib stream — the encode side of compressed
/// part transfer (`OP_COMPRESSEDPART` on the serve path).
pub(crate) fn deflate(plain: &[u8]) -> Vec<u8> {
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
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
        assert_eq!(inflate(&deflate(&plain), plain.len()).unwrap(), plain);
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
            inflate(&deflate(&plain), 4096),
            Err(InflateFailed::TooLarge { ceiling: 4096 })
        );
    }
}
