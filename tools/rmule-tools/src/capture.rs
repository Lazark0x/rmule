//! Capture evidence on disk: reading a recorded packet back, rendering raw wire
//! bytes for the operator, and writing a new fixture without ever clobbering an
//! existing one.

use std::path::Path;

use anyhow::{Context, Result};
use rmule_primitives::Packet;

/// Render raw wire bytes as lower-case hex — how the tools print a datagram or
/// frame that has no decoded projection worth showing.
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

pub(crate) fn decode_packet_path(path: &Path) -> Result<Packet> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Packet::decode_exact(&bytes).with_context(|| format!("decode packet {}", path.display()))
}

/// Write captured counterparty bytes to a file that must not already exist.
///
/// Capture tools name their outputs after the fixture they feed, so a second run
/// against a different counterparty would otherwise overwrite the evidence of
/// the first in place. Refuse instead — the operator moves or renames the old
/// capture deliberately (there is no `--force`; the point is that a clobber is
/// never silent).
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        anyhow::bail!(
            "{} already exists; refusing to overwrite a capture (move it aside first)",
            path.display()
        );
    }
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::write_new;

    /// The **Capture** rule the NAT-T and IPv6 drivers now write through: a
    /// second write to one path is refused and the first bytes survive.
    #[test]
    fn a_capture_is_never_overwritten() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("frame.bin");
        write_new(&path, b"first").expect("the first write lands");
        assert!(write_new(&path, b"second").is_err());
        assert_eq!(std::fs::read(&path).expect("read back"), b"first");
    }
}
