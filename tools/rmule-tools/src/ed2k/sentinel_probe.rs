//! `ed2k sentinel-probe`: the readiness marker for rmule's sentinel-safe reader
//! (ADR-0085).
//!
//! Builds ed2k-server#12's documented 39-byte sentinel-source payload in
//! memory, decodes it through this binary's own compiled `rmule-ed2k`, and
//! asserts the appended address block landed as a single `Ipv6` source with a
//! clean tail. A `cargo test` in the crate proves the reader once; this proves
//! it is actually wired into the `rmule-tools` binary the interop harness
//! runs — the distinction `tools/interop-harness`'s `sentinel-sources-legacy`
//! flow (ADR-0092) gates on. That flow points its
//! `--sentinel-reader-probe` at this command; a non-zero exit here is its
//! documented-absence signal, never a hang or a silent pass.

use std::net::Ipv6Addr;

use anyhow::{Context, Result, bail};
use rmule_ed2k::FoundSources;
use rmule_primitives::{Ipv6Endpoint, Packet, PacketProtocol, PeerSource, SourceListTail};

/// `OP_FOUNDSOURCES`'s opcode byte (`Opcode::FoundSources`, not re-exported to
/// this crate — the payload shape is public API, the opcode constant is not).
const OP_FOUNDSOURCES: u8 = 0x42;

/// The address the probe's payload appends after its one sentinel record.
const PROBE_ADDRESS: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x00c0);
const PROBE_PORT: u16 = 4662;
/// Fills the 16-byte file hash field; the probe never looks it up, only round
/// trips it.
const PROBE_FILE_HASH_BYTE: u8 = 0x51;

/// `[hash 16][count 1][id 4][port 2][tail 16]` — ed2k-server#12's documented
/// 39-byte shape for one sentinel source (see
/// `crates/rmule-ed2k/tests/ed2k/sentinel_sources.rs`, which this mirrors at
/// the wire level rather than importing, since a test module is not this
/// binary's dependency).
fn probe_payload() -> Vec<u8> {
    let mut payload = vec![PROBE_FILE_HASH_BYTE; 16];
    payload.push(1);
    payload.extend_from_slice(&PeerSource::IPV6_SENTINEL.to_le_bytes());
    payload.extend_from_slice(&PROBE_PORT.to_le_bytes());
    payload.extend_from_slice(&PROBE_ADDRESS.octets());
    payload
}

/// Decode the probe payload and assert the sentinel-safe reader read it.
///
/// # Errors
/// If the payload does not decode at all, or decodes to anything other than
/// the one `Ipv6` source it names with a clean (non-`Malformed`) tail — either
/// is this binary's sentinel-safe reader not being wired end to end.
pub(crate) fn sentinel_probe() -> Result<()> {
    let payload = probe_payload();
    assert_eq!(
        payload.len(),
        39,
        "ed2k-server#12's sentinel source payload"
    );
    println!("sentinel_probe: payload_len={}", payload.len());

    let packet = Packet::new(PacketProtocol::Edonkey, OP_FOUNDSOURCES, payload);
    let decoded = FoundSources::decode_packet(&packet)
        .context("decode ed2k-server#12's sentinel source payload")?;

    let expected = PeerSource::Ipv6(Ipv6Endpoint::new(PROBE_ADDRESS, PROBE_PORT));
    let sources = decoded.sources();
    if sources != [expected] {
        bail!("sentinel_probe: expected one source {expected:?}, decoded {sources:?}");
    }
    let tail = decoded.tail();
    if tail != (SourceListTail::Read { sentinels: 1 }) {
        bail!(
            "sentinel_probe: expected a clean tail (Read {{ sentinels: 1 }}), decoded {tail:?} \
             — the reader did not consume the appended address block"
        );
    }

    println!("sentinel_probe: source={expected:?}");
    println!("sentinel_probe: tail={tail:?}");
    println!("sentinel_probe: PASS (sentinel-safe reader wired end to end)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_probe_passes_against_this_binarys_own_reader() {
        sentinel_probe().expect("the compiled-in sentinel-safe reader decodes its own probe");
    }
}
