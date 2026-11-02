//! `ed2k sentinel-probe`: the readiness marker for rmule's sentinel-safe reader
//! (ADR-0085).
//!
//! Builds ed2k-server#12's documented 39-byte sentinel-source payload in
//! memory, decodes it through this binary's own compiled `rmule-ed2k`, and
//! asserts the appended address block landed as a single `Ipv6` source with a
//! clean tail. It then decodes the list the legacy leg hands aMule: whole it
//! reads whole, and with stray bytes past its last record it does not measure,
//! so only the records before the first sentinel are kept. A `cargo test` in the crate proves the reader once; this proves
//! it is actually wired into the `rmule-tools` binary the interop harness
//! runs — the distinction `tools/interop-harness`'s `sentinel-sources-legacy`
//! flow (ADR-0092) gates on. That flow points its
//! `--sentinel-reader-probe` at this command; a non-zero exit here is its
//! documented-absence signal, never a hang or a silent pass.

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, bail};
use rmule_ed2k::FoundSources;
use rmule_primitives::{
    ClientId, Ipv6Endpoint, Packet, PacketProtocol, PeerSource, SourceListTail,
};

/// `OP_FOUNDSOURCES`'s opcode byte (`Opcode::FoundSources`, not re-exported to
/// this crate — the payload shape is public API, the opcode constant is not).
const OP_FOUNDSOURCES: u8 = 0x42;

/// The address the probe's payload appends after its one sentinel record.
const PROBE_ADDRESS: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x00c0);
const PROBE_PORT: u16 = 4662;
/// Fills the 16-byte file hash field; the probe never looks it up, only round
/// trips it.
const PROBE_FILE_HASH_BYTE: u8 = 0x51;
/// The records either side of the sentinel in the three-record lists.
const BEFORE: (Ipv4Addr, u16) = (Ipv4Addr::new(203, 0, 113, 50), 5001);
const AFTER: (Ipv4Addr, u16) = (Ipv4Addr::new(203, 0, 113, 60), 5003);

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

/// `[hash 16][count 3]`, a plain record, the sentinel with its inline address, a
/// plain record, and `stray` past the last record.
fn three_record_payload(stray: &[u8]) -> Vec<u8> {
    let plain = |(address, port): (Ipv4Addr, u16)| {
        let mut record = address.octets().to_vec();
        record.extend_from_slice(&port.to_le_bytes());
        record
    };
    let mut payload = vec![PROBE_FILE_HASH_BYTE; 16];
    payload.push(3);
    payload.extend_from_slice(&plain(BEFORE));
    payload.extend_from_slice(&PeerSource::IPV6_SENTINEL.to_le_bytes());
    payload.extend_from_slice(&PROBE_PORT.to_le_bytes());
    payload.extend_from_slice(&PROBE_ADDRESS.octets());
    payload.extend_from_slice(&plain(AFTER));
    payload.extend_from_slice(stray);
    payload
}

/// The source a plain record names.
fn plain_source((address, port): (Ipv4Addr, u16)) -> Result<PeerSource> {
    let id = u32::from_le_bytes(address.octets());
    PeerSource::from_record(ClientId::from_u32(id), port)
        .context("a plain probe record is a usable source")
}

/// The list the legacy leg emits reads whole: the sentinel's sixteen bytes sit
/// inside its own record, so the record after it keeps its offset.
fn inline_list_reads_whole() -> Result<()> {
    let payload = three_record_payload(&[]);
    let packet = Packet::new(PacketProtocol::Edonkey, OP_FOUNDSOURCES, payload);
    let decoded = FoundSources::decode_packet(&packet).context("decode the inline list")?;
    let expected = [
        plain_source(BEFORE)?,
        PeerSource::Ipv6(Ipv6Endpoint::new(PROBE_ADDRESS, PROBE_PORT)),
        plain_source(AFTER)?,
    ];
    if decoded.sources() != expected {
        bail!(
            "sentinel_probe: the inline list decoded {:?}, expected {expected:?}",
            decoded.sources()
        );
    }
    println!(
        "sentinel_probe: inline list kept {} of 3 records, tail={:?}",
        decoded.sources().len(),
        decoded.tail()
    );
    Ok(())
}

/// The same list with stray bytes past its last record does not measure: once a
/// variable-length record may have been misread no offset is trustworthy, so the
/// record before the first sentinel is kept and nothing after it.
fn unmeasured_list_keeps_the_records_before_the_first_sentinel() -> Result<()> {
    let payload = three_record_payload(&[0; 3]);
    let packet = Packet::new(PacketProtocol::Edonkey, OP_FOUNDSOURCES, payload);
    let decoded =
        FoundSources::decode_packet(&packet).context("decode the list that does not measure")?;
    let expected = [plain_source(BEFORE)?];
    if decoded.sources() != expected {
        bail!(
            "sentinel_probe: the list that does not measure decoded {:?}, expected {expected:?}",
            decoded.sources()
        );
    }
    let tail = decoded.tail();
    if !matches!(tail, SourceListTail::Malformed { .. }) {
        bail!("sentinel_probe: the list that does not measure read as {tail:?}");
    }
    println!(
        "sentinel_probe: list that does not measure kept {} of 3 records, tail={tail:?}",
        decoded.sources().len()
    );
    Ok(())
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
    inline_list_reads_whole()?;
    unmeasured_list_keeps_the_records_before_the_first_sentinel()?;
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
