//! The **Reask Responder** — the uploader half of the peer-UDP reask
//! (ADR-0057), sans-I/O and stateless.
//!
//! Two steps across one seam. [`read`] takes what can be known of an
//! `OP_REASKFILEPING` before its sender is: the file it names. The runtime then
//! resolves the sender against its upload queue as a [`Pinger`] and hands that
//! in with the queue's room and the file's share; [`answer`] applies aMule's
//! rules (stock 2.3.3 `4e8f2b3c` `ClientUDPSocket.cpp:171-235`) and says what
//! goes back on the wire ([`ReaskReply`]) and what the ping told the queue
//! ([`Standing`]):
//!
//! - the sender is resolved before the file, so even `OP_FILENOTFOUND` may be
//!   obfuscated for a waiter we know;
//! - a known waiter's ping is answered only for the file it waits for, and its
//!   UDP version decides what is read of the ping (`> 3` the part status,
//!   `== 3` the complete-source count) and whether our status rides the ack —
//!   the parts we hold of the file, a whole file's as the count `0` alone;
//! - a ping cut short of what that version reads is silenced, as aMule's
//!   reader throws and its dispatcher only logs;
//! - an unknown pinger gets `OP_QUEUEFULL`, always plaintext, only while
//!   `waiting + 50 > max`, and silence otherwise, as does an IP several
//!   waiters share.

use rmule_primitives::{FileHash, WireReader};

use super::codec::{
    ClientUdpOpcode, ReaskAck, file_not_found_datagram, queue_full_datagram, strip_header,
    udp_header,
};
use super::crypt::PeerUdpCryptTarget;
use crate::file::PartBitmap;
use crate::file_request::{FileSizedStatus, read_file_sized_status};

/// How far above the waiting count an unknown pinger finds the queue full:
/// aMule answers `OP_QUEUEFULL` while `waiting + 50 > queue size`
/// (`ClientUDPSocket.cpp:232`).
const QUEUE_FULL_HEADROOM: usize = 50;

/// An inbound `OP_REASKFILEPING`, read as far as anyone can before its sender
/// is known: the file it names. What else it carries depends on the sender's
/// UDP version, which only the queue knows, so the rest stays unread until
/// [`answer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReaskPing<'a> {
    datagram: &'a [u8],
    file_hash: FileHash,
}

impl ReaskPing<'_> {
    /// The file the ping asks about.
    #[must_use]
    pub const fn file_hash(&self) -> FileHash {
        self.file_hash
    }
}

/// Read a whole `[0xC5][0x90][body]` datagram as a ping, or `None` when it is
/// too short to name a file or is not a ping at all — dropped unanswered,
/// since nothing in it says whom to answer about what.
#[must_use]
pub fn read(datagram: &[u8]) -> Option<ReaskPing<'_>> {
    file_hash_of(datagram).map(|file_hash| ReaskPing {
        datagram,
        file_hash,
    })
}

/// The `0x90` a buddy relayed over its TCP link (`OP_REASKCALLBACKTCP`),
/// re-framed from the forwarded body so it reads as one that arrived by
/// socket: aMule re-enters its own ping consume with that body and the
/// injected requester standing in for the datagram source
/// (`ClientTCPSocket.cpp#L1695`).
#[must_use]
pub fn relayed_ping(forwarded: &[u8]) -> Vec<u8> {
    let mut datagram = udp_header(ClientUdpOpcode::ReaskFilePing);
    datagram.extend_from_slice(forwarded);
    datagram
}

/// Who sent a ping, as far as the upload queue is concerned (aMule
/// `CUploadQueue::GetWaitingClientByIP_UDP`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pinger {
    /// One waiter, matched by IP and UDP port or as the only waiter behind
    /// its IP.
    Known(KnownWaiter),
    /// Several waiters share the pinger's IP on other UDP ports.
    Ambiguous,
    /// No waiter behind the pinger's IP.
    Unknown,
}

/// What the queue and the waiter's hello say of a known pinger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KnownWaiter {
    /// The file the waiter is queued for.
    pub waiting_for: FileHash,
    /// Its 1-based queue position, which the ack carries back.
    pub rank: u16,
    /// Its advertised peer-UDP version.
    pub udp_version: u8,
    /// Its hello's extended-requests claim, which decides how much of a
    /// UDPv4 ping's status is read.
    pub extended_requests: u8,
    /// Its identity for obfuscation, when we hold one.
    pub crypt_target: Option<PeerUdpCryptTarget>,
}

/// How full the upload queue is, for the unknown pinger's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueRoom {
    /// Peers waiting now.
    pub waiting: usize,
    /// The queue's maximum.
    pub max: usize,
}

/// The file a ping names, as we share it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedFile {
    /// Its exact size, which a UDPv4 ping's status is read against.
    pub size: u64,
    /// The parts we hold, in the writer's count (`size / PARTSIZE + 1`); a
    /// status holding every part, or the count-`0` sentinel, goes out as the
    /// count `0` alone.
    pub status: PartBitmap,
}

impl SharedFile {
    /// A file we share whole.
    #[must_use]
    pub fn whole(size: u64) -> Self {
        Self {
            size,
            status: PartBitmap::complete_source_sentinel(),
        }
    }
}

/// The responder's verdict on one ping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaskAnswer {
    /// What goes back on the wire, if anything.
    pub reply: ReaskReply,
    /// What the ping told the queue about the waiter's standing.
    pub standing: Standing,
}

/// What goes back to the pinger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReaskReply {
    /// Send `datagram` back to the ping's source, obfuscated for
    /// `encrypt_for` when the send gate allows it, plaintext when `None`.
    Send {
        /// The plaintext reply.
        datagram: Vec<u8>,
        /// The peer the reply may be obfuscated for.
        encrypt_for: Option<PeerUdpCryptTarget>,
    },
    /// Send nothing, for this reason.
    Silent(Silence),
}

/// Why a ping goes unanswered. Each silence pushes the pinger to a TCP full
/// ask, which repairs whatever the two sides disagree on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Silence {
    /// The waiter is queued for another file.
    OtherFile,
    /// Several waiters share the pinger's IP.
    AmbiguousIp,
    /// An unknown pinger while the queue has room.
    UnknownWithRoom,
    /// The ping is shorter than its sender's version reads: aMule's reader
    /// throws and its dispatcher only logs. Worth counting.
    Malformed,
}

/// What a ping told the queue about the pinger's standing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Standing {
    /// The ping reached no waiter's own file: the queue is untouched.
    Untouched,
    /// A known waiter asked about its own file: its reask clock refreshes.
    Heard,
    /// As [`Heard`](Self::Heard), and the ping restated the waiter's part
    /// status, which the runtime records — `None` clears what it held.
    Restated(Option<PartBitmap>),
}

/// Answer `ping` from `pinger`, given the queue's `room` and the file as we
/// share it (`None` when we do not share the file).
#[must_use]
pub fn answer(
    ping: &ReaskPing<'_>,
    pinger: &Pinger,
    room: QueueRoom,
    shared: Option<&SharedFile>,
) -> ReaskAnswer {
    let Some(shared) = shared else {
        // Resolved before the file, so a waiter we know is answered
        // obfuscated even here; anyone else plaintext.
        let encrypt_for = match pinger {
            Pinger::Known(waiter) => waiter.crypt_target,
            Pinger::Ambiguous | Pinger::Unknown => None,
        };
        return ReaskAnswer::untouched(ReaskReply::Send {
            datagram: file_not_found_datagram(),
            encrypt_for,
        });
    };
    match pinger {
        Pinger::Known(waiter) => answer_waiter(ping, waiter, shared),
        Pinger::Ambiguous => ReaskAnswer::untouched(ReaskReply::Silent(Silence::AmbiguousIp)),
        Pinger::Unknown if room.waiting + QUEUE_FULL_HEADROOM > room.max => {
            // Never obfuscated: there is no identity to key on (aMule: "we
            // cannot answer this one encrypted since we dont know this
            // client").
            ReaskAnswer::untouched(ReaskReply::Send {
                datagram: queue_full_datagram(),
                encrypt_for: None,
            })
        }
        Pinger::Unknown => ReaskAnswer::untouched(ReaskReply::Silent(Silence::UnknownWithRoom)),
    }
}

/// A known waiter's ping for a file we share.
fn answer_waiter(ping: &ReaskPing<'_>, waiter: &KnownWaiter, shared: &SharedFile) -> ReaskAnswer {
    let file_size = shared.size;
    if waiter.waiting_for != ping.file_hash {
        return ReaskAnswer::untouched(ReaskReply::Silent(Silence::OtherFile));
    }
    let silenced = |standing| ReaskAnswer {
        reply: ReaskReply::Silent(Silence::Malformed),
        standing,
    };
    // A UDPv4 waiter's ping restates its own part status, read as its name
    // ask's is (`ClientUDPSocket.cpp:202-203` → `ProcessExtendedInfo`); a ping
    // cut short makes that reader throw after it cleared or partly set the
    // status, which stays recorded.
    let mut standing = Standing::Heard;
    if waiter.udp_version > 3 {
        match read_status(ping.datagram, file_size, waiter.extended_requests) {
            PingStatus::Read(status) => standing = Standing::Restated(status),
            PingStatus::Malformed(status) => return silenced(Standing::Restated(status)),
        }
    }
    // A UDPv3 waiter's ping is read for its complete-source count alone
    // (`:204-205`), which the hash alone does not carry.
    if waiter.udp_version == 3 && !carries_complete_count(ping.datagram) {
        return silenced(standing);
    }
    // Our status rides only to a UDPv4 waiter (`:214-219`): a part file's
    // own, a whole file's as the count `0` alone, the writer shape for a file
    // that is not a part file.
    let part_status = (waiter.udp_version > 3).then(|| {
        if shared.status.is_complete() {
            PartBitmap::complete_source_sentinel()
        } else {
            shared.status.clone()
        }
    });
    ReaskAnswer {
        reply: ReaskReply::Send {
            datagram: ReaskAck {
                part_status,
                rank: waiter.rank,
            }
            .encode_udp(),
            encrypt_for: waiter.crypt_target,
        },
        standing,
    }
}

impl ReaskAnswer {
    const fn untouched(reply: ReaskReply) -> Self {
        Self {
            reply,
            standing: Standing::Untouched,
        }
    }
}

/// The leading 16-byte file hash of a `0x90` datagram, or `None` when the
/// datagram is malformed or the wrong opcode. A reask is routed by hash and
/// UDP source alone: an unknown pinger's UDP version is unknown, so the
/// version-gated tail is not read here.
fn file_hash_of(datagram: &[u8]) -> Option<FileHash> {
    let body = strip_header(datagram, ClientUdpOpcode::ReaskFilePing).ok()?;
    WireReader::new(body).read_file_hash("file hash").ok()
}

/// Whether a UDPv3 waiter's `0x90` holds the complete-source count its
/// reader takes right after the hash, whatever the waiter's
/// extended-requests claim (stock 2.3.3 `4e8f2b3c`
/// `ClientUDPSocket.cpp:204-205`). A ping that is the hash alone makes
/// that read throw, and the dispatcher's catch only logs (`:131-134`):
/// the ping is malformed and goes unanswered. Bytes past the count are
/// ignored.
fn carries_complete_count(datagram: &[u8]) -> bool {
    strip_header(datagram, ClientUdpOpcode::ReaskFilePing)
        .is_ok_and(|body| body.len() >= FileHash::BYTE_LEN + 2)
}

/// What the uploader takes from a UDPv4 waiter's ping for the shared file
/// of `file_size` bytes, read as aMule's `ProcessExtendedInfo` reads it
/// (stock 2.3.3 `4e8f2b3c` `UploadClient.cpp:397-456`, reached from
/// `ClientUDPSocket.cpp:202-203` and the buddy relay's
/// `ClientTCPSocket.cpp:1735-1736`), `extended_requests` being the
/// pinger's hello claim. The bitmap is sized by the **file's** part count,
/// not the wire's; the complete-source count is read only for a claim
/// above `1`; bytes past what the claim reads are ignored.
fn read_status(datagram: &[u8], file_size: u64, extended_requests: u8) -> PingStatus {
    let Some(tail) = strip_header(datagram, ClientUdpOpcode::ReaskFilePing)
        .ok()
        .and_then(|body| body.get(FileHash::BYTE_LEN..))
    else {
        return PingStatus::Malformed(None);
    };
    // A claim of `0` is cleared before anything is read
    // (`UploadClient.cpp:400-406`).
    if extended_requests == 0 {
        return PingStatus::Read(None);
    }
    // The count, the bitmap sized by the file, and a count other than
    // the file's clearing the status are the name ask's reader too
    // (`:408-446`, `read_file_sized_status`).
    match read_file_sized_status(tail, file_size) {
        FileSizedStatus::Cut(status) => PingStatus::Malformed(status),
        FileSizedStatus::Cleared => PingStatus::Read(None),
        // The complete-source count follows a real status for a claim
        // above `1` (`:448-455`); its absence throws after the status is
        // set. Count `0` reads nothing more (`:415-416`).
        FileSizedStatus::Read { status, end }
            if extended_requests > 1 && status.part_count() != 0 && tail.len() < end + 2 =>
        {
            PingStatus::Malformed(Some(status))
        }
        FileSizedStatus::Read { status, .. } => PingStatus::Read(Some(status)),
    }
}

/// What a UDPv4 waiter's `0x90` says of its own parts, as
/// [`read_status`] reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum PingStatus {
    /// Read to the end the claim asks for: the pinger's status in its wire
    /// shape (count `0` is a complete copy's), or `None` where aMule clears it
    /// without reading — a claim of `0`, or a count that is not the file's.
    Read(Option<PartBitmap>),
    /// Cut short where aMule's reader throws: its dispatcher only logs, so
    /// the ping goes unanswered. Carries the status as far as it was read
    /// before the throw, `None` when not even the count arrived.
    Malformed(Option<PartBitmap>),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The uploader's read of a UDPv4 ping, shape by shape, as
    /// aMule's `ProcessExtendedInfo` reads it (stock 2.3.3 `4e8f2b3c`
    /// `UploadClient.cpp:397-456`).
    #[test]
    fn a_pings_status_is_read_by_the_files_part_count_and_the_senders_claim() {
        use rmule_primitives::ED2K_PART_SIZE;

        let ping = |tail: &[u8]| [&[0xC5, 0x90][..], &[0xAB; 16], tail].concat();
        let bitmap = |count, bytes: &[u8]| PartBitmap::decode(count, bytes).unwrap();

        // Twenty parts: a three-byte status, then the complete-source count.
        let size = 19 * ED2K_PART_SIZE + 1;
        let read = |tail: &[u8], claim| read_status(&ping(tail), size, claim);
        let whole = [0x14, 0x00, 0xFF, 0x0F, 0x03, 0x07, 0x00];
        let status = bitmap(20, &[0xFF, 0x0F, 0x03]);
        assert_eq!(read(&whole, 2), PingStatus::Read(Some(status.clone())));
        // Without the count: malformed for a claim of 2, whole for a claim of 1.
        assert_eq!(
            read(&whole[..5], 2),
            PingStatus::Malformed(Some(status.clone()))
        );
        assert_eq!(read(&whole[..5], 1), PingStatus::Read(Some(status)));
        // A status cut short keeps the bits read before the throw.
        assert_eq!(
            read(&whole[..3], 1),
            PingStatus::Malformed(Some(bitmap(20, &[0xFF, 0x00, 0x00]))),
        );
        // The hash alone, or a count cut short: nothing set.
        assert_eq!(read(&[], 1), PingStatus::Malformed(None));
        assert_eq!(read(&whole[..1], 1), PingStatus::Malformed(None));
        // A claim of 0 is never read; a count not the file's clears unread.
        assert_eq!(read(&[], 0), PingStatus::Read(None));
        assert_eq!(read(&[0x13, 0x00], 2), PingStatus::Read(None));
        // Count 0 reads nothing more, not even the complete-source count.
        assert_eq!(
            read(&[0x00, 0x00], 2),
            PingStatus::Read(Some(bitmap(0, &[])))
        );

        // Sixteen whole parts: the wire counts seventeen (a phantom part),
        // but the reader takes the file's two bytes and the count right after.
        let size = 16 * ED2K_PART_SIZE;
        let read = |tail: &[u8]| read_status(&ping(tail), size, 2);
        assert_eq!(
            read(&[0x11, 0x00, 0xFF, 0xFF, 0x05, 0x00]),
            PingStatus::Read(Some(bitmap(17, &[0xFF, 0xFF, 0x00]))),
        );
        assert_eq!(
            read(&[0x11, 0x00, 0xFF, 0xFF, 0x01]),
            PingStatus::Malformed(Some(bitmap(17, &[0xFF, 0xFF, 0x00]))),
        );
    }
}
