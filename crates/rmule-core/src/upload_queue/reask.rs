//! Who an inbound reask's UDP source is on the wait list (ADR-0057): the
//! attribution the serve side answers a `0x90` by, and the heartbeat a matched
//! one refreshes.

use std::time::Instant;

use rmule_primitives::PeerEndpoint;

use super::{Queued, ReaskResolution, UploadSlotQueue};

impl UploadSlotQueue {
    /// Resolve an inbound reask's UDP source against the wait list, aMule
    /// `GetWaitingClientByIP_UDP` (ADR-0057): an exact IP + UDP port match, the
    /// unique-IP fallback (port ignored when exactly one waiter shares the IP),
    /// the multiple-same-IP ambiguity, or an unknown pinger. Read-only — the
    /// caller refreshes the heartbeat via [`refresh_reask`](Self::refresh_reask)
    /// once the hash is confirmed.
    ///
    /// `0x90`/`0x91` are byte-identical over IPv6, so the reask needs no new
    /// opcode — but the attribution does need the whole address. Matching a
    /// 32-bit projection of a 128-bit sender would let two peers inside one
    /// `/64` answer for each other's queue slot, which is why the comparison
    /// is on [`PeerEndpoint::ip`] and the parameter is family-generic
    /// (ADR-0087).
    #[must_use]
    pub fn resolve_reask(&self, udp_src: PeerEndpoint) -> ReaskResolution {
        let ip = udp_src.ip();
        let port = udp_src.port();
        if let Some(entry) = self
            .waiting
            .iter()
            .find(|q| q.peer.ip() == ip && q.udp_port == Some(port))
        {
            return entry.as_known();
        }
        let mut from_ip = self.waiting.iter().filter(|q| q.peer.ip() == ip);
        match (from_ip.next(), from_ip.next()) {
            (Some(entry), None) => return entry.as_known(),
            (Some(_), Some(_)) => return ReaskResolution::AmbiguousIp,
            _ => {}
        }
        // No live waiter from this IP: a peer we promoted to a **pending
        // dial-back grant** (a disconnected top-waiter, ADR-0057) is still
        // queued at the head from its own view — the dial-back has not yet
        // reached it. aMule keeps such a client reask-answerable, so its reask
        // confirms it is alive and earns an `OP_REASKACK` at the head rather
        // than a silent drop. Matched by IP alone — a granted slot does not retain the
        // advertised UDP port — but its promoted `udp_version` rides along so a
        // v4 grantee's ack carries the part status its parser requires.
        self.granted
            .iter()
            .find(|g| g.dial_back_since.is_some() && g.peer.ip() == ip)
            .map_or(ReaskResolution::Unknown, |slot| ReaskResolution::Known {
                peer: slot.peer,
                file_hash: slot.file_hash,
                rank: 1,
                udp_version: slot.udp_version,
            })
    }

    /// The waiter a ping from `udp_src`, which [`resolve_reask`](Self::resolve_reask)
    /// did not know, comes from when the hello of its standing link names
    /// that address, as `names` reads it: on the client-UDP port the waiter
    /// advertised, and never between two IPv4 addresses (ADR-0107, "One client
    /// on two addresses").
    #[must_use]
    pub fn resolve_named_reask(
        &self,
        udp_src: PeerEndpoint,
        names: impl Fn(PeerEndpoint) -> bool,
    ) -> ReaskResolution {
        self.waiting
            .iter()
            .find(|q| {
                q.udp_port == Some(udp_src.port())
                    && !matches!(
                        (q.peer, udp_src),
                        (PeerEndpoint::V4(_), PeerEndpoint::V4(_))
                    )
                    && names(q.peer)
            })
            .map_or(ReaskResolution::Unknown, Queued::as_known)
    }

    /// Refresh `peer`'s reask heartbeat to `now` — a matched `OP_REASKFILEPING`
    /// keeps its standing alive against the purge clock (ADR-0057).
    pub fn refresh_reask(&mut self, peer: PeerEndpoint, now: Instant) {
        if let Some(entry) = self.waiting.iter_mut().find(|q| q.peer == peer) {
            entry.last_reask = now;
        }
    }
}

impl Queued {
    fn as_known(&self) -> ReaskResolution {
        ReaskResolution::Known {
            peer: self.peer,
            file_hash: self.file_hash,
            rank: self.last_reported_rank,
            udp_version: self.udp_version,
        }
    }
}
