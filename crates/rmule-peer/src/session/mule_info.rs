//! The legacy `OP_EMULEINFO` exchange (docs/protocol/parity/peer-tcp.md,
//! *Hello read surface*): read a pre-0.42 mule's block into the connection's
//! software evidence and capabilities, answer it, and send one to an accepted
//! peer that needs it — each exactly where both references do.

use super::{PeerSession, State};
use crate::IdentityChange;
use crate::emule_info::{EmuleInfo, LegacyMuleInfo};

impl PeerSession {
    /// An `OP_EMULEINFO` (`answer` false) or `OP_EMULEINFOANSWER`. The legacy
    /// block is read whole; a block under an unknown protocol byte leaves its
    /// version and clears the compatible client. An `OP_EMULEINFO` is answered with our
    /// block each time it comes unless it is aMule's OS-info block: aMule
    /// answers whenever `ProcessMuleInfoPacket` returns false, an unknown
    /// protocol byte included (`ClientTCPSocket.cpp:1262-1273`,
    /// `BaseClient.cpp:893-895`, `:1006`).
    pub(super) fn on_emule_info(&mut self, answer: bool, info: &EmuleInfo) {
        let (legacy, unknown_version) = match info {
            EmuleInfo::Legacy(legacy) => (Some(legacy), None),
            EmuleInfo::Other { mule_version, .. } => (None, Some(*mule_version)),
            EmuleInfo::OsInfo { .. } => return,
        };
        // Before an accepted peer's `OP_HELLO` there is no client to fold it
        // into; both references end the connection there, rmule keeps it
        // (ADR-0018) and forgets the block, as that hello would clear it.
        if matches!(self.state, State::AwaitingHello | State::BeforeStart) {
            return;
        }
        if !answer {
            // Both references answer every block that is not OS info, to
            // its sender, each time (stock aMule 2.3.3
            // `ClientTCPSocket.cpp:1262-1273`, eMule `ListenSocket.cpp:1133`).
            let ours = LegacyMuleInfo::advertised(&self.advertised_hello_body());
            self.write_packet(ours.encode_packet(true));
        }
        let Some(legacy) = legacy else {
            // aMule records the version, clears the compatible client and
            // the mule flag, and returns before it re-derives the software,
            // lights identification or reads a capability
            // (`BaseClient.cpp:884-895`); the next hello names the peer from
            // what it recorded.
            if let Some(mule_version) = unknown_version {
                self.peer_software.unknown_emule_info(mule_version);
            }
            self.revise_source_exchange();
            return;
        };
        self.peer_software.emule_info(legacy);
        let reask = (legacy.udp_port() != 0)
            .then(|| (legacy.udp_port(), legacy.capabilities().udp_version()));
        if reask.is_some() {
            self.peer_legacy_reask = reask;
        }
        if self.peer_misc_options.is_none() {
            self.peer_misc_options = Some(legacy.capabilities());
        }
        let software = self.peer_software.software();
        self.revise_identity(IdentityChange::Software, |identity| {
            identity.revise_software(software)
        });
        if let Some((udp_port, udp_version)) = reask
            && !self.peer_hello_named_reask
        {
            self.revise_identity(IdentityChange::ReaskContact, |identity| {
                identity.revise_reask_contact(udp_port, udp_version)
            });
        }
        if matches!(self.state, State::Identified) {
            // An old eMule starts Secure User Identification once hello and
            // block have both arrived (its `InfoPacketsReceived`).
            self.maybe_start_secure_ident();
        }
        self.revise_source_exchange();
    }

    /// An identified peer's block may change what it says about source
    /// exchange — a pre-0.42 mule's SX version arrives only here (stock aMule
    /// 2.3.3 `BaseClient.cpp:918-921`, eMule `BaseClient.cpp:804-808`) — so
    /// the download's Source Ask Clock reads what this session's own ask gate
    /// reads (ADR-0108). A block before the hello answer needs no revision:
    /// the identity carries it.
    fn revise_source_exchange(&mut self) {
        let support = self.source_exchange_support();
        self.revise_identity(IdentityChange::SourceExchange, |identity| {
            identity.revise_source_exchange(support)
        });
    }

    /// Before answering an accepted hello: a peer behind eMule's hash mark
    /// whose hello was not a mule hello is a pre-0.42 mule, and both references
    /// send it their block first (aMule `ClientTCPSocket.cpp:347-349`, eMule
    /// `ListenSocket.cpp:274-275`) — the only way it learns what we support.
    pub(super) fn send_emule_info_if_legacy(&mut self) {
        if self.peer_software.wants_emule_info() {
            let ours = LegacyMuleInfo::advertised(&self.advertised_hello_body());
            self.write_packet(ours.encode_packet(false));
        }
    }
}
