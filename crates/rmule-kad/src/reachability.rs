//! Typed codecs for the Kad2 firewall self-check messages (ADR-0058): the
//! `0x50`/`0x53` TCP-check requests a **Routing Responder** answers and the
//! `0x58`/`0x59` responses it sends. The responder side decodes the two
//! requests and encodes the two responses; the **requester cycle**
//! ([`FirewallSelfCheck`]) emits `0x50`/`0x53` and
//! consumes `0x58`/`0x59` (and, via core, the `OP_KAD_FWTCPCHECK_ACK` TCP ack).
//! The single-envelope codec models all four directions so its round-trips are
//! provable and the requester reuses the emit direction unchanged.
//!
//! ## Provenance
//!
//! Opcode bytes are the canonical eMule Kad constants
//! (`src/include/protocol/kad/Constants.h`); the request layouts and their
//! exact-2 / min-19 size gates are the aMule listener's
//! (`KademliaUDPListener.cpp`, cited in ADR-0058). The `0x58` response body is
//! the observed requester IP as a `WriteUInt32` — written **low-octet-first**
//! (reversed dotted octets), the same convention rmule's Kad contact codec uses
//! (`messages.rs` `read_ipv4_low_octet_first`). Capture-pinned by the requester
//! leg: aMule's genuine `0x58` for `203.0.113.3` is `03 71 00 cb`
//! (`fixtures/firewalled/captured/amule-233-firewall-selfcheck-requester`). The
//! `0x62` result body (`<errorcode 1><port 2 LE>`) and the peer-TCP
//! `OP_FWCHECKUDPREQ` request (`<intern 2><extern 2><key 4>`, all LE) are the
//! aMule `Process2FirewallUDP` / `SendFirewallCheckUDPRequest` reads/writes —
//! little-endian, since `ENDIAN_SWAP_16` is a no-op on the LE wire.
//!
//! ## aMule divergences (ADR-0058, reported per ADR-0045)
//!
//! - **UDP intern-port retro-correction**: ADR-0058 specifies the tester prefers
//!   the intern port "even retroactively within 10 s". aMule 2.3.3 codes the
//!   check (`UDPFirewallTester.cpp#L95`) but never stamps `m_lastSucceededTime`
//!   on success, so its `+10 s` window is always past and the correction is
//!   **dead code**. rmule stamps the success time
//!   ([`UdpFirewallTester::accept_result`]) so the correction works as the ADR
//!   intends — a deliberate divergence from the shipping binary.
//! - **UDP six-minute timeout gate**: aMule concludes firewalled-by-timeout only
//!   when the **TCP** verdict is also firewalled and UDP was never verified open
//!   (`CKademlia::IsFirewalled() && !m_isFWVerifiedUDP`); ADR-0058's prose names
//!   only the 6-minute silence. rmule keeps aMule's full gate
//!   ([`UdpFirewallTester::check_timeout`]) — the one place the two self-checks
//!   compose.

mod message;
mod tcp_check;
mod udp_test;

pub use self::message::FirewallDecodeError;
pub(crate) use self::message::{
    FirewallMessage, FirewallUdpResult, FwCheckUdpRequest, KADEMLIA_FIREWALLED_REQ,
    KADEMLIA_FIREWALLED2_REQ, KADEMLIA2_FIREWALLUDP, is_firewall_check_req, is_firewall_check_res,
};
pub(crate) use self::tcp_check::{
    CHECK_WINDOW, FIREWALL_CHECKS, FirewallResponseOutcome, FirewallSelfCheck, RECHECK_INTERVAL,
};
pub(crate) use self::udp_test::{
    PongOutcome, UDP_TEST_TIMEOUT, UdpFirewallTester, UdpHelperResult, UdpResultOutcome, UdpVerdict,
};
