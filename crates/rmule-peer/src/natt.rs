//! eMuleAI's **NAT-T transport envelope** (`OP_UDPRESERVEDPROT2`, `0xB2`) —
//! the sans-I/O half of ADR-0091's transport: the frame codec, the
//! connect-options view the CAPS frames carry, the QUIC application proof, and
//! the per-endpoint **CAPS Negotiation** state machine.
//!
//! The envelope is deliberately opcode-free. Every other UDP surface rmule
//! speaks is `[protocol][opcode][payload]`; `0xB2` is
//! `[0xB2][frame type][payload]` and the frame type is a namespace of its own
//! (5 of 256 used). That is the whole reason NAT-T can share the advertised
//! client-UDP port: `0xB2` has been reserved — and passed through unparsed —
//! by every eMule-family client since 2007, so a legacy peer drops a NAT-T
//! frame instead of misreading it.
//!
//! What lives here is the wire and the clock-driven state; the sockets, the
//! uTP/QUIC engines and the `Tunnel` are `rmule_net::natt`'s (ADR-0081: no
//! protocol knowledge in the runtime crate, no socket in the protocol crate).
//! The `0xC5` signalling that gets two peers *to* a transport —
//! `OP_RENDEZVOUS`, `OP_HOLEPUNCH`, `OP_NATT_ENDPOINT_HINT` — is the
//! `rendezvous` submodule's.
//!
//! # Obfuscation
//!
//! `0xB2` is on the **never-obfuscated whitelist** (ADR-0046's amendment for
//! this ADR): a datagram whose first byte is literally `0xB2` bypasses the
//! dual-path decrypt untouched, in every eMule-family client read
//! (byte-identical across aMule master, aMule 3.0.1, eMule 0.70b, eMule 0.72a
//! and eMuleAI). That is a statement about the *plaintext form*, not a ban: a
//! NAT-T transport frame **is** obfuscated once a key for the endpoint is
//! known, and then its first byte is the random crypt marker, never `0xB2`.
//! The key arrives in the [`NattFrame::Key`] frame. See
//! [`rmule_net::natt`](../../rmule_net/natt/index.html) for the TTLs.

mod caps;
mod frame;
mod negotiation;
mod prediction;
mod proof;
mod punch;
mod rendezvous;
mod schedule;

/// `bytes` as uppercase hex digits, two per byte.
fn hex_digits(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

pub use caps::{
    CAPS_FRAME_LEN, CAPS_MAGIC, CAPS_VERSION, CapsDecodeError, CapsFrame, NattConnectOptions,
    NattTransport,
};
pub use frame::{
    NATT_PROTOCOL, NattFrame, NattFrameDecodeError, NattFrameType, frame_transport, natt_frame_type,
};
pub use negotiation::{
    CAPS_LEGACY_TIMEOUT, CapsNegotiation, HelloNattClaim, QUIC_FAILURE_TTL, TransportVerdict,
};
pub use prediction::{
    OwnMapping, PREDICTION_ATTEMPT_INTERVAL, PREDICTION_ATTEMPTS, PREDICTION_FAN_SOCKETS,
    PREDICTION_LINGER, PREDICTION_PACE, PREDICTION_PROBES, PROBE_DELAY, PROBE_PORTS, PeerMapping,
    PortPrediction, PredictionPlan, PredictionRng, PredictionRole, PredictionStep, prediction_role,
    probe_ports,
};
pub use proof::{QUIC_PROOF_LEN, QUIC_PROOF_MAGIC, QuicProof, QuicProofError, QuicProofVerdict};
pub use punch::{
    PUNCH_BURST, PUNCH_SWEEP, PunchTarget, PunchTargetSource, burst_delay, is_public_punch_address,
    punch_burst, resolve_punch_target,
};
pub use rendezvous::{
    ENDPOINT_HINT_LEN, ENDPOINT_HINT_VERSION, EndpointHint, RendezvousBody, RendezvousDecodeError,
    holepunch_datagram, is_holepunch,
};
pub use schedule::{
    CALLBACK_SILENCE_FALLBACK, PUNCHED_PATH_KEEPALIVE, PunchJitter, RENDEZVOUS_BACKOFF,
    RENDEZVOUS_MAX_ATTEMPTS, RENDEZVOUS_TIMEOUT, RendezvousFailure, RendezvousSchedule,
    RendezvousStep, RendezvousTrigger, RetireReason,
};
