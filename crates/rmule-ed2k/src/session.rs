//! The sans-I/O state machine for one eD2k server session.
//!
//! Owns no socket, no clock and no runtime: bytes in through `handle_bytes`,
//! service requests in through `handle_command`, effects out through
//! `poll_output`. The thin Tokio driver in `rmule-net` is the only place that
//! turns those effects into I/O (ADR-0081, ADR-0021).

use std::sync::Arc;

use rmule_primitives::{
    Capabilities, ClientId, ClientIdentity, CryptStance, Packet, PrimitiveError, SearchQuery,
    ServerEndpoint, SessionCore, SessionOutput, pack_if_smaller,
};

use crate::{
    CallbackRequest, CloseReason, CommandRejectReason, Ed2kCommand, Ed2kCommandKind, Ed2kError,
    Ed2kEvent, GetServerList, GetSourcesRequest, HolepunchRequest, LoginAdvert, LoginRequest,
    OfferFiles, QueryMoreResults, RelatedSearchRequest, SearchRequest, ServerAssignedFacts,
    ServerCapability, ServerGrants, ServerPacket, UdpPortsAdvert,
    server_packet::DecodedServerFrame,
};

/// Pure state machine for one eD2k server session.
///
/// Owns no socket, no clock, no runtime. Bytes go in through
/// [`handle_bytes`](Self::handle_bytes); service-layer requests through
/// [`handle_command`](Self::handle_command); effects come out through
/// [`poll_output`](Self::poll_output) as [`Output`] values. The thin Tokio
/// driver in `rmule-net` is the only place that turns those effects
/// into I/O.
pub struct Ed2kSession {
    endpoint: ServerEndpoint,
    identity: ClientIdentity,
    capabilities: Capabilities,
    state: State,
    client_id: Option<ClientId>,
    /// The server's `SRV_TCPFLG` grants, projected at `OP_IDCHANGE`
    /// (ADR-0047): every gated command path reads its own field. Default
    /// (nothing granted) before login or after a bare 4-byte reply.
    grants: ServerGrants,
    /// The IDCHANGE-extension projection (ADR-0047): public IP, standard
    /// port, obfuscation port. Re-projected whole on every IDCHANGE.
    facts: ServerAssignedFacts,
    /// Our Known IPv6 for the login's `CT_MOD_IP_V6` tag and its coupled
    /// `SRVCAP_IPV6` flag bit (ADR-0087 §4.1), set via
    /// [`with_ipv6_advertisement`](Self::with_ipv6_advertisement). `None`
    /// sends neither.
    ipv6_advert: Option<std::net::Ipv6Addr>,
    /// The login's `0xF9` tag (ADR-0091), set by
    /// [`with_udp_ports_advertisement`](Self::with_udp_ports_advertisement).
    /// `None` — the default — sends none, which tells an ed2k-server this
    /// client cannot be punched.
    udp_ports_advert: Option<UdpPortsAdvert>,
    core: SessionCore<Ed2kEvent, CloseReason>,
}

#[derive(Debug)]
enum State {
    BeforeStart,
    AwaitingIdChange,
    LoggedIn,
    Closed,
}

/// One effect drained from an [`Ed2kSession`]: the shared
/// [`SessionOutput`] spine over the eD2k event and close-reason
/// vocabularies (ADR-0044).
pub type Output = SessionOutput<Ed2kEvent, CloseReason>;

/// Protocol-layer fault detected by the session.
///
/// `Frame` wraps a `PrimitiveError` from the eD2k framing layer
/// (`Packet::decode`); `Packet` wraps an `Ed2kError` from the typed
/// payload decoder (`ServerPacket::decode`). Neither is recoverable
/// inside the session — they always close it.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionError {
    /// The bytes did not form a frame.
    #[error("frame decode: {0}")]
    Frame(
        /// The framing failure.
        #[from]
        PrimitiveError,
    ),
    /// The frame decoded but its payload did not.
    #[error("packet decode: {0}")]
    Packet(
        /// The payload failure.
        #[from]
        Ed2kError,
    ),
}

// "Packet before login" is not a structural sequence violation (ADR-0047): a
// live capture shows real lugdunum servers push `OP_SERVERMESSAGE` ahead of
// `OP_IDCHANGE`, and aMule (`ServerSocket.cpp:120-318`) enforces no
// welcome-burst ordering. A second `OP_IDCHANGE` is mid-session
// re-assignment in aMule (LowID↔HighID transitions re-run the whole
// handler), so the session re-projects and re-emits instead of closing.

impl Ed2kSession {
    /// A session that has not started: nothing sent, no id assigned, the
    /// shipped capability set, and crypt disabled until configured.
    #[must_use]
    pub fn new(endpoint: ServerEndpoint, identity: ClientIdentity) -> Self {
        Self {
            endpoint,
            identity,
            capabilities: Capabilities::shipped(CryptStance::disabled()),
            state: State::BeforeStart,
            client_id: None,
            grants: ServerGrants::default(),
            facts: ServerAssignedFacts::default(),
            ipv6_advert: None,
            udp_ports_advert: None,
            core: SessionCore::new(),
        }
    }

    /// Advertise our Known IPv6 at login — the `CT_MOD_IP_V6` tag and the
    /// `SRVCAP_IPV6` flag together (ADR-0087 §4.1).
    ///
    /// The runtime layer passes what the Advertised Endpoints chooser settled
    /// (ADR-0084: Known *and* not probed-unreachable), the same value the peer
    /// hello's tag rides, so the two surfaces can never name different
    /// addresses. Omitting the call sends neither signal — and the spec's own
    /// consequence follows: a client that can parse IPv6 sources but holds no
    /// confident address of its own has no channel to say so, and receives
    /// none.
    #[must_use]
    pub const fn with_ipv6_advertisement(mut self, address: std::net::Ipv6Addr) -> Self {
        self.ipv6_advert = Some(address);
        self
    }

    /// Advertise our UDP ports at login — ed2k-server's `CT_EMULE_UDPPORTS`
    /// (`0xF9`), which is also how a client says it can be punched
    /// (ADR-0091). The runtime layer calls this only while a client-UDP
    /// socket is bound; omitting it sends no tag, and an ed2k-server then
    /// refuses to introduce anyone to us.
    #[must_use]
    pub const fn with_udp_ports_advertisement(mut self, ports: UdpPortsAdvert) -> Self {
        self.udp_ports_advert = Some(ports);
        self
    }

    /// The IDCHANGE-extension facts the server last asserted (ADR-0047):
    /// default (nothing asserted) before login; re-projected whole on every
    /// IDCHANGE, including a mid-session re-assignment. Consumers: direct
    /// callback / Kad firewall self-check / buddy read the public IP, the
    /// ADR-0042 crypt dial reads the obfuscation port with its grant.
    #[must_use]
    pub fn server_facts(&self) -> ServerAssignedFacts {
        self.facts
    }

    /// Override the capability registry this session advertises at login
    /// (ADR-0047) — the runtime layer injects the crypt stance derived
    /// from its obfuscation policy. Default is the shipped set with
    /// crypt disabled.
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: Capabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// The server endpoint this session is bound to. Available to the
    /// runtime layer for logging and capture metadata.
    #[must_use]
    pub fn endpoint(&self) -> &ServerEndpoint {
        &self.endpoint
    }

    /// The client identity this session presents in `LoginRequest`.
    /// Available to the runtime layer for capture metadata.
    #[must_use]
    pub fn identity(&self) -> &ClientIdentity {
        &self.identity
    }

    /// Open the session: emit `LoginRequested` and the encoded
    /// `LoginRequest` write. Transitions `BeforeStart` -> `AwaitingIdChange`.
    /// No-op if called from any other state.
    pub fn start(&mut self) {
        if !matches!(self.state, State::BeforeStart) {
            return;
        }
        self.core.push_event(Ed2kEvent::LoginRequested {
            endpoint: self.endpoint.clone(),
        });
        let bytes = LoginRequest::from_identity_advertising(
            &self.identity,
            &self.capabilities,
            LoginAdvert {
                ipv6: self.ipv6_advert,
                udp_ports: self.udp_ports_advert,
            },
        )
        .encode_packet()
        .encode();
        self.core.push_write(Arc::from(bytes));
        self.state = State::AwaitingIdChange;
    }

    /// Driver-facing signal that the login-response deadline elapsed.
    /// Mirrors the sans-I/O pattern (ADR-0021) and
    /// `PeerSession::hello_deadline_elapsed`: the session owns no clock;
    /// the runtime calls this when its login timeout fires. Closes with
    /// `LoginTimeout` only while login is still pending
    /// (`AwaitingIdChange`); a no-op once login has resolved. `close`
    /// queues the paired `Disconnected` + `Close(LoginTimeout)`, the same
    /// terminal sequence as every other close path.
    pub fn login_deadline_elapsed(&mut self) {
        if matches!(self.state, State::AwaitingIdChange) {
            self.close(CloseReason::LoginTimeout);
        }
    }

    /// Append bytes from the socket, extract complete frames, and dispatch
    /// them. Silently no-ops after the session has closed. The buffer loop
    /// lives in [`SessionCore::feed`]; a frame that fails to decode closes
    /// the session carrying the decode error.
    pub fn handle_bytes(&mut self, bytes: &[u8]) {
        SessionCore::feed(
            self,
            |session| &mut session.core,
            bytes,
            Self::dispatch_packet,
            |session, error| {
                session.close(CloseReason::ProtocolViolation(SessionError::Frame(error)));
            },
        );
    }

    /// Apply a service-layer command.
    pub fn handle_command(&mut self, command: Ed2kCommand) {
        if matches!(self.state, State::Closed) {
            return;
        }
        match command {
            Ed2kCommand::RequestServerList => {
                if !matches!(self.state, State::LoggedIn) {
                    self.reject_command(
                        Ed2kCommandKind::RequestServerList,
                        CommandRejectReason::NotLoggedIn,
                    );
                    return;
                }
                let bytes = GetServerList.encode_packet().encode();
                self.core.push_write(Arc::from(bytes));
            }
            Ed2kCommand::QueryMoreResults => {
                if !matches!(self.state, State::LoggedIn) {
                    self.reject_command(
                        Ed2kCommandKind::QueryMoreResults,
                        CommandRejectReason::NotLoggedIn,
                    );
                    return;
                }
                let bytes = QueryMoreResults.encode_packet().encode();
                self.core.push_write(Arc::from(bytes));
            }
            Ed2kCommand::Search { query } => {
                if !matches!(self.state, State::LoggedIn) {
                    self.reject_command(Ed2kCommandKind::Search, CommandRejectReason::NotLoggedIn);
                    return;
                }
                // A size bound past `u32::MAX` only widens to a `0x08` term
                // when this server advertised `SRV_TCPFLG_LARGEFILES` in its
                // `OP_IDCHANGE`; otherwise it clamps (aMule's `supports64bit`,
                // `SearchList.cpp:340`). Unlike `RequestSources`, an oversized
                // bound is never a rejection — a clamped query is still a
                // faithful, answerable search, just a wider one.
                let packet = match query {
                    SearchQuery::Keywords(query) => SearchRequest::from_query(query)
                        .with_large_file_support(self.grants.large_files)
                        .encode_packet(),
                    SearchQuery::RelatedFiles(query) => {
                        if !self.grants.related_search {
                            self.reject_command(
                                Ed2kCommandKind::Search,
                                CommandRejectReason::UnsupportedServerCapability {
                                    capability: ServerCapability::RelatedSearch,
                                },
                            );
                            return;
                        }
                        RelatedSearchRequest::from_query(&query).encode_packet()
                    }
                };
                let bytes = packet.encode();
                self.core.push_write(Arc::from(bytes));
            }
            Ed2kCommand::RequestSources { target } => {
                if !matches!(self.state, State::LoggedIn) {
                    self.reject_command(
                        Ed2kCommandKind::RequestSources,
                        CommandRejectReason::NotLoggedIn,
                    );
                    return;
                }
                let request = if target.file_size() <= u64::from(u32::MAX) {
                    GetSourcesRequest::Normal { target }
                } else if self.grants.large_files {
                    GetSourcesRequest::Large { target }
                } else {
                    self.reject_command(
                        Ed2kCommandKind::RequestSources,
                        CommandRejectReason::UnsupportedServerCapability {
                            capability: ServerCapability::LargeFiles,
                        },
                    );
                    return;
                };
                // Ask for obfuscation-aware sources (`0x23` → the server answers
                // `0x44` with per-source crypt options + optional User Hash) only
                // when the server advertises TCP obfuscation *and* rmule's crypt
                // stance can use it — aMule's `SRV_TCPFLG_TCPOBFUSCATION &&
                // IsClientCryptLayerSupported()` gate (ADR-0046). Otherwise the
                // plaintext `0x19` request, whose `0x42` reply carries no hash.
                let packet = if self.grants.tcp_obfuscation && self.capabilities.crypt().supports()
                {
                    request.encode_obfu_packet()
                } else {
                    request.encode_packet()
                };
                self.core.push_write(Arc::from(packet.encode()));
            }
            Ed2kCommand::RequestCallback { low_id } => {
                if !matches!(self.state, State::LoggedIn) {
                    self.reject_command(
                        Ed2kCommandKind::RequestCallback,
                        CommandRejectReason::NotLoggedIn,
                    );
                    return;
                }
                let bytes = CallbackRequest::new(low_id).encode_packet().encode();
                self.core.push_write(Arc::from(bytes));
            }
            Ed2kCommand::RequestHolepunch {
                target,
                our_udp_port,
            } => {
                if !matches!(self.state, State::LoggedIn) {
                    self.reject_command(
                        Ed2kCommandKind::RequestHolepunch,
                        CommandRejectReason::NotLoggedIn,
                    );
                    return;
                }
                let bytes = HolepunchRequest {
                    target,
                    our_udp_port,
                }
                .encode_packet()
                .encode();
                self.core.push_write(Arc::from(bytes));
            }
            Ed2kCommand::OfferFiles { files } => {
                if !matches!(self.state, State::LoggedIn) {
                    self.reject_command(
                        Ed2kCommandKind::OfferFiles,
                        CommandRejectReason::NotLoggedIn,
                    );
                    return;
                }
                let needs_large_files = files.iter().any(|f| f.file_size() > u64::from(u32::MAX));
                if needs_large_files && !self.grants.large_files {
                    self.reject_command(
                        Ed2kCommandKind::OfferFiles,
                        CommandRejectReason::UnsupportedServerCapability {
                            capability: ServerCapability::LargeFiles,
                        },
                    );
                    return;
                }
                let client_id = self
                    .client_id
                    .expect("client_id is set at OP_IDCHANGE before reaching LoggedIn");
                let packet = OfferFiles::announce(client_id, self.identity.tcp_port(), &files)
                    .encode_packet();
                let packet = if self.grants.compression {
                    pack_if_smaller(packet)
                } else {
                    packet
                };
                let bytes = packet.encode();
                self.core.push_write(Arc::from(bytes));
            }
            Ed2kCommand::Disconnect => {
                self.close(CloseReason::Local);
            }
        }
    }

    fn reject_command(&mut self, command: Ed2kCommandKind, reason: CommandRejectReason) {
        self.core
            .push_event(Ed2kEvent::CommandRejected { command, reason });
    }

    /// Drain the next queued effect. Returns `None` when nothing pending.
    pub fn poll_output(&mut self) -> Option<Output> {
        self.core.poll_output()
    }

    fn dispatch_packet(&mut self, packet: Packet) {
        match ServerPacket::decode_frame(&packet) {
            Ok(DecodedServerFrame::Packet(server_packet)) => {
                self.dispatch_server_packet(server_packet);
            }
            Ok(DecodedServerFrame::CompressedFrameSkipped {
                opcode,
                compressed_len,
                reason,
            }) => {
                self.core.push_event(Ed2kEvent::CompressedFrameSkipped {
                    opcode,
                    compressed_len,
                    reason,
                });
            }
            Ok(DecodedServerFrame::SearchResultSkipped { reason }) => {
                self.core
                    .push_event(Ed2kEvent::SearchResultSkipped { reason });
            }
            Err(error) => {
                self.close(CloseReason::ProtocolViolation(SessionError::Packet(error)));
            }
        }
    }

    fn dispatch_server_packet(&mut self, server_packet: ServerPacket) {
        if matches!(self.state, State::BeforeStart | State::Closed) {
            return;
        }
        if let ServerPacket::IdChange(id) = &server_packet {
            // Re-assignment semantics (ADR-0047, aMule `ServerSocket.cpp`):
            // every OP_IDCHANGE re-runs the whole handler — grants and facts
            // re-project, the id re-applies, the event re-emits
            // (LowID↔HighID mid-session transitions are legitimate). A zero
            // id is aMule's smart-id bookkeeping case: flags and ports still
            // apply, but the id does not and no connected transition (or
            // event) follows.
            self.grants = id.tcp_flags.map(ServerGrants::from).unwrap_or_default();
            self.facts = ServerAssignedFacts::project(id);
            if id.client_id.as_u32() == 0 {
                return;
            }
            self.state = State::LoggedIn;
            self.client_id = Some(id.client_id);
            let event = Ed2kEvent::from_server_packet(&server_packet);
            self.core.push_event(event);
            return;
        }
        if matches!(server_packet, ServerPacket::Reject(_)) {
            // Server-side explicit refusal. Emit the LoginRejected event
            // so consumers see the typed signal, then close immediately —
            // the runtime note documents that aMule treats OP_REJECT as
            // terminal (server FINs next). A non-typed `ServerClosed`
            // here would lose the "explicitly refused vs. socket dropped"
            // distinction that consumers need for retry decisions.
            let event = Ed2kEvent::from_server_packet(&server_packet);
            self.core.push_event(event);
            self.close(CloseReason::LoginRejected);
            return;
        }
        let event = Ed2kEvent::from_server_packet(&server_packet);
        self.core.push_event(event);
    }

    /// Close with `reason`: [`SessionCore::close`] owns the paired
    /// `Disconnected`-then-`Close` discipline; this wrapper locks the
    /// protocol state machine into `Closed`. `CloseReason` derives `Clone`
    /// and stores only an `io::ErrorKind` (never an `io::Error`), so the
    /// reason rides on both outputs cheaply.
    fn close(&mut self, reason: CloseReason) {
        self.state = State::Closed;
        self.core.close(
            Ed2kEvent::Disconnected {
                reason: reason.clone(),
            },
            reason,
        );
    }
}
