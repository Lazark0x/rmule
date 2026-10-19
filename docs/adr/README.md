# Architecture decision records

Each file here is a decision in force, numbered in the order it was taken. A changed
decision is edited in place and a dropped one is deleted, so no file carries a status.
Every ADR follows one template: Context, Decision, Consequences, and Considered options
where a rejected alternative would otherwise come back.

| ADR | Decision |
| --- | --- |
| [0001](0001-protocol-behaviour-in-reusable-libraries.md) | Protocol behaviour lives in reusable libraries; front-ends only consume them |
| [0002](0002-compatibility-gated-dependency-reuse.md) | Reuse general crates freely; accept protocol-specific crates only on compatibility evidence |
| [0003](0003-amule-behaviour-is-compatibility-truth.md) | Compatibility truth is aMule's behaviour, read through the references and proven by fixtures |
| [0004](0004-gpl-3-or-later-and-no-ported-source.md) | rmule is GPL-3.0-or-later and never ports eMule or aMule source code |
| [0005](0005-cargo-workspace-of-small-protocol-crates.md) | One Cargo workspace of small protocol crates and thin application crates |
| [0006](0006-hand-written-byte-codecs.md) | Explicit hand-written byte codecs for eMule wire formats |
| [0007](0007-runtime-free-protocol-crates.md) | Protocol crates stay runtime-free; Tokio drives networking, orchestration and apps |
| [0008](0008-lenient-links-strict-packets.md) | Lenient eD2k links, strict packets |
| [0009](0009-synthetic-human-readable-and-binary-fixtures.md) | Protocol fixtures are human-readable plus binary, and their content is synthetic |
| [0010](0010-typed-library-errors-anyhow-at-edges.md) | Library crates return typed errors; anyhow only at tool and CLI edges |
| [0011](0011-layered-command-event-stack.md) | A layered protocol stack: commands flow down, events flow up |
| [0012](0012-ed2k-hash-crate-behind-rmule-types.md) | The `ed2k` hash crate is used behind rmule-owned hash types |
| [0013](0013-pinned-local-reference-cache.md) | Upstream source is never committed; protocol references are cached locally from pinned sources |
| [0014](0014-emule-part-boundary-file-hash.md) | The canonical eD2k file hash uses eMule's exact-part-size boundary |
| [0015](0015-per-topic-protocol-notes.md) | rmule-authored protocol notes are organised one file per protocol topic |
| [0016](0016-wire-ipv4-endpoint-apart-from-server-endpoint.md) | Wire IPv4 endpoints are a type of their own, apart from host-or-IP server endpoints |
| [0017](0017-three-orthogonal-server-primitives.md) | A server is three separate primitives: where it is, who it is, and how busy it is |
| [0018](0018-preserve-unknown-well-formed-packets.md) | Preserve unknown well-formed tags and packets; reject only malformed bytes |
| [0019](0019-wire-faithful-ed2k-text.md) | eD2k text is kept as its original bytes in an `Ed2kText` primitive |
| [0020](0020-commands-describe-intent-not-packets.md) | Commands describe intent, not packets |
| [0021](0021-sans-io-ed2k-session-with-connection-handle.md) | Sans-I/O Ed2kSession with Connection handle |
| [0022](0022-capture-is-a-first-class-library-feature.md) | Capture is a first-class library feature |
| [0023](0023-typed-close-reason.md) | Typed CloseReason replaces String |
| [0024](0024-peer-capture-defaults-to-protocol-only.md) | Peer capture defaults to ProtocolOnly |
| [0025](0025-reusable-fully-interleaved-peer-session.md) | PeerSession is reusable and fully interleaved with a single active slot |
| [0026](0026-core-owned-download-orchestration.md) | Core owns download orchestration: per-peer connections, multi-peer scheduling, verification and storage |
| [0027](0027-tracing-as-third-diagnostic-channel.md) | Tracing as a third diagnostic channel |
| [0028](0028-worker-phase-diagnostics-snapshot.md) | Worker phase and diagnostics snapshot for hang investigation |
| [0029](0029-block-level-cross-peer-part-assembly.md) | Block-level cross-peer part assembly with a core-owned prefix buffer |
| [0030](0030-candidate-source-pool-with-worker-backfill.md) | Candidate-source pool with worker backfill and event-driven peer identification |
| [0031](0031-bidirectional-peer-session-and-inbound-listener.md) | Bidirectional peer session with core-owned upload scheduling and an inbound listener |
| [0032](0032-persistent-multiplexed-server-session.md) | Persistent, multiplexed eD2k server session shared by source-lookup and serve |
| [0033](0033-local-interop-harness-with-real-counterparties.md) | Local interop harness uses real server, aMule, and rmule CLI |
| [0034](0034-core-owned-search.md) | Core-owned search: searches run side by side, each leg on its own, and a row belongs to every search it answers |
| [0035](0035-search-spacing-on-one-server-link.md) | Search requests on one server link go at least two seconds apart |
| [0036](0036-more-results.md) | More results: only the operator asks, and only the newest search on the link pages |
| [0037](0037-related-files-search.md) | The Related-Files Search is its own query kind, on the connected server only |
| [0038](0038-aich-block-recovery-with-trusted-set-root.md) | AICH block-level recovery with a trusted-set root |
| [0039](0039-low-id-callback-download-via-adopted-worker.md) | Low-ID callback download via an adopted inbound worker |
| [0040](0040-deterministic-correctness-tier.md) | Deterministic correctness tier: in-process fake counterparties in rmule-testkit |
| [0041](0041-secure-user-identification-and-credit.md) | Secure User Identification and credit, honoring eMule's weak key |
| [0042](0042-rc4-crypt-layer-below-the-packet-codec.md) | Protocol obfuscation is an RC4 crypt layer, wrapped generically below the packet codec |
| [0043](0043-kad-full-node-for-source-discovery.md) | Kad is a full Kad2 node for source discovery, with rmule as its own evidence stimulus |
| [0044](0044-shared-sans-io-session-spine.md) | A shared sans-I/O session spine in rmule-primitives owns the paired-Disconnected close |
| [0045](0045-evidence-standard-per-parity-disposition.md) | A parity gap closes on the evidence its disposition demands |
| [0046](0046-per-datagram-udp-obfuscation-layer.md) | One per-datagram obfuscation layer serves peer, Kad and server UDP under one policy |
| [0047](0047-honest-capability-advertisement.md) | Honest Capability Advertisement from one registry |
| [0048](0048-one-identity-per-node.md) | One identity per node, owned by the core |
| [0049](0049-one-crypt-rule-for-outbound-peer-dials.md) | One crypt rule decides every outbound peer dial, with no plaintext retry |
| [0050](0050-hello-tag-count-refusal.md) | A hello that miscounts its tags is refused by name |
| [0051](0051-server-udp-engine-for-global-sources-and-search.md) | One server-UDP engine serves global sources and global search |
| [0052](0052-server-status-chain-and-capability-store.md) | A challenge-gated status chain fills a per-server capability store and judges server health |
| [0053](0053-frame-and-tag-codecs-in-rmule-primitives.md) | Frame and tag codecs live in rmule-primitives, with one packed-frame mechanism and per-surface policy |
| [0054](0054-peer-multipacket.md) | Peer multipacket: one semantic core, bundled and separate wire shapes |
| [0055](0055-symmetric-source-exchange.md) | Source exchange is symmetric, feeds the live candidate pool and propagates only verified contacts |
| [0056](0056-symmetric-cancel-transfer.md) | Cancel transfer is symmetric: consumed as aMule does, emitted on aMule's triggers |
| [0057](0057-udp-reask-keeps-queue-standing.md) | Queue standing survives disconnect, kept by a UDP reask over one shared client-UDP socket |
| [0058](0058-kad-firewall-self-check.md) | rmule runs and answers aMule's Kad firewall self-check, TCP and UDP |
| [0059](0059-peer-roster.md) | The Peer Roster: one store of the peers this session already deals with |
| [0060](0060-self-reach.md) | Self Reach: one owner answers every reader of our reachability |
| [0061](0061-low-id-callback-route-tree-and-buddies.md) | Low-ID connectivity: one callback route tree, and rmule both serves as and uses a buddy |
| [0062](0062-symmetric-kad-keyword-search-and-publish.md) | Kad keywords are symmetric: rmule searches, publishes and stores, deriving keywords byte for byte as aMule does |
| [0063](0063-kad-notes-by-empty-storer-parity.md) | Kad notes are handled by Empty-Storer Parity: rmule behaves as an aMule storer that never holds a note |
| [0064](0064-kad-liveness-and-verified-contacts.md) | Kad liveness: aMule's flood limiter in the node, bans reported to a core BanStore, and verified contacts |
| [0065](0065-bootstrap-http-acquisition.md) | Bootstrap lists are fetched over HTTP by rmule-bootstrap, behind one Fetcher seam, with aMule's defaults |
| [0066](0066-server-met-and-nodes-dat-codecs.md) | server.met and nodes.dat codecs live with their domain types and replicate aMule's readers |
| [0067](0067-core-owned-startup-join.md) | Core owns the startup join, with aMule's Kad join mechanics and the ed2k→Kad handoff |
| [0068](0068-private-citizen-parity-for-human-layer-opcodes.md) | Human-layer opcodes answer as aMule at its most private setting (Private-Citizen Parity) |
| [0069](0069-thin-front-ends-over-the-core.md) | Front ends are thin shells over the core: headless rmule-cli and the in-process rmule TUI behind a CoreClient seam |
| [0070](0070-table-sort.md) | Every table is ordered by one view-owned Table Sort |
| [0071](0071-download-eta-and-speed.md) | Download ETA divides by a 60-second average; speed is a 4-second meter |
| [0072](0072-row-selection.md) | One Row Selection: the cursor is an identity that follows its row |
| [0073](0073-held-searches.md) | Held Searches: every search of the run stays open as an entry |
| [0074](0074-keys-with-consequences.md) | Keys with consequences are bound only on the tab that shows what they change |
| [0075](0075-run-log.md) | The Run Log: a lean level safe to share and a full level, each value classed by its type |
| [0076](0076-arguments-and-the-data-directory.md) | rmule parses its own arguments and resolves the data directory once, before anything touches it |
| [0077](0077-monotonic-byte-counters-in-core.md) | Transfer byte counters are monotonic facts in the core; rates are derived at the edge |
| [0078](0078-download-name-and-exact-size.md) | A download's name and exact size are one stored core fact, reported on both core surfaces |
| [0079](0079-positional-part-status.md) | A download's progress is one positional part-state vector; every count is derived from it |
| [0080](0080-managed-server-list.md) | The managed server list is a core-owned model, changed only by command and published whole as a level |
| [0081](0081-crate-topology.md) | Crate topology: sans-I/O protocol crates named after their wire conversation, one runtime crate rmule-net |
| [0082](0082-emule-reference-source.md) | eMule 0.70b is the Reference Source for specification; parity is measured against aMule, and against the eMule family only where aMule implements nothing |
| [0083](0083-redb-typed-store.md) | Durable state lives in one redb file behind the rmule-store typed layer; protocol crates stay storage-free |
| [0084](0084-address-learning.md) | Address Learning: one confidence-tiered store owns our own External Endpoints |
| [0085](0085-family-generic-peer-endpoints.md) | Family-generic peer endpoints, IPv4 kept as a type invariant where the wire packs 32 bits, and two sockets per port |
| [0086](0086-port-mapping.md) | Port Mapping: PCP, NAT-PMP and UPnP raced, graded on the exact external port, and acting on Reachability |
| [0087](0087-ipv6-emule-qt-dialect.md) | Speak the emule-qt IPv6 dialect end to end, with kno's seven hardenings |
| [0088](0088-per-address-upload-queue-cap.md) | At most three waiting upload-queue entries per address, an IPv6 /64 counting as one |
| [0089](0089-file-links-and-their-sources.md) | File links: every field a reference reads is read, and the link's sources are the run's first candidates |
| [0090](0090-source-ownership-inside-one-download.md) | A download holds each source under one owner, spends a failed endpoint, and never re-pools bad data |
| [0091](0091-nat-traversal-emuleai-dialect.md) | NAT Traversal: eMuleAI's dialect, two Rendezvous coordinators, a uTP/QUIC Tunnel under the peer session |
| [0092](0092-nat-and-ipv6-bench.md) | The NAT and IPv6 bench: translating gateways that prove their own type, an IPv6 WAN, four counterparty bodies, and flows that can fail |
| [0093](0093-activity-lifecycle.md) | Activity lifecycle: one retire per activity, deaths are stops, quit is every stop in order |
| [0094](0094-durable-download-state.md) | A download's state is durable: a process ending changes neither the operator's word nor its verified parts |
| [0095](0095-connecting-is-the-operators-act.md) | Connecting is the operator's act: nothing else dials a server |
| [0096](0096-lost-session-is-re-made.md) | A lost server session is re-made while the operator's intent stands |
| [0097](0097-download-source-legs-and-ask-budget.md) | A download asks whichever source leg is up, waits when neither is, and shares one Source Ask Budget |
| [0098](0098-hello-names-the-live-session.md) | Every hello names the live server session |
| [0099](0099-announce-policy.md) | The Announce Policy: shares may be withheld from servers that answer related searches |
| [0100](0100-known-file-marks.md) | Known-File Marks: every search result says whether rmule has, fetches, failed, had or dropped the file |
| [0101](0101-shared-directories.md) | Shared directories are the only way rmule shares a whole file: whole directories, recursive, guarded and confirmed |
| [0102](0102-directory-scan-and-hash-trust.md) | The scan hashes one file at a time and trusts a stored hash on its path, size and time |
| [0103](0103-directory-watch.md) | The watch: one notify stream per shared directory, coalesced and waiting for stillness |
| [0104](0104-spare-copies-and-renames.md) | Spare copies and renames carry a stored hash only when the file's identity proves it |
| [0105](0105-had-set.md) | The Had Set remembers content that left the disk, by hash, and a move never passes through it |
| [0106](0106-registry-against-the-disk.md) | The registry against the disk: what is offered is readable now, and a peer is answered honestly when it is not |
| [0107](0107-one-peer-several-downloads.md) | One peer, several downloads: one link and one queue standing per peer, and every claim and answer keyed to the download it serves |
| [0108](0108-source-exchange-ask-cadence.md) | The source-exchange ask follows aMule's gate, per peer and download, under every name the peer is known by |
| [0109](0109-source-seeds.md) | Source Seeds: a restart dials first the peers the last run knew, without asking anyone |
| [0110](0110-dial-end-cause.md) | A dial that ends before the hello says why, and the cause outlives the slot |
| [0111](0111-sparse-part-file.md) | A part file stays positional and is never pre-sized; every write that extends it punches the gap it opened, and each run measures whether its disk holds holes |
| [0112](0112-streaming-window-availability-aware-part-scheduling.md) | A peer is handed only a part it advertised: very rare first, then aMule's head and tail, then a streaming window, then rarest |
| [0113](0113-partial-share-from-the-first-verified-part.md) | A download offers its verified parts from the first one, running or paused: the download's own, never a registry row |
| [0114](0114-preview-action.md) | Preview hands a download's own file to the operator's player as one argument, once its first part is verified |
| [0115](0115-temp-directory-and-completion-move.md) | Part files live in a Temp Directory apart from finished files; completion moves the file into the download directory, waits while a program holds it, and copies only across volumes |
| [0116](0116-asking-and-transferring.md) | A download asks for queue places under one Connection Budget and transfers from every slot it is granted; a Low-ID rmule reasks at 15 minutes; an uploader we queue at is preferred within aMule's score |
