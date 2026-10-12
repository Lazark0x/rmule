//! The Kad runtime's facts as the diagnostics snapshot carries them:
//! the join observable, the table size, the node's identity and the two
//! ADR-0058 self-check verdicts with what the last TCP check drew.

/// The Kad runtime facts [`DiagnosticsSnapshot::kad`](super::DiagnosticsSnapshot::kad) reports.
/// Every field is a level or monotonic **fact** in the snapshot discipline: no
/// rates, no windows — a consumer that wants motion differences snapshots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KadRuntimeDiagnostics {
    /// aMule's `HasHadContact`: at least one counterparty Kad datagram has
    /// been received since the node started — the "joined" observable a
    /// cold-start caller (the ADR-0067 Join Sequence's `EnableKad` leg) waits
    /// on. Only a received datagram can flip it, so it reports a counterparty
    /// reaction, never a self-claim. Fed by the node's silent→heard edge
    /// (`KadEvent::HadContact`), so any accepted datagram counts — not only a
    /// probe answer.
    pub contact_responded: bool,
    /// Live routing-table size — how many contacts the running node currently
    /// holds (event-derived: adds minus evictions, exact because the node
    /// pairs every eviction with its event).
    pub contacts: usize,
    /// The `(keyword, file)` rows the node's keyword index stores for other
    /// publishers (ADR-0062) — aMule's indexed-keywords figure.
    pub keywords_stored: usize,
    /// The node's own Kad ID — the durable keyspace identity core read from
    /// its store at build (`AppConfigStore::ensure_kad_identity`).
    pub node_id: crate::KadId,
    /// The ADR-0058 TCP-reachability verdict as the Kad runtime currently
    /// publishes it — the same cell the ADR-0061 callback chooser reads.
    pub firewall: KadFirewallVerdict,
    /// Why [`Self::firewall`] reads as it does: whether a check has run, and
    /// how many connect-backs the last one drew.
    pub firewall_check: KadFirewallCheck,
    /// The ADR-0058 UDP-reachability verdict — what the UDP self-check's
    /// helpers concluded. `Open` beside a firewalled TCP verdict is what puts
    /// the direct-callback bit (`0x08`) in every source publish.
    pub udp: KadUdpVerdict,
    /// Kad datagrams and their wire bytes, in and out, across the shared
    /// client-UDP bind this session — counted outside the Kad crypt on both
    /// sides, so an obfuscated datagram counts its header and padding.
    /// Monotonic; a rate is a consumer's difference.
    pub traffic: KadTraffic,
}

/// Kad traffic totals as [`KadRuntimeDiagnostics::traffic`] reports them.
pub use rmule_net::kad::KadTrafficTotals as KadTraffic;

/// The ADR-0058 UDP verdict projected for diagnostics consumers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KadUdpVerdict {
    /// A helper's `0x62` reached us on this Kad UDP port.
    Open {
        /// The port proven reachable, intern-preferred.
        port: u16,
    },
    /// Both helpers failed, or six minutes passed with no answer while the
    /// TCP verdict was firewalled too.
    Firewalled,
    /// No helper has answered yet — the fresh-node posture.
    Unverified,
}

/// The ADR-0058 TCP verdict projected for diagnostics consumers — the public
/// face of the reachability store's three-grade state. The honest fresh-node
/// posture is [`Firewalled`](Self::Firewalled): a node that has not *proven*
/// openness never claims it (the production runtime's self-check is still
/// capture-gated off, so a deployment reports firewalled until that lands —
/// truthful, if conservative).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KadFirewallVerdict {
    /// ≥ 2 distinct counterparties acked our TCP connect-back window.
    Open,
    /// A self-check cycle is in flight and undecided.
    Checking,
    /// No proven openness — the default, and the verdict while firewalled.
    Firewalled,
}

/// What the ADR-0058 TCP self-check has drawn — the why beside a
/// [`KadFirewallVerdict`]. A firewalled verdict with no check behind it is the
/// fresh-node default, not a finding; one after a check that drew no
/// connect-back says nobody could dial our TCP port.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KadFirewallCheck {
    /// No check has started since the node did.
    #[default]
    NotYetRun,
    /// A check is collecting connect-backs: `acks` so far.
    Running {
        /// Connect-backs counted since the check started.
        acks: u32,
    },
    /// The last check has ended with `acks` connect-backs.
    Ended {
        /// Connect-backs the check drew; [`Self::ACKS_FOR_OPEN`] or more is
        /// open.
        acks: u32,
    },
}

impl KadFirewallCheck {
    /// Connect-backs a check needs to prove the TCP port open (aMule's
    /// `KADEMLIAFIREWALLCHECKS` boundary).
    pub const ACKS_FOR_OPEN: u32 = 2;
}

/// Where the **Kad Activity** stands: the level the Networks tab's Kad
/// switch reads, so a front end never assumes Kad is up because it asked.
/// Written by the actor at the activity's start, its stop's begin and its
/// retire; rides the shared state, so the sync snapshot carries it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KadState {
    /// No node: never started, stopped, or refused.
    #[default]
    Off,
    /// A node runs. Whether anyone has answered it yet is
    /// [`KadRuntimeDiagnostics::contact_responded`].
    Running,
    /// A stop is under way: the node's lever is pulled and its tasks are
    /// being joined.
    Stopping,
}

/// How the shared diagnostics state reads the running Kad Activity's facts:
/// a live reader the activity installs at start and takes back at retire, so
/// the sync [`crate::Core::diagnostics_snapshot`] and the `DumpDiagnostics`
/// echo return the same value (ADR-0028). A reader, not a copy: every fact
/// here is a level other tasks keep moving.
#[derive(Clone)]
pub(crate) struct KadFactsSource {
    read: std::sync::Arc<dyn Fn() -> KadRuntimeDiagnostics + Send + Sync>,
    /// How many tasks the activity holds (`kad_tasks_live`).
    pub(crate) tasks_live: usize,
}

impl KadFactsSource {
    pub(crate) fn new(
        tasks_live: usize,
        read: impl Fn() -> KadRuntimeDiagnostics + Send + Sync + 'static,
    ) -> Self {
        Self {
            read: std::sync::Arc::new(read),
            tasks_live,
        }
    }

    pub(crate) fn read(&self) -> KadRuntimeDiagnostics {
        (self.read)()
    }
}

impl std::fmt::Debug for KadFactsSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KadFactsSource")
            .field("tasks_live", &self.tasks_live)
            .finish_non_exhaustive()
    }
}
