//! The **Reflector Probe**'s client half: RFC 5780 mapping-behaviour and
//! filtering-behaviour discovery against the harness's `natprobe` container.
//!
//! This is what turns a **NAT Gateway**'s *configuration* into an *observation*.
//! A flow that reports "the punch failed behind a symmetric NAT" has fabricated
//! the interesting half of that sentence unless something measured the NAT from
//! the inside, in the same run — which is exactly what ADR-0045's amended
//! evidence posture demands of every negative NAT row. The probe writes its
//! result as a run-dir row beside the gateway's own `nft`/`conntrack` dump; the
//! harness compares the two.
//!
//! One test is **not** RFC 5780's. The five below address the reflector's own
//! two ports, so a gateway rule keyed on the *pinned client port* — the one
//! port every NAT-T punch and uTP opener is aimed at — is outside their reach
//! entirely. `--pinned-port` adds a sixth test against a **Pinned-Port Sink**
//! on the reflector's primary address, and its answer is the only live evidence
//! that the LAN can still reach the WAN on that port.
//!
//! The procedure is RFC 5780 §4.3/§4.4; the wire is not. STUN's binding format
//! would oblige rmule to carry a STUN codec purely to read its own bench
//! provenance, so the reflector speaks one ASCII line (documented in
//! `tools/interop-harness/images/natprobe/README.md`) and the five tests below
//! ride it.
//!
//! **Stimulus, never evidence.** Nothing here observes a counterparty; it
//! observes the bench.

use std::fmt::Write as _;
use std::fs;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Args;

/// The reflector's line protocol version tag.
const PROTOCOL: &str = "RMULE-NATPROBE/1";

/// Behaviour spellings. These are a read contract with the harness's
/// `nat::MappingBehaviour` / `nat::FilteringBehaviour`, which parse the row this
/// writes; the two crates agree by spelling rather than by a shared type,
/// because the probe must run inside the bench without the harness in its tree.
const ENDPOINT_INDEPENDENT: &str = "endpoint-independent";
const ADDRESS_DEPENDENT: &str = "address-dependent";
const ADDRESS_AND_PORT_DEPENDENT: &str = "address-and-port-dependent";
/// Test I never answered, so nothing downstream of it means anything.
const UNKNOWN: &str = "unknown";
/// A filtering test answered from a socket other than the one it asked the
/// reflector to change to. Any NAT admits a reply from the endpoint the client
/// itself addressed, so such an answer measures nothing about filtering.
const CHANGE_IGNORED: &str = "change-ignored";

/// The pinned-port egress test's stable name, cited by the harness's claims.
const PINNED_PORT_TEST: &str = "pinned-port-reach";

/// `rmule-tools nat probe` — run the five RFC 5780 tests and write the row.
#[derive(Debug, Args)]
pub(crate) struct NatProbeArgs {
    /// The reflector's first fake-public address.
    #[arg(long)]
    pub(crate) reflector_primary: Ipv4Addr,
    /// The reflector's second fake-public address (the same container holds
    /// both; two addresses are what RFC 5780's mapping tests need).
    #[arg(long)]
    pub(crate) reflector_secondary: Ipv4Addr,
    /// The reflector's first UDP port.
    #[arg(long, default_value_t = 3478)]
    pub(crate) reflector_primary_port: u16,
    /// The reflector's second UDP port.
    #[arg(long, default_value_t = 3479)]
    pub(crate) reflector_secondary_port: u16,
    /// The local UDP port to probe from. It must be the port the gateway pins,
    /// because `full-cone-pinned` is endpoint-independent **only** for that
    /// port — probing from an ephemeral port would measure a different NAT than
    /// the one the flow builds.
    #[arg(long, default_value_t = 4672)]
    pub(crate) local_port: u16,
    /// The gateway's **pinned** client port, if the reflector holds a
    /// Pinned-Port Sink there. Adds one test that sends a single datagram to
    /// `reflector_primary:<pinned>` and asserts it is answered.
    ///
    /// The five RFC 5780 tests above address the reflector's own two ports and
    /// can therefore never see a gateway rule keyed on the pinned *destination*
    /// port — which is how an unscoped prerouting DNAT once passed
    /// `natgw-selfproof` four times while eating every punch the client aimed
    /// at that port. This is the live leg that closes it; the rendered-ruleset
    /// leg (`tests/harness/natgw_ruleset.rs`) closes it statically.
    #[arg(long)]
    pub(crate) pinned_port: Option<u16>,
    /// Per-attempt reply deadline.
    #[arg(long, default_value_t = 1500)]
    pub(crate) timeout_ms: u64,
    /// Attempts per test before it counts as unanswered. A filtering test that
    /// is *meant* to be dropped costs `attempts × timeout_ms`, so keep both
    /// small.
    #[arg(long, default_value_t = 3)]
    pub(crate) attempts: u32,
    /// Where to write the `nat-probe.toml` row.
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
}

/// Which socket the reflector is asked to answer from, relative to the one the
/// request lands on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Change {
    /// Same address, same port — the mapping tests.
    None,
    /// Same address, the other port — the Address-Dependent Filtering test.
    Port,
    /// The other address, the other port — the Endpoint-Independent Filtering
    /// test.
    Both,
}

impl Change {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Port => "port",
            Self::Both => "both",
        }
    }
}

/// One test's record: what was asked, and what came back.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TestOutcome {
    name: &'static str,
    target: SocketAddr,
    change: Change,
    /// The source the reflector observed — the client's address after
    /// translation. `None` when nothing answered.
    mapped: Option<SocketAddr>,
    /// The socket the reply actually left from, so an answer that ignored the
    /// requested change is visible rather than silently counted.
    answered_from: Option<SocketAddr>,
}

impl TestOutcome {
    fn answered(&self) -> bool {
        self.mapped.is_some()
    }
}

/// RFC 5780 §4.3. `first` is Test I (primary address, primary port), `second` is
/// Test II (secondary address, primary port), `third` is Test III (secondary
/// address, secondary port).
///
/// Test I unanswered means the probe never reached the reflector at all, and no
/// classification follows from the other two — `unknown`, not a guess.
fn classify_mapping(
    first: Option<SocketAddr>,
    second: Option<SocketAddr>,
    third: Option<SocketAddr>,
) -> &'static str {
    let (Some(first), Some(second)) = (first, second) else {
        return UNKNOWN;
    };
    if first == second {
        return ENDPOINT_INDEPENDENT;
    }
    match third {
        Some(third) if third == second => ADDRESS_DEPENDENT,
        Some(_) => ADDRESS_AND_PORT_DEPENDENT,
        None => UNKNOWN,
    }
}

/// Whether the **Pinned-Port Sink** answered — i.e. whether one datagram the
/// client addressed to the gateway's pinned port reached the WAN at all.
///
/// `false` when the test was not run, because the row's reader must never read
/// "not probed" as "reachable": a proof that can be omitted by forgetting an
/// operand is not a proof.
fn pinned_port_reachable(outcomes: &[TestOutcome]) -> bool {
    outcomes
        .iter()
        .any(|outcome| outcome.name == PINNED_PORT_TEST && outcome.answered())
}

/// RFC 5780 §4.4. `changed_both` is the address-and-port change test,
/// `changed_port` the port-only one: `None` unanswered, `Some(true)` answered
/// from the changed endpoint, `Some(false)` answered from any other. Both are
/// asked of the **primary** address, and both must run before any test
/// touches the secondary address — otherwise a `restricted` gateway's dynamic
/// set would already hold the secondary and the port-only test would read as
/// endpoint-independent.
///
/// Test I unanswered classifies nothing: two silent change tests behind a
/// probe that never reached the reflector are not address-and-port-dependent
/// filtering. An answer that ignored its change is `change-ignored`, never a
/// filtering behaviour.
fn classify_filtering(
    test_i_answered: bool,
    changed_both: Option<bool>,
    changed_port: Option<bool>,
) -> &'static str {
    if !test_i_answered {
        UNKNOWN
    } else if changed_both == Some(false) || changed_port == Some(false) {
        CHANGE_IGNORED
    } else if changed_both == Some(true) {
        ENDPOINT_INDEPENDENT
    } else if changed_port == Some(true) {
        ADDRESS_DEPENDENT
    } else {
        ADDRESS_AND_PORT_DEPENDENT
    }
}

/// Whether a change test was answered from the endpoint it asked for:
/// `None` when it was not answered at all.
fn answered_from_changed(outcome: &TestOutcome, expected: SocketAddr) -> Option<bool> {
    outcome
        .answered()
        .then(|| outcome.answered_from == Some(expected))
}

/// Run the probe and write its row.
///
/// # Errors
/// If the local socket cannot be bound or the row cannot be written. A test that
/// goes unanswered is a *result*, not an error — half of them are meant to be
/// dropped.
pub(crate) fn run_nat_probe(args: NatProbeArgs) -> Result<()> {
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, args.local_port))
        .with_context(|| format!("bind local probe port {}", args.local_port))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(args.timeout_ms)))
        .context("set probe read timeout")?;

    let primary = SocketAddr::from((args.reflector_primary, args.reflector_primary_port));
    let secondary_addr_primary_port =
        SocketAddr::from((args.reflector_secondary, args.reflector_primary_port));
    let secondary_both =
        SocketAddr::from((args.reflector_secondary, args.reflector_secondary_port));

    // Order is load-bearing, see `classify_filtering`: the two filtering tests
    // run against the primary address before Tests II/III ever address the
    // secondary one. The pinned-port test goes **last** so the five indices the
    // classifiers read stay where they are — it addresses the primary address,
    // which every earlier test has already touched, so its position costs
    // nothing.
    let mut plan = vec![
        ("mapping-i", primary, Change::None),
        ("filtering-change-both", primary, Change::Both),
        ("filtering-change-port", primary, Change::Port),
        ("mapping-ii", secondary_addr_primary_port, Change::None),
        ("mapping-iii", secondary_both, Change::None),
    ];
    if let Some(pinned) = args.pinned_port {
        plan.push((
            PINNED_PORT_TEST,
            SocketAddr::from((args.reflector_primary, pinned)),
            Change::None,
        ));
    }

    let mut outcomes = Vec::with_capacity(plan.len());
    for (index, (name, target, change)) in plan.into_iter().enumerate() {
        let outcome = run_test(&socket, name, target, change, index as u32, args.attempts)?;
        println!(
            "nat-probe test={} target={} change={} answered={} mapped={} from={}",
            outcome.name,
            outcome.target,
            outcome.change.as_str(),
            outcome.answered(),
            outcome
                .mapped
                .map_or_else(|| "-".to_owned(), |mapped| mapped.to_string()),
            outcome
                .answered_from
                .map_or_else(|| "-".to_owned(), |from| from.to_string()),
        );
        outcomes.push(outcome);
    }

    let mapping = classify_mapping(outcomes[0].mapped, outcomes[3].mapped, outcomes[4].mapped);
    // The endpoints each change asks the reflector to answer from.
    let changed_both = SocketAddr::from((args.reflector_secondary, args.reflector_secondary_port));
    let changed_port = SocketAddr::from((args.reflector_primary, args.reflector_secondary_port));
    let filtering = classify_filtering(
        outcomes[0].answered(),
        answered_from_changed(&outcomes[1], changed_both),
        answered_from_changed(&outcomes[2], changed_port),
    );
    let pinned_reachable = pinned_port_reachable(&outcomes);
    println!("nat-probe mapping_behaviour={mapping}");
    println!("nat-probe filtering_behaviour={filtering}");
    if let Some(pinned) = args.pinned_port {
        println!("nat-probe pinned_port={pinned} pinned_port_reachable={pinned_reachable}");
    }

    let row = render_row(&args, mapping, filtering, pinned_reachable, &outcomes);
    print!("{row}");
    if let Some(path) = &args.out {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        fs::write(path, &row).with_context(|| format!("write {}", path.display()))?;
        println!("nat-probe row written to {}", path.display());
    }
    if mapping == UNKNOWN {
        bail!(
            "nat-probe: Test I ({primary}) went unanswered, so no NAT behaviour could be \
             measured — the row records the absence rather than a classification"
        );
    }
    Ok(())
}

/// Send one test's request up to `attempts` times, matching the reply by its
/// transaction id so a late answer to an earlier test cannot be miscounted.
fn run_test(
    socket: &UdpSocket,
    name: &'static str,
    target: SocketAddr,
    change: Change,
    index: u32,
    attempts: u32,
) -> Result<TestOutcome> {
    for attempt in 0..attempts {
        let txid = format!("{index:02}{attempt:02}");
        let request = format!("{PROTOCOL} REQ {txid} {}\n", change.as_str());
        if let Err(error) = socket.send_to(request.as_bytes(), target) {
            // An `--internal` bridge with no route to the target answers with
            // ENETUNREACH here. That is an observation about the bench, and it
            // must not abort the other tests.
            eprintln!("nat-probe {name}: send to {target} failed: {error}");
            continue;
        }
        if let Some((mapped, from)) = await_reply(socket, &txid)? {
            return Ok(TestOutcome {
                name,
                target,
                change,
                mapped: Some(mapped),
                answered_from: Some(from),
            });
        }
    }
    Ok(TestOutcome {
        name,
        target,
        change,
        mapped: None,
        answered_from: None,
    })
}

/// Read until a reply carrying `txid` arrives or the socket's read timeout
/// expires. Datagrams that are not this reflector's replies, or carry another
/// transaction, are skipped — the local port is the client's real eD2k/Kad port
/// and a bench bridge carries other traffic.
fn await_reply(socket: &UdpSocket, txid: &str) -> Result<Option<(SocketAddr, SocketAddr)>> {
    let deadline = Instant::now()
        + socket
            .read_timeout()
            .context("read probe socket timeout")?
            .unwrap_or_else(|| Duration::from_millis(1500));
    let mut buffer = [0_u8; 2048];
    while Instant::now() < deadline {
        let (read, source) = match socket.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::ConnectionRefused
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error).context("receive probe reply"),
        };
        if let Some(mapped) = parse_reply(&buffer[..read], txid) {
            return Ok(Some((mapped, source)));
        }
    }
    Ok(None)
}

/// The reflector's reply line: `… RES <txid> <mapped-ip> <mapped-port> …`.
/// Returns the mapped address when the line is this reflector's answer to
/// `txid`, and `None` for anything else on the wire.
fn parse_reply(payload: &[u8], txid: &str) -> Option<SocketAddr> {
    let text = std::str::from_utf8(payload).ok()?;
    let mut fields = text.split_whitespace();
    if fields.next()? != PROTOCOL || fields.next()? != "RES" || fields.next()? != txid {
        return None;
    }
    let address: Ipv4Addr = fields.next()?.parse().ok()?;
    let port: u16 = fields.next()?.parse().ok()?;
    Some(SocketAddr::from((address, port)))
}

/// The `nat-probe.toml` row. Hand-rendered rather than serialised: rmule-tools
/// carries no TOML dependency, and the row is five scalars plus one array of
/// tables whose shape is asserted by the harness.
fn render_row(
    args: &NatProbeArgs,
    mapping: &str,
    filtering: &str,
    pinned_reachable: bool,
    outcomes: &[TestOutcome],
) -> String {
    let mut row = String::new();
    let _ = writeln!(row, "probe = \"rfc5780\"");
    let _ = writeln!(row, "local_port = {}", args.local_port);
    // `0` is the spelling for "no sink was named", and it pairs with a `false`
    // reachability — the two fields are read together.
    let _ = writeln!(row, "pinned_port = {}", args.pinned_port.unwrap_or(0));
    let _ = writeln!(row, "pinned_port_reachable = {pinned_reachable}");
    let _ = writeln!(
        row,
        "reflector_primary = \"{}:{}\"",
        args.reflector_primary, args.reflector_primary_port
    );
    let _ = writeln!(
        row,
        "reflector_secondary = \"{}:{}\"",
        args.reflector_secondary, args.reflector_secondary_port
    );
    let _ = writeln!(row, "mapping_behaviour = \"{mapping}\"");
    let _ = writeln!(row, "filtering_behaviour = \"{filtering}\"");
    for outcome in outcomes {
        let _ = writeln!(row, "\n[[test]]");
        let _ = writeln!(row, "name = \"{}\"", outcome.name);
        let _ = writeln!(row, "target = \"{}\"", outcome.target);
        let _ = writeln!(row, "change = \"{}\"", outcome.change.as_str());
        let _ = writeln!(row, "answered = {}", outcome.answered());
        match outcome.mapped {
            Some(mapped) => {
                let _ = writeln!(row, "mapped = \"{mapped}\"");
            }
            None => {
                let _ = writeln!(row, "mapped = \"\"");
            }
        }
        match outcome.answered_from {
            Some(from) => {
                let _ = writeln!(row, "answered_from = \"{from}\"");
            }
            None => {
                let _ = writeln!(row, "answered_from = \"\"");
            }
        }
    }
    row
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([203, 0, 113, 2], port))
    }

    #[test]
    fn one_external_port_toward_two_hosts_is_endpoint_independent_mapping() {
        assert_eq!(
            classify_mapping(Some(addr(4672)), Some(addr(4672)), Some(addr(4672))),
            ENDPOINT_INDEPENDENT
        );
    }

    #[test]
    fn a_fresh_port_per_host_and_port_is_the_symmetric_case() {
        assert_eq!(
            classify_mapping(Some(addr(4672)), Some(addr(51001)), Some(addr(51002))),
            ADDRESS_AND_PORT_DEPENDENT
        );
    }

    #[test]
    fn a_port_that_changes_per_host_but_not_per_port_is_address_dependent() {
        assert_eq!(
            classify_mapping(Some(addr(4672)), Some(addr(51001)), Some(addr(51001))),
            ADDRESS_DEPENDENT
        );
    }

    #[test]
    fn an_unanswered_test_i_classifies_nothing() {
        assert_eq!(
            classify_mapping(None, Some(addr(4672)), Some(addr(4672))),
            UNKNOWN
        );
        // Test I answered but II silent is equally unclassifiable: a NAT that
        // dropped the second probe would otherwise read as symmetric.
        assert_eq!(classify_mapping(Some(addr(4672)), None, None), UNKNOWN);
        // II answered and III silent cannot separate address-dependent from
        // address-and-port-dependent.
        assert_eq!(
            classify_mapping(Some(addr(4672)), Some(addr(51001)), None),
            UNKNOWN
        );
    }

    #[test]
    fn filtering_reads_the_widest_answered_test() {
        let (yes, silent) = (Some(true), None);
        assert_eq!(classify_filtering(true, yes, yes), ENDPOINT_INDEPENDENT);
        assert_eq!(classify_filtering(true, yes, silent), ENDPOINT_INDEPENDENT);
        assert_eq!(classify_filtering(true, silent, yes), ADDRESS_DEPENDENT);
        assert_eq!(
            classify_filtering(true, silent, silent),
            ADDRESS_AND_PORT_DEPENDENT
        );
    }

    /// A reflector that answered a change test from the socket the client
    /// addressed passes every NAT type, so it must not read as
    /// endpoint-independent filtering.
    #[test]
    fn an_answer_that_ignored_its_change_is_not_a_filtering_reading() {
        assert_eq!(classify_filtering(true, Some(false), None), CHANGE_IGNORED);
        assert_eq!(classify_filtering(true, None, Some(false)), CHANGE_IGNORED);
        let outcome = |from| TestOutcome {
            name: "filtering-change-both",
            target: addr(3478),
            change: Change::Both,
            mapped: Some(addr(4672)),
            answered_from: Some(from),
        };
        let changed = SocketAddr::from(([203, 0, 113, 4], 3479));
        assert_eq!(
            answered_from_changed(&outcome(changed), changed),
            Some(true)
        );
        assert_eq!(
            answered_from_changed(&outcome(addr(3478)), changed),
            Some(false)
        );
    }

    /// Test I unanswered: the change tests' silence is the probe's, not the
    /// gateway's, and reads `unknown` rather than address-and-port-dependent.
    #[test]
    fn an_unanswered_test_i_classifies_no_filtering() {
        assert_eq!(classify_filtering(false, None, None), UNKNOWN);
    }

    /// A pinned-port test that was never run must not read as a pass: the
    /// whole point of the leg is that a gateway rule keyed on that port is
    /// invisible to the five RFC 5780 tests, so a silently absent row would
    /// restore exactly that blind spot.
    #[test]
    fn an_unrun_pinned_port_test_is_not_reachability() {
        let outcome = |name, mapped| TestOutcome {
            name,
            target: addr(4672),
            change: Change::None,
            mapped,
            answered_from: mapped,
        };
        assert!(!pinned_port_reachable(&[outcome(
            "mapping-i",
            Some(addr(4672))
        )]));
        assert!(!pinned_port_reachable(&[outcome(PINNED_PORT_TEST, None)]));
        assert!(pinned_port_reachable(&[
            outcome("mapping-i", Some(addr(4672))),
            outcome(PINNED_PORT_TEST, Some(addr(4672))),
        ]));
    }

    #[test]
    fn a_reply_is_only_read_when_it_carries_this_transaction() {
        let reply = b"RMULE-NATPROBE/1 RES 0100 203.0.113.2 4672 203.0.113.4 3479 203.0.113.3 3478";
        assert_eq!(parse_reply(reply, "0100"), Some(addr(4672)));
        assert_eq!(parse_reply(reply, "0200"), None, "another test's reply");
        assert_eq!(parse_reply(b"\xe4\x21 kad datagram", "0100"), None);
        assert_eq!(parse_reply(b"RMULE-NATPROBE/1 REQ 0100 none", "0100"), None);
    }
}
