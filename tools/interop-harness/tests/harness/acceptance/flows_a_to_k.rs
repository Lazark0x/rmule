//! Flows A-K: one `#[test]` wrapper per harness flow.

use super::{bench_enabled, read, read_string, run_flow};
use crate::fixture::unused_local_port;
use std::path::Path;

/// **Flow A — server cycle.** rmule against a live eserver with one aMule
/// sharing the synthetic file: login accepted + IDCHANGE `SRV_TCPFLG` recorded,
/// UDP status ping answered, global search finds the file, get-sources returns
/// ≥1 source, and the download byte-completes — each leg asserted by the
/// flow, which records a per-leg verdict.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn flow_a_server_cycle() {
    if !bench_enabled("A") {
        return;
    }
    let port = unused_local_port();
    let port_arg = port.port().to_string();
    drop(port); // before the container's own host-port publish binds it
    let run_dir = run_flow(
        "server-cycle",
        &[
            "--skip-build",
            "--server-host-port",
            &port_arg,
            // Three sequential in-container rmule-tools compiles (probe, search,
            // download), so each readiness/leg needs a generous per-step budget.
            "--timeout",
            "600",
        ],
    );
    let verdict = read_string(&run_dir, "server-cycle-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "flow A: every server-cycle leg must pass:\n{verdict}",
    );
}

/// **Flow B — forward download.** aMule shares a synthetic file behind the
/// eserver; rmule discovers the source and downloads it. Proves a full
/// server-login → search/get-sources → peer-transfer round trip against a live
/// aMule, byte-for-byte. (Adopts the existing `amule-serves-rmule-downloads`.)
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn flow_b_forward_download() {
    if !bench_enabled("B") {
        return;
    }
    let port = unused_local_port();
    let port_arg = port.port().to_string();
    drop(port); // before the container's own host-port publish binds it
    let run_dir = run_flow(
        "amule-serves-rmule-downloads",
        &["--skip-build", "--server-host-port", &port_arg],
    );
    assert_eq!(
        read(&run_dir, "synthetic/shared.bin"),
        read(&run_dir, "rmule/output.bin"),
        "flow B: rmule's download must byte-match the aMule-shared file",
    );
}

/// **Flow D — Low-ID callback capability (ADR-0039; ADR-0040 exemption).**
/// The aMule sharer is forced Low-ID (firewalled inbound TCP). The Lugdunum test
/// eserver never surfaces a Low-ID peer as a source (`OP_GETSOURCES` returns no
/// `OP_FOUNDSOURCES` — ADR-0040), so rmule cannot discover the aMule and no
/// callback can be relayed: a documented compatibility-tier limitation, not a
/// rmule fault. What this flow proves on real wire is
/// rmule's own **callback capability** — logging into the real server while the
/// real Low-ID aMule shares the file, rmule is assigned a High ID and binds its
/// inbound listener (the ADR-0039 precondition for adopting a called-back peer).
/// The byte-completing adoption path is proven deterministically by the
/// in-process correctness tier (`callback_loopback`, ADR-0040). (Adopts
/// `amule-low-id-callback`.)
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn flow_d_low_id_callback() {
    if !bench_enabled("D") {
        return;
    }
    let port = unused_local_port();
    let port_arg = port.port().to_string();
    drop(port); // before the container's own host-port publish binds it
    let run_dir = run_flow(
        "amule-low-id-callback",
        &[
            "--skip-build",
            "--server-host-port",
            &port_arg,
            // Readiness budget for the eserver + Low-ID aMule to come up; the
            // rmule run itself is bounded inside the flow (it cannot complete).
            "--timeout",
            "420",
        ],
    );
    let verdict = read_string(&run_dir, "amule-low-id-callback-verdict.toml");
    assert!(
        verdict.contains("callback_capable = true"),
        "flow D: rmule must reach callback capability (High ID + bound listener) \
         against the real eserver while a real Low-ID aMule shares the file:\n{verdict}",
    );
}

/// **Flow C — reverse download.** rmule *serves* the synthetic file; a live
/// aMule downloads it via an ed2k link and byte-completes on its incoming file.
/// This is the reverse-harness leg that later unlocks the aMule-downloads-from-
/// rmule capture rows. (Adopts `rmule-serves-amule-downloads`.)
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn flow_c_reverse_download() {
    if !bench_enabled("C") {
        return;
    }
    let port = unused_local_port();
    let port_arg = port.port().to_string();
    drop(port); // before the container's own host-port publish binds it
    let run_dir = run_flow(
        "rmule-serves-amule-downloads",
        &[
            "--skip-build",
            "--server-host-port",
            &port_arg,
            // The rmule serve container compiles rmule-tools in-container before
            // it announces; the default 300s can be too tight under load.
            "--timeout",
            "600",
        ],
    );
    assert_eq!(
        read(&run_dir, "synthetic/shared.bin"),
        read(&run_dir, "amule/shared.bin"),
        "flow C: aMule's incoming file must byte-match the file rmule served",
    );
}

/// **Flow E — crypt-on transfer.** A crypt-*required* aMule peer; rmule learns
/// its runtime User Hash from a plaintext hello, then obfuscate-dials it and
/// completes a Secure User Identification exchange plus a part transfer over the
/// obfuscated connection. Success is `peer identity_verified` on rmule's stdout
/// (the capture command exits non-zero otherwise). No captures promoted.
///
/// Note: this proves the *peer-to-peer* obfuscated transfer (the reachable
/// crypt path today). A server-mediated forward download with an obfuscated
/// source dial (`ed2k download start --obfuscation`) is a separate tooling gap
/// gap. (Adopts `amule-direct-sui --obfuscation required`.)
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn flow_e_crypt_on_transfer() {
    if !bench_enabled("E") {
        return;
    }
    let port = unused_local_port();
    let port_arg = port.port().to_string();
    drop(port); // before the container's own host-port publish binds it
    let run_dir = run_flow(
        "amule-direct-sui",
        &[
            "--skip-build",
            "--amule-host-port",
            &port_arg,
            "--obfuscation",
            "required",
            "--timeout",
            "420",
        ],
    );
    let stdout = read_string(&run_dir, "rmule/stdout.log");
    assert!(
        stdout.contains("peer identity_verified"),
        "flow E: obfuscated SUI must complete (peer identity_verified):\n{stdout}",
    );
}

/// **Flow F — Kad join + publish + search.** rmule joins a stock-aMule
/// fake-public Kad swarm (Config A, one pinned storer on an internal
/// documentation-range /24), publishes the synthetic file's source, and
/// searches it back. The flow judges the round trip from rmule's own tap:
/// aMule's `0x4B` publish ack and its genuine `0x3B` source answer — the
/// verdict is PASS only when the published entry is searched back. Reuses one
/// swarm boot for the whole flow.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn flow_f_kad_publish_search() {
    if !bench_enabled("F") {
        return;
    }
    // Stock aMule + capture images are present; the rmule stimulus image is
    // always rebuilt from the workspace. The rmule image builds from the repo
    // root, so pass absolute paths — the test's CWD is the crate dir, where the
    // flow's repo-root-relative defaults would not resolve.
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let dockerfile = repo_root.join("tools/interop-harness/images/rmule-node/Dockerfile");
    let (repo_root, dockerfile) = (
        repo_root.to_str().unwrap().to_string(),
        dockerfile.to_str().unwrap().to_string(),
    );
    let run_dir = run_flow(
        "kad-fake-public-source",
        &[
            "--skip-build",
            "--timeout",
            "420",
            "--rmule-dockerfile",
            &dockerfile,
            "--rmule-build-context",
            &repo_root,
        ],
    );
    let verdict = read_string(&run_dir, "kad/kad-source-capture-verdict.txt");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "flow F: the published source must be searched back (0x4B ack + 0x3B answer):\n{verdict}",
    );
}

/// **Flow G — ed2k→Kad handoff (ADR-0067).** The `rmule-tools
/// ed2k kad-handoff` runner is at once eD2k-connected to a Kad-running aMule and
/// running a Kad node: it consumes the aMule hello's `CT_EMULE_UDPPORTS` Kad
/// port + `CT_EMULE_MISCOPTIONS2` Kad version, brokers a `BootstrapFromPeer`
/// dial, and reaches Kad contact. A stand-alone rmule Kad seed first brings the
/// counterparty to "Kad: Connected" (a third party, so the runner's own node
/// only joins via the handoff dial). PASS = the runner reports `joined` and the
/// observed `CT_EMULE_UDPPORTS` layout is recorded.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn flow_g_ed2k_kad_handoff() {
    if !bench_enabled("G") {
        return;
    }
    let run_dir = run_flow(
        "ed2k-kad-handoff",
        &[
            "--skip-build",
            // The runner compiles rmule-tools (with its Kad join node) in the
            // container before it runs, so the readiness budget must be generous.
            "--timeout",
            "600",
        ],
    );
    let verdict = read_string(&run_dir, "ed2k-kad-handoff-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\"") && verdict.contains("joined = true"),
        "flow G: the ed2k→Kad handoff must reach joined:\n{verdict}",
    );
    assert!(
        verdict.contains("CT_EMULE_UDPPORTS"),
        "flow G: the observed CT_EMULE_UDPPORTS layout must be recorded:\n{verdict}",
    );
}

/// **Flow H — HTTP-bootstrap cold start (GREEN).** The full cold start driven by
/// the `rmule-tools ed2k bootstrap-fetch` runner: a fresh rmule
/// fetches `server.met` + `nodes.dat` over HTTP from a local fixture, connects to
/// the fetched eD2k server, and Kad-joins from the fetched contact against the
/// live swarm. The flow asserts both stages (`server_login` + `kad_joined`)
/// and records a PASS/FAIL verdict.
///
/// The aMule-*authored* server.met / v2 nodes.dat goldens (legs 2 + 3) are
/// harvested by the separate `http-bootstrap-goldens` and `v2-nodes-dat-harvest`
/// subcommands and proven by the `server_met_golden` / `nodes_dat_golden` decode
/// tests; this flow serves topology-matched files (the goldens' fixed harvest
/// addresses cannot connect a fresh bench) and proves the runner's live
/// fetch → decode → connect → join pipeline.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn flow_h_http_bootstrap_cold_start() {
    if !bench_enabled("H") {
        return;
    }
    let run_dir = run_flow(
        "http-bootstrap-cold-start",
        &[
            "--skip-build",
            "--kad-connect-deadline",
            "90",
            "--handoff-window",
            "100",
        ],
    );
    let verdict = read_string(&run_dir, "http-bootstrap-cold-start-verdict.toml");
    assert!(
        verdict.contains("join_sequence = true"),
        "flow H: the runner must drive the ADR-0067 Join Sequence (first-run fetch installed):\n{verdict}",
    );
    assert!(
        verdict.contains("server_login = true"),
        "flow H: the runner must fetch server.met over HTTP and log in to the fetched server:\n{verdict}",
    );
    assert!(
        verdict.contains("kad_joined = true"),
        "flow H: the runner must fetch nodes.dat over HTTP and Kad-join the fetched contact:\n{verdict}",
    );
}

/// **Flow I — packed source-exchange (ADR-0043).** The
/// multi-registrant leg: 15 fabricated distinct-IP High-ID identities register
/// one hash on the live eserver, a downloading aMule learns them via
/// get-sources and establishes them, and rmule then dials that aMule and asks
/// it for sources inside the `0xA4` bundle (advertising SX nibble 3). aMule's
/// answer crosses its own 354-byte pack threshold at 12 rows, so it comes back
/// zlib-packed as `0xD4` — the `0xD4` / `0x82`-inflate / `0x84`-v4 capture in
/// one frame. PASS = `answer_packed`.
///
/// Two rmule-side preconditions carry this flow: every registrant must earn
/// High-ID (a Low-ID registrant is never counted into the answer, ADR-0040),
/// and the source ask must ride the `0xA4` bundle — aMule 2.3.3 always rejects
/// a standalone `OP_REQUESTSOURCES2` with a disconnect.
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn flow_i_packed_source_exchange() {
    if !bench_enabled("I") {
        return;
    }
    let port = unused_local_port();
    let port_arg = port.port().to_string();
    drop(port); // before the container's own host-port publish binds it
    let run_dir = run_flow(
        "packed-source-exchange",
        &[
            "--skip-build",
            "--server-host-port",
            &port_arg,
            // rmule-tools containers compile from the mounted workspace (shared
            // target ⇒ one cold build), plus the aMule download settle.
            "--timeout",
            "900",
        ],
    );
    let verdict = read_string(&run_dir, "packed-source-exchange-verdict.toml");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "flow I: aMule must answer with a packed 0xD4 source frame:\n{verdict}",
    );
}

/// **Flow J — inverted-role keyword store (ADR-0062 recipes 2+4).**
/// The role inversion of flow F: a stock aMule *publishes* a keyword and
/// *searches* it toward rmule's keyword store (rmule's KadID pinned to the
/// keyword target so it is the XOR-closest node), so rmule's serve side faces
/// genuine aMule `0x33` (search) — and, when the publish gate opens, `0x43`
/// (publish) — request bytes. PASS = the required recipe 4: an inbound aMule
/// `0x33` reached rmule AND rmule emitted `KeywordSearchServed` (clean decode +
/// serve). Recipe 2 (`0x43`) is judged independently and recorded, never gating.
/// (Adopts `kad-inverted-keyword`.)
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn flow_j_inverted_keyword_store() {
    if !bench_enabled("J") {
        return;
    }
    // The rmule storer image builds from the repo root, so pass absolute paths —
    // the test's CWD is the crate dir (mirrors flow F).
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let dockerfile = repo_root.join("tools/interop-harness/images/rmule-node/Dockerfile");
    let (repo_root, dockerfile) = (
        repo_root.to_str().unwrap().to_string(),
        dockerfile.to_str().unwrap().to_string(),
    );
    let run_dir = run_flow(
        "kad-inverted-keyword",
        &[
            "--skip-build",
            "--timeout",
            "600",
            "--rmule-dockerfile",
            &dockerfile,
            "--rmule-build-context",
            &repo_root,
        ],
    );
    let verdict = read_string(&run_dir, "kad/kad-inverted-keyword-verdict.txt");
    assert!(
        verdict.contains("verdict = \"PASS\""),
        "flow J: aMule's genuine 0x33 keyword search must reach rmule's store and be served \
         (search_captured):\n{verdict}",
    );
}

/// **Flow K — firewalled-counterparty buddy/callback leg (ADR-0061).**
/// A stock aMule Kad node with its Kad TCP+UDP port iptables-DROPped self-reports
/// firewalled; rmule (pinned to `~aMuleKadID`) taps every datagram the firewalled
/// node sends toward it and scans for the buddy/callback opcodes (`0x51`/`0x52`/
/// `0x5A`/`0x94`/`0x95`). The honest observable is that the
/// firewall installs and the firewalled aMule reaches rmule (PASS/OBSERVED); a
/// *complete* buddy/callback exchange is 20-min `FIND_BUDDY_INTERVAL` +
/// reachability-convergence gated and rmule's live Kad node does not yet wire the
/// ADR-0061 responder, so the recipe opcode is recorded as an observation
/// (ADR-0045). (Adopts `kad-firewalled-buddy`.)
#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn flow_k_firewalled_buddy() {
    if !bench_enabled("K") {
        return;
    }
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let dockerfile = repo_root.join("tools/interop-harness/images/rmule-node/Dockerfile");
    let (repo_root, dockerfile) = (
        repo_root.to_str().unwrap().to_string(),
        dockerfile.to_str().unwrap().to_string(),
    );
    let run_dir = run_flow(
        "kad-firewalled-buddy",
        &[
            "--skip-build",
            "--timeout",
            "420",
            "--window",
            "360",
            "--rmule-dockerfile",
            &dockerfile,
            "--rmule-build-context",
            &repo_root,
        ],
    );
    let verdict = read_string(&run_dir, "kad/kad-firewalled-buddy-verdict.toml");
    // Accepting OBSERVED is deliberate: the gate is one-sided (rmule's emit),
    // so a counterparty that stops answering degrades the verdict artifact
    // PASS→OBSERVED rather than failing the run — live-swarm silence is a
    // documented block, not a regression this suite can adjudicate.
    assert!(
        verdict.contains("verdict = \"PASS\"") || verdict.contains("verdict = \"OBSERVED\""),
        "flow K: the firewall must install and the firewalled aMule must reach rmule (PASS on a \
         captured buddy/callback opcode, else OBSERVED with the documented timer/wiring block):\n{verdict}",
    );
}
