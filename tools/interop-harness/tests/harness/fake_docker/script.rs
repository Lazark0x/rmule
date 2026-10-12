//! The **Fake Docker** itself: the shell scripts this suite hands to
//! `--container-runtime`, one per orchestration shape they must replay, plus
//! the stub `rmule-tools` and ED2K hash commands. Each records the argv it was
//! handed and prints canned output — orchestration shape only, never a
//! counterparty.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::fixture::{KAD_FILE_HASH_HEX, deterministic_bytes, make_executable};

/// Fake docker that only logs every invocation and answers success, with no
/// capability line from a `run`: every **Bench Doctor** probe it backs reports
/// every capability absent, so a NAT flow that requires one takes the
/// graceful `SKIPPED` path right after `build_images` runs, with no network or
/// container orchestration in between. Cheap way for a test to see exactly
/// what `build_images` invoked.
pub(crate) fn fake_build_log_docker(dir: &Path, log: &Path) -> PathBuf {
    let path = dir.join("build-log-docker");
    let mut script = std::fs::File::create(&path).unwrap();
    writeln!(script, "#!/bin/sh").unwrap();
    writeln!(script, "set -eu").unwrap();
    writeln!(script, "printf '%s\\n' \"$*\" >> \"{}\"", log.display()).unwrap();
    writeln!(script, "exit 0").unwrap();
    drop(script);
    make_executable(&path);
    path
}

/// Fake docker for the stock-aMule Kad smoke: both nodes report Kad-started via
/// logs, and `amulecmd Status` reports Connected on the first poll.
pub(crate) fn fake_kad_smoke_docker(dir: &Path, log: &Path) -> PathBuf {
    let path = dir.join("kad-smoke-docker");
    let mut script = std::fs::File::create(&path).unwrap();
    writeln!(script, "#!/bin/sh").unwrap();
    writeln!(script, "set -eu").unwrap();
    writeln!(script, "printf '%s\\n' \"$*\" >> \"{}\"", log.display()).unwrap();
    writeln!(script, "case \"$1\" in").unwrap();
    writeln!(script, "  --version) exit 0 ;;").unwrap();
    writeln!(script, "  build) exit 0 ;;").unwrap();
    writeln!(
        script,
        "  network) if [ \"$2\" = create ]; then printf '%s\\n' 'network:kad-smoke'; fi; exit 0 ;;"
    )
    .unwrap();
    writeln!(
        script,
        "  run) name=\"${{4:-container}}\"; printf '%s\\n' \"container:$name\"; exit 0 ;;"
    )
    .unwrap();
    // Both nodes run the routing role, so both emit the routing-ready line.
    writeln!(
        script,
        "  logs) printf '%s\\n' 'rmule-kad-routing-ready'; exit 0 ;;"
    )
    .unwrap();
    // amulecmd Status → Connected on the first poll.
    writeln!(
        script,
        "  exec) case \" $* \" in *Status*) printf '%s\\n' 'Kad: Connected (ok)' ;; esac; exit 0 ;;"
    )
    .unwrap();
    writeln!(script, "  inspect) printf '%s\\n' '203.0.113.2'; exit 0 ;;").unwrap();
    writeln!(script, "  rm) exit 0 ;;").unwrap();
    writeln!(script, "esac").unwrap();
    writeln!(script, "exit 0").unwrap();
    drop(script);
    make_executable(&path);
    path
}

/// Fake docker that records its args and succeeds — enough to exercise the
/// golden-flush exec + cp composition.
pub(crate) fn fake_flush_docker(dir: &Path, log: &Path) -> PathBuf {
    let path = dir.join("flush-docker");
    let mut script = std::fs::File::create(&path).unwrap();
    writeln!(script, "#!/bin/sh").unwrap();
    writeln!(script, "printf '%s\\n' \"$*\" >> \"{}\"", log.display()).unwrap();
    writeln!(script, "exit 0").unwrap();
    drop(script);
    make_executable(&path);
    path
}

/// Fake docker whose `logs` never contains `files_announced` — the eserver
/// login never lands (the give-up-after-N path).
pub(crate) fn fake_login_retry_docker(dir: &Path, log: &Path) -> PathBuf {
    let path = dir.join("login-retry-docker");
    let mut script = std::fs::File::create(&path).unwrap();
    writeln!(script, "#!/bin/sh").unwrap();
    writeln!(script, "printf '%s\\n' \"$*\" >> \"{}\"", log.display()).unwrap();
    writeln!(script, "case \"$1\" in").unwrap();
    writeln!(script, "  run) printf '%s\\n' container; exit 0 ;;").unwrap();
    writeln!(
        script,
        "  logs) printf '%s\\n' 'serve not-ready'; exit 0 ;;"
    )
    .unwrap();
    writeln!(script, "  rm) exit 0 ;;").unwrap();
    writeln!(script, "esac").unwrap();
    writeln!(script, "exit 0").unwrap();
    drop(script);
    make_executable(&path);
    path
}

pub(crate) fn fake_kad_docker(dir: &Path, log: &Path) -> PathBuf {
    let path = dir.join("kad-docker");
    let mut script = std::fs::File::create(&path).unwrap();
    writeln!(script, "#!/bin/sh").unwrap();
    writeln!(script, "set -eu").unwrap();
    writeln!(script, "printf '%s\\n' \"$*\" >> \"{}\"", log.display()).unwrap();
    writeln!(script, "case \"$1\" in").unwrap();
    writeln!(script, "  --version) exit 0 ;;").unwrap();
    writeln!(script, "  build) exit 0 ;;").unwrap();
    writeln!(
        script,
        "  network) if [ \"$2\" = create ]; then printf '%s\\n' \"network:$3\"; fi; exit 0 ;;"
    )
    .unwrap();
    writeln!(script, "  run)").unwrap();
    writeln!(script, "    container_name=\"${{4:-container}}\"").unwrap();
    // Capture sidecar: create the fake pcap at the mounted host directory.
    writeln!(script, "    case \" $* \" in").unwrap();
    writeln!(script, "      *' interop-capture'*|*'interop-capture:'*)").unwrap();
    writeln!(script, "        capture_host=''").unwrap();
    writeln!(script, "        while [ \"$#\" -gt 0 ]; do").unwrap();
    writeln!(script, "          if [ \"$1\" = -v ]; then").unwrap();
    writeln!(script, "            shift").unwrap();
    writeln!(script, "            case \"$1\" in").unwrap();
    writeln!(
        script,
        "              *:/capture) capture_host=${{1%:/capture}} ;;"
    )
    .unwrap();
    writeln!(script, "            esac").unwrap();
    writeln!(script, "          fi").unwrap();
    writeln!(script, "          shift || true").unwrap();
    writeln!(script, "        done").unwrap();
    writeln!(
        script,
        "        if [ -n \"$capture_host\" ]; then printf 'fake-pcap\\n' > \"$capture_host/kad.pcap\"; fi"
    )
    .unwrap();
    writeln!(script, "        ;;").unwrap();
    writeln!(script, "    esac").unwrap();
    writeln!(
        script,
        "    printf '%s\\n' \"container:$container_name\"; exit 0 ;;"
    )
    .unwrap();
    writeln!(script, "  logs)").unwrap();
    writeln!(script, "    case \"$2\" in").unwrap();
    writeln!(
        script,
        "      *publisher*) printf '%s\\n' 'rmule-kad-publisher-ready' ;;"
    )
    .unwrap();
    writeln!(
        script,
        "      *requester*) printf '%s\\n' 'rmule-kad-requester-ready'; printf '%s\\n' 'rmule-kad-source-search-active' ;;"
    )
    .unwrap();
    // The storer joins as a routing-role node, so it emits the routing ready
    // line (its container name has no "routing" substring of its own).
    writeln!(
        script,
        "      *storer*|*routing*) printf '%s\\n' 'rmule-kad-routing-ready' ;;"
    )
    .unwrap();
    writeln!(script, "      *) printf '%s\\n' 'logs' ;;").unwrap();
    writeln!(script, "    esac").unwrap();
    writeln!(script, "    exit 0 ;;").unwrap();
    writeln!(script, "  inspect) printf '%s\\n' '172.18.0.5'; exit 0 ;;").unwrap();
    writeln!(script, "  exec) exit 0 ;;").unwrap();
    writeln!(script, "  rm) exit 0 ;;").unwrap();
    writeln!(script, "esac").unwrap();
    writeln!(script, "exit 0").unwrap();
    drop(script);
    make_executable(&path);
    path
}

pub(crate) fn fake_docker(dir: &Path, log: &Path) -> PathBuf {
    fake_docker_with_mode(dir, log, "success")
}

pub(crate) fn fake_docker_with_mode(dir: &Path, log: &Path, mode: &str) -> PathBuf {
    let path = dir.join("docker");
    let mut script = std::fs::File::create(&path).unwrap();
    writeln!(script, "#!/bin/sh").unwrap();
    writeln!(script, "set -eu").unwrap();
    writeln!(script, "mode='{}'", mode).unwrap();
    writeln!(script, "printf '%s\\n' \"$*\" >> \"{}\"", log.display()).unwrap();
    writeln!(script, "case \"$1\" in").unwrap();
    writeln!(script, "  --version) exit 0 ;;").unwrap();
    writeln!(script, "  build) printf '%s\\n' \"built:$4\"; exit 0 ;;").unwrap();
    writeln!(
        script,
        "  network) if [ \"$2\" = create ]; then printf '%s\\n' \"network:$3\"; exit 0; fi; exit 0 ;;"
    )
    .unwrap();
    writeln!(script, "  run)").unwrap();
    writeln!(script, "    container_name=\"${{4:-container}}\"").unwrap();
    writeln!(
        script,
        "    if [ \"$mode\" = run-fails ]; then printf '%s\\n' 'run failed' >&2; exit 42; fi"
    )
    .unwrap();
    writeln!(script, "    case \" $* \" in").unwrap();
    writeln!(script, "      *' --rm '*)").unwrap();
    // bench-smoke probe container: emit a canned capability report and exit
    // before the download/search simulation (there is no synthetic file).
    writeln!(script, "        case \" $* \" in").unwrap();
    writeln!(script, "          *' ed2k server probe '*)").unwrap();
    writeln!(
        script,
        "            printf '%s\\n' 'probe_endpoint: 203.0.113.2:4661'"
    )
    .unwrap();
    writeln!(
        script,
        "            printf '%s\\n' 'login_accepted: true client_id=123'"
    )
    .unwrap();
    writeln!(script, "            printf '%s\\n' 'tcp_flags: 0x00000003'").unwrap();
    writeln!(
        script,
        "            printf '%s\\n' 'srv_tcpflg_compression: true'"
    )
    .unwrap();
    writeln!(
        script,
        "            printf '%s\\n' 'compression_advert: YES'"
    )
    .unwrap();
    writeln!(
        script,
        "            printf '%s\\n' 'plain_ping[tcp+0=4661]: udp_flags=0x00000123'"
    )
    .unwrap();
    writeln!(
        script,
        "            printf '%s\\n' 'plain_ping[tcp+0=4661]: srv_udpflg_udpobfuscation=false'"
    )
    .unwrap();
    writeln!(
        script,
        "            printf '%s\\n' 'crypt_ping[tcp+12=4673]: no-reply'"
    )
    .unwrap();
    writeln!(
        script,
        "            printf '%s\\n' 'crypt_ping_answered: false'"
    )
    .unwrap();
    writeln!(script, "            printf '%s\\n' 'crypt_advert: NO'").unwrap();
    writeln!(script, "            exit 0 ;;").unwrap();
    writeln!(script, "        esac").unwrap();
    writeln!(script, "        original_args=\"$*\"").unwrap();
    writeln!(
        script,
        "        case \" $original_args \" in *' cargo build '*) exit 0 ;; esac"
    )
    .unwrap();
    writeln!(script, "        run_root=''").unwrap();
    writeln!(script, "        while [ \"$#\" -gt 0 ]; do").unwrap();
    writeln!(script, "          if [ \"$1\" = -v ]; then").unwrap();
    writeln!(script, "            shift").unwrap();
    writeln!(script, "            case \"$1\" in").unwrap();
    writeln!(
        script,
        "              *:/interop-run) run_root=${{1%:/interop-run}} ;;"
    )
    .unwrap();
    writeln!(script, "            esac").unwrap();
    writeln!(script, "          fi").unwrap();
    writeln!(script, "          shift || true").unwrap();
    writeln!(script, "        done").unwrap();
    writeln!(
        script,
        "        cp \"$run_root/synthetic/shared.bin\" \"$run_root/rmule/output.bin\""
    )
    .unwrap();
    writeln!(script, "        case \" $original_args \" in").unwrap();
    writeln!(script, "          *' ed2k search '*)").unwrap();
    writeln!(script, "            printf '%s\\n' 'search_started id=1'").unwrap();
    writeln!(
        script,
        "            printf '%s\\n' '0: file_hash=fakehash size=65536 primary_name=shared.bin source_count=1'"
    )
    .unwrap();
    writeln!(
        script,
        "            printf '%s\\n' 'search_completed id=1 total=1'"
    )
    .unwrap();
    writeln!(script, "            exit 0 ;;").unwrap();
    writeln!(script, "        esac").unwrap();
    writeln!(
        script,
        "        printf '%s\\n' 'download.sources_found id=1 total=1 usable_high_id=1'"
    )
    .unwrap();
    writeln!(
        script,
        "        printf '%s\\n' 'download.peer_selected id=1 peer=rmule-interop-amule:4662'"
    )
    .unwrap();
    writeln!(
        script,
        "        printf '%s\\n' 'download.part_verified id=1 part_index=0'"
    )
    .unwrap();
    writeln!(script, "        printf '%s\\n' 'download.completed id=1'").unwrap();
    writeln!(
        script,
        "        printf '%s\\n' 'download finalized id=1 path=/interop-run/rmule/output.bin'"
    )
    .unwrap();
    writeln!(script, "        exit 0 ;;").unwrap();
    writeln!(script, "    esac").unwrap();
    writeln!(script, "    case \" $* \" in").unwrap();
    writeln!(script, "      *' AMULE_DOWNLOAD_LINK='*)").unwrap();
    writeln!(script, "        amule_root=''").unwrap();
    writeln!(script, "        while [ \"$#\" -gt 0 ]; do").unwrap();
    writeln!(script, "          if [ \"$1\" = -v ]; then").unwrap();
    writeln!(script, "            shift").unwrap();
    writeln!(script, "            case \"$1\" in").unwrap();
    writeln!(
        script,
        "              *:/incoming) amule_root=${{1%:/incoming}} ;;"
    )
    .unwrap();
    writeln!(script, "            esac").unwrap();
    writeln!(script, "          fi").unwrap();
    writeln!(script, "          shift || true").unwrap();
    writeln!(script, "        done").unwrap();
    writeln!(
        script,
        "        cp \"$amule_root/../synthetic/shared.bin\" \"$amule_root/shared.bin\""
    )
    .unwrap();
    writeln!(script, "        ;;").unwrap();
    writeln!(script, "    esac").unwrap();
    writeln!(script, "    printf '%s\\n' \"container:$container_name\"").unwrap();
    writeln!(script, "    exit 0 ;;").unwrap();
    writeln!(script, "  logs) if [ \"$mode\" = logs-fail ]; then printf '%s\\n' 'logs failed' >&2; exit 43; fi; if [ \"$mode\" = amule-ready ] && printf '%s' \"$2\" | grep -q 'amule'; then printf '%s\\n' 'custom-amule-ready'; exit 0; fi; if [ \"$mode\" = reverse-ready ] && printf '%s' \"$2\" | grep -q 'amule'; then printf '%s\\n' 'rmule-amule-download-complete'; exit 0; fi; if [ \"$mode\" = reverse-ready ] && printf '%s' \"$2\" | grep -q 'rmule-interop-rmule'; then printf '%s\\n' 'serve.files_announced file_count=1'; exit 0; fi; printf '%s\\n' \"logs:$2\"; exit 0 ;;").unwrap();
    writeln!(script, "  inspect) printf '%s\\n' '172.18.0.3'; exit 0 ;;").unwrap();
    writeln!(script, "  rm) exit 0 ;;").unwrap();
    writeln!(script, "esac").unwrap();
    writeln!(script, "exit 0").unwrap();
    drop(script);
    make_executable(&path);
    path
}

/// ED2K hash command for the Kad flow. Unlike `fake_hash_command` (whose
/// `fakehash` placeholder the eD2k tests assert on), this emits a real 32-hex
/// file hash so the harness can parse it and derive the storer's Kad ID. The
/// hash matches the `kad_seed` unit-test vector so `expected_storer_kad_id`
/// is the known on-wire target.
pub(crate) fn fake_kad_hash_command(dir: &Path) -> PathBuf {
    let path = dir.join("fake-kad-hash");
    let mut script = std::fs::File::create(&path).unwrap();
    writeln!(script, "#!/bin/sh").unwrap();
    writeln!(
        script,
        "printf '%s\\n' 'canonical_link: ed2k://|file|shared.bin|65536|{KAD_FILE_HASH_HEX}|/'"
    )
    .unwrap();
    drop(script);
    make_executable(&path);
    path
}

pub(crate) fn fake_rmule_tools(dir: &Path) -> PathBuf {
    let path = dir.join("fake-rmule-tools");
    let mut script = std::fs::File::create(&path).unwrap();
    writeln!(script, "#!/bin/sh").unwrap();
    writeln!(script, "set -eu").unwrap();
    writeln!(script, "out=''").unwrap();
    writeln!(script, "while [ \"$#\" -gt 0 ]; do").unwrap();
    writeln!(
        script,
        "  if [ \"$1\" = --out ]; then shift; out=\"$1\"; fi"
    )
    .unwrap();
    writeln!(script, "  shift || true").unwrap();
    writeln!(script, "done").unwrap();
    writeln!(
        script,
        "cp \"{}\" \"$out\"",
        dir.join("shared.bin").display()
    )
    .unwrap();
    writeln!(
        script,
        "printf '%s\\n' 'download.sources_found id=1 total=1 usable_high_id=1'"
    )
    .unwrap();
    writeln!(
        script,
        "printf '%s\\n' 'download.peer_selected id=1 peer=127.0.0.1:4662'"
    )
    .unwrap();
    writeln!(
        script,
        "printf '%s\\n' 'download.part_verified id=1 part_index=0'"
    )
    .unwrap();
    writeln!(script, "printf '%s\\n' 'download.completed id=1'").unwrap();
    writeln!(
        script,
        "printf '%s\\n' \"download finalized id=1 path=$out\""
    )
    .unwrap();
    drop(script);

    std::fs::write(dir.join("shared.bin"), deterministic_bytes(65536)).unwrap();
    make_executable(&path);
    path
}
