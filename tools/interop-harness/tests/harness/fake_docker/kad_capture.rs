//! The Kad source-lookup capture, phase by phase: the private capture topology,
//! the seeded identities and bootstrap contacts every node starts from, the
//! publish window, and the conservative candidate summary.

use crate::fake_docker::script::{fake_kad_docker, fake_kad_hash_command};
use crate::fixture::{
    assert_ordered, env_value, expected_storer_kad_id, hex, run_dirs, run_fake_kad_capture,
};

#[test]
fn kad_source_lookup_phase1_orchestrates_private_capture() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_kad_docker(fake_bin.path(), &docker_log);
    let hash_command = fake_kad_hash_command(fake_bin.path());

    run_fake_kad_capture(
        &docker,
        &hash_command,
        run_root.path(),
        &["--routing-nodes", "0"],
    );

    let log = std::fs::read_to_string(&docker_log).unwrap();
    assert_ordered(
        &log,
        &[
            "--version".to_owned(),
            "network create --subnet 172.30.0.0/24 rmule-interop-kad-".to_owned(),
            // Hub topology: the storer is started first and must report Kad-ready
            // (logs) before the publisher and requester — which bootstrap to it —
            // are started.
            "run --detach --name rmule-interop-kad-storer-".to_owned(),
            "-e AMULE_SCENARIO_MODE=kad-node".to_owned(),
            "-e AMULE_KAD_ROLE=routing".to_owned(),
            "logs rmule-interop-kad-storer-".to_owned(),
            "run --detach --name rmule-interop-kad-publisher-".to_owned(),
            "-e AMULE_KAD_ROLE=publisher".to_owned(),
            "run --detach --name rmule-interop-kad-requester-".to_owned(),
            "-e AMULE_KAD_ROLE=requester".to_owned(),
            "logs rmule-interop-kad-publisher-".to_owned(),
            "logs rmule-interop-kad-requester-".to_owned(),
            "run --detach --name rmule-interop-kad-capture-".to_owned(),
            "--network container:rmule-interop-kad-requester-".to_owned(),
            "--cap-add NET_RAW".to_owned(),
            "--cap-add NET_ADMIN".to_owned(),
            "tcpdump -i eth0 --immediate-mode -U -s 0 -B 65536 -w /capture/kad.pcap".to_owned(),
            "port 4672 or portrange 4672-4682".to_owned(),
            "exec rmule-interop-kad-requester-".to_owned(),
            "rm -f rmule-interop-kad-capture-".to_owned(),
            "network rm rmule-interop-kad-".to_owned(),
        ],
    );

    // No extra Phase 2 routing nodes when --routing-nodes 0 (the storer is
    // separate and not labelled "routing-N").
    assert!(
        !log.contains("rmule-interop-kad-routing-"),
        "phase 1 should not start routing-N nodes:\n{log}"
    );

    let runs = run_dirs(run_root.path());
    assert_eq!(runs.len(), 1);
    let run = &runs[0];
    assert!(run.join("synthetic/shared.bin").is_file());
    assert!(run.join("synthetic/shared.ed2k.txt").is_file());
    assert!(run.join("capture/kad/kad.pcap").is_file());
    assert!(run.join("kad/endpoints.toml").is_file());

    let endpoints = std::fs::read_to_string(run.join("kad/endpoints.toml")).unwrap();
    assert!(endpoints.contains("role = \"publisher\""), "{endpoints}");
    assert!(endpoints.contains("role = \"requester\""), "{endpoints}");
    assert!(endpoints.contains("role = \"storer\""), "{endpoints}");
    // Each node records the port plan; the requester is one above the publisher
    // and the storer one above that (the deterministic static-IP plan reflects
    // these as 172.30.0.2/.3/.4 in the seeded nodes.dat, asserted separately).
    assert!(endpoints.contains("udp_port = 4672"), "{endpoints}");
    assert!(endpoints.contains("udp_port = 4674"), "{endpoints}");

    let summary = std::fs::read_to_string(run.join("kad/candidate-summary.toml")).unwrap();
    assert!(summary.contains("scenario = \"kad-source-lookup-capture\""));
    assert!(summary.contains("phase1_attempted = true"));
    assert!(summary.contains("phase2_attempted = false"));
    assert!(summary.contains("public_kad_used = false"));
    assert!(summary.contains("source_lookup_result_observed = false"));
    assert!(summary.contains("routing_order_observed = false"));

    // Per-node logs land under logs/kad/<role>/, not the eD2k logs/amule path.
    assert!(run.join("logs/kad/publisher/stdout.log").is_file());
    assert!(run.join("logs/kad/requester/stdout.log").is_file());
    assert!(run.join("logs/kad/storer/stdout.log").is_file());
}

#[test]
fn phase1_starts_publisher_requester_and_storer() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_kad_docker(fake_bin.path(), &docker_log);
    let hash_command = fake_kad_hash_command(fake_bin.path());

    run_fake_kad_capture(
        &docker,
        &hash_command,
        run_root.path(),
        &["--routing-nodes", "0"],
    );

    let log = std::fs::read_to_string(&docker_log).unwrap();
    for needle in [
        "run --detach --name rmule-interop-kad-publisher-",
        "run --detach --name rmule-interop-kad-requester-",
        "run --detach --name rmule-interop-kad-storer-",
    ] {
        assert!(log.contains(needle), "missing `{needle}` in:\n{log}");
    }

    // The storer joins as a routing-role node (no share, no download) but with a
    // distinct container so it can carry the file-hash-derived Kad ID.
    let storer_run = log
        .lines()
        .find(|line| line.contains("run --detach --name rmule-interop-kad-storer-"))
        .expect("storer run command");
    assert!(
        storer_run.contains("-e AMULE_KAD_ROLE=routing"),
        "storer runs in routing role:\n{storer_run}"
    );

    // The storer's seeded Kad ID equals the file-hash-derived on-wire target for
    // the known fake hash `fakehash` is not hex; the deterministic hash command
    // here returns a real 32-hex hash so the derivation is computable.
    let runs = run_dirs(run_root.path());
    let storer_prefs = std::fs::read(runs[0].join("kad/seed/storer/preferencesKad.dat")).unwrap();
    assert_eq!(storer_prefs.len(), 23);
    assert_eq!(
        &storer_prefs[6..22],
        &expected_storer_kad_id(),
        "storer seed carries the file-hash-derived Kad ID at offset 6"
    );

    // The nodes summary records the seeded storer Kad ID for cross-checking.
    let nodes = std::fs::read_to_string(runs[0].join("kad/nodes.toml")).unwrap();
    assert!(nodes.contains("role = \"storer\""), "{nodes}");
    assert!(
        nodes.contains(&format!("kad_id = \"{}\"", hex(&expected_storer_kad_id()))),
        "{nodes}"
    );
}

#[test]
fn kad_nodes_receive_seeded_preferences_kad_dat() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_kad_docker(fake_bin.path(), &docker_log);
    let hash_command = fake_kad_hash_command(fake_bin.path());

    run_fake_kad_capture(
        &docker,
        &hash_command,
        run_root.path(),
        &["--routing-nodes", "0"],
    );

    let runs = run_dirs(run_root.path());
    // Every node gets a 23-byte preferencesKad.dat with its Kad ID at offset 6.
    for role in ["publisher", "requester", "storer"] {
        let prefs =
            std::fs::read(runs[0].join(format!("kad/seed/{role}/preferencesKad.dat"))).unwrap();
        assert_eq!(prefs.len(), 23, "{role} prefs is 23 bytes");
    }

    // The env points each node at its mounted seed file.
    let log = std::fs::read_to_string(&docker_log).unwrap();
    let publisher_run = log
        .lines()
        .find(|line| line.contains("run --detach --name rmule-interop-kad-publisher-"))
        .unwrap();
    assert!(
        publisher_run.contains("-e AMULE_KAD_PREFS_DAT=/seed/preferencesKad.dat"),
        "{publisher_run}"
    );
    assert!(
        publisher_run.contains("-v ") && publisher_run.contains(":/seed"),
        "seed dir is mounted at /seed:\n{publisher_run}"
    );
    // Distinct seeded IDs: publisher and requester differ from the storer.
    let publisher_prefs =
        std::fs::read(runs[0].join("kad/seed/publisher/preferencesKad.dat")).unwrap();
    let requester_prefs =
        std::fs::read(runs[0].join("kad/seed/requester/preferencesKad.dat")).unwrap();
    assert_ne!(&publisher_prefs[6..22], &requester_prefs[6..22]);
    assert_ne!(
        &publisher_prefs[6..22],
        &expected_storer_kad_id(),
        "publisher Kad ID is not the storer's hash-derived ID"
    );
}

#[test]
fn publisher_user_hash_is_known_and_distinct_from_kad_id() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_kad_docker(fake_bin.path(), &docker_log);
    let hash_command = fake_kad_hash_command(fake_bin.path());

    run_fake_kad_capture(
        &docker,
        &hash_command,
        run_root.path(),
        &["--routing-nodes", "0"],
    );

    let log = std::fs::read_to_string(&docker_log).unwrap();
    let publisher_run = log
        .lines()
        .find(|line| line.contains("run --detach --name rmule-interop-kad-publisher-"))
        .unwrap();
    let user_hash = env_value(publisher_run, "AMULE_USER_HASH");
    assert_eq!(user_hash.len(), 32, "16-byte hash as hex");
    assert!(
        user_hash.bytes().all(|b| b.is_ascii_hexdigit()),
        "user hash is hex: {user_hash}"
    );

    // Only the publisher carries a User Hash; requester and storer do not.
    let runs = run_dirs(run_root.path());
    let publisher_prefs =
        std::fs::read(runs[0].join("kad/seed/publisher/preferencesKad.dat")).unwrap();
    assert_ne!(
        user_hash,
        hex(&publisher_prefs[6..22]),
        "User Hash is distinct from the publisher Kad ID"
    );
    for other in ["requester", "storer"] {
        let other_run = log
            .lines()
            .find(|line| line.contains(&format!("run --detach --name rmule-interop-kad-{other}-")))
            .unwrap();
        assert!(
            !other_run.contains("AMULE_USER_HASH="),
            "{other} must not carry a User Hash:\n{other_run}"
        );
    }
}

#[test]
fn kad_nodes_are_seeded_with_bootstrap_nodes_dat() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_kad_docker(fake_bin.path(), &docker_log);
    let hash_command = fake_kad_hash_command(fake_bin.path());

    run_fake_kad_capture(
        &docker,
        &hash_command,
        run_root.path(),
        &["--routing-nodes", "0"],
    );

    let runs = run_dirs(run_root.path());
    // Hub topology: the publisher's nodes.dat is a v3/edition-1 bootstrap file
    // naming its single peer — the storer (the rendezvous hub) — by its static IP
    // in reversed-octet order.
    let nodes_dat = std::fs::read(runs[0].join("kad/seed/publisher/nodes.dat")).unwrap();
    assert_eq!(&nodes_dat[0..4], &[0, 0, 0, 0], "zero marker");
    assert_eq!(&nodes_dat[4..8], &3u32.to_le_bytes(), "version 3");
    assert_eq!(&nodes_dat[8..12], &1u32.to_le_bytes(), "edition 1");
    assert_eq!(
        &nodes_dat[12..16],
        &1u32.to_le_bytes(),
        "one bootstrap peer: the storer hub"
    );
    // The single peer is the storer at 172.30.0.4 (reversed octets 04 00 1e ac).
    assert_eq!(&nodes_dat[16..32], &expected_storer_kad_id());
    assert_eq!(&nodes_dat[32..36], &[0x04, 0x00, 0x1e, 0xac]);

    // The storer is the hub: it bootstraps to nobody, so its nodes.dat is just the
    // 16-byte header with a zero contact count.
    let storer_nodes_dat = std::fs::read(runs[0].join("kad/seed/storer/nodes.dat")).unwrap();
    assert_eq!(
        storer_nodes_dat.len(),
        16,
        "storer nodes.dat is header-only"
    );
    assert_eq!(
        &storer_nodes_dat[12..16],
        &0u32.to_le_bytes(),
        "hub storer has zero bootstrap peers"
    );

    let log = std::fs::read_to_string(&docker_log).unwrap();
    let publisher_run = log
        .lines()
        .find(|line| line.contains("run --detach --name rmule-interop-kad-publisher-"))
        .unwrap();
    assert!(
        publisher_run.contains("-e AMULE_KAD_NODES_DAT=/seed/nodes.dat"),
        "{publisher_run}"
    );
}

#[test]
fn kad_source_lookup_phase2_starts_routing_nodes() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_kad_docker(fake_bin.path(), &docker_log);
    let hash_command = fake_kad_hash_command(fake_bin.path());

    run_fake_kad_capture(
        &docker,
        &hash_command,
        run_root.path(),
        &["--routing-nodes", "3"],
    );

    let log = std::fs::read_to_string(&docker_log).unwrap();
    // Publisher, requester, storer, and three routing nodes are all harness-owned.
    for needle in [
        "run --detach --name rmule-interop-kad-publisher-",
        "run --detach --name rmule-interop-kad-requester-",
        "run --detach --name rmule-interop-kad-storer-",
        "run --detach --name rmule-interop-kad-routing-1-",
        "run --detach --name rmule-interop-kad-routing-2-",
        "run --detach --name rmule-interop-kad-routing-3-",
    ] {
        assert!(log.contains(needle), "missing `{needle}` in:\n{log}");
    }
    // Capture still attaches to the requester namespace.
    assert!(
        log.contains("--network container:rmule-interop-kad-requester-"),
        "{log}"
    );
    assert!(
        log.contains("-e AMULE_KAD_ROLE=routing"),
        "routing nodes run in routing role:\n{log}"
    );

    let runs = run_dirs(run_root.path());
    assert_eq!(runs.len(), 1);
    let summary = std::fs::read_to_string(runs[0].join("kad/candidate-summary.toml")).unwrap();
    assert!(summary.contains("phase2_attempted = true"), "{summary}");
    assert!(summary.contains("routing_node_count = 3"), "{summary}");
}

#[test]
fn kad_capture_waits_publish_window_then_searches() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_kad_docker(fake_bin.path(), &docker_log);
    let hash_command = fake_kad_hash_command(fake_bin.path());

    run_fake_kad_capture(
        &docker,
        &hash_command,
        run_root.path(),
        &["--routing-nodes", "0"],
    );

    let log = std::fs::read_to_string(&docker_log).unwrap();
    // The hub storer reports ready first, then the publisher and requester; all
    // must be Kad-ready (logs polled) before the capture sidecar starts, and the
    // search only fires after capture is up. The publish window sits between
    // readiness and capture; fake-docker only checks the ordering, not the wait.
    assert_ordered(
        &log,
        &[
            "logs rmule-interop-kad-storer-".to_owned(),
            "logs rmule-interop-kad-publisher-".to_owned(),
            "logs rmule-interop-kad-requester-".to_owned(),
            "run --detach --name rmule-interop-kad-capture-".to_owned(),
            "exec rmule-interop-kad-requester-".to_owned(),
        ],
    );
    // The search is fired by Cancel + re-Add of the synthetic ED2K link (a bare
    // Add is gated by aMule's per-file Kad search timer); both run on the requester.
    assert!(
        log.contains(" Cancel ") && log.contains(" Add ed2k://|file|"),
        "trigger must cancel then re-add the download:\n{log}"
    );
}

#[test]
fn kad_candidate_summary_stays_conservative_until_promotion() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_kad_docker(fake_bin.path(), &docker_log);
    let hash_command = fake_kad_hash_command(fake_bin.path());

    run_fake_kad_capture(&docker, &hash_command, run_root.path(), &[]);

    let runs = run_dirs(run_root.path());
    assert_eq!(runs.len(), 1);
    // A fake pcap exists, but the summary must never claim observed evidence or
    // self-promote: manual inspection is still required.
    assert!(runs[0].join("capture/kad/kad.pcap").is_file());
    let summary = std::fs::read_to_string(runs[0].join("kad/candidate-summary.toml")).unwrap();
    assert!(
        summary.contains("source_lookup_result_observed = false"),
        "{summary}"
    );
    assert!(
        summary.contains("routing_order_observed = false"),
        "{summary}"
    );
    assert!(summary.contains("promotion_required = true"), "{summary}");
}

#[test]
fn kad_candidate_summary_records_controlled_identities() {
    let run_root = tempfile::tempdir().unwrap();
    let fake_bin = tempfile::tempdir().unwrap();
    let docker_log = run_root.path().join("docker.log");
    let docker = fake_kad_docker(fake_bin.path(), &docker_log);
    let hash_command = fake_kad_hash_command(fake_bin.path());

    run_fake_kad_capture(&docker, &hash_command, run_root.path(), &[]);

    let runs = run_dirs(run_root.path());
    let summary = std::fs::read_to_string(runs[0].join("kad/candidate-summary.toml")).unwrap();
    // The storer Kad ID equals the file-hash-derived on-wire target.
    assert!(
        summary.contains(&format!(
            "storer_kad_id = \"{}\"",
            hex(&expected_storer_kad_id())
        )),
        "{summary}"
    );
    // Publisher Kad ID and User Hash are both recorded and are distinct, so a
    // human can resolve which the captured 0x3B source-row id matches.
    let publisher_kad_id = summary
        .lines()
        .find_map(|line| line.strip_prefix("publisher_kad_id = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .expect("publisher_kad_id recorded");
    let publisher_user_hash = summary
        .lines()
        .find_map(|line| line.strip_prefix("publisher_user_hash = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .expect("publisher_user_hash recorded");
    assert_eq!(publisher_kad_id.len(), 32);
    assert_eq!(publisher_user_hash.len(), 32);
    assert_ne!(
        publisher_kad_id, publisher_user_hash,
        "publisher Kad ID and User Hash must be distinct"
    );
    assert!(
        summary.contains("expected_source_row_identity = \"publisher_kad_id_or_user_hash\""),
        "{summary}"
    );
    // Still conservative.
    assert!(
        summary.contains("source_lookup_result_observed = false"),
        "{summary}"
    );
    assert!(summary.contains("promotion_required = true"), "{summary}");
}
