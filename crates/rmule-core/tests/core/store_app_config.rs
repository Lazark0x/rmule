//! The [`AppConfigStore`] ⊃ [`ServerListStore`] contract against the durable
//! implementation (ADR-0083): the generate-once minting, what a Core
//! Settings edit to the identity rows may and may not disturb, the managed list's fold and
//! its mutators' `false`, and what all of it looks like after a restart.
//!
//! Every contract assertion runs on both backends the one implementation
//! ships on — the engine's in-memory backend and a real file — because they are
//! the same code over a different `StorageBackend`, and a leg that only ever
//! saw memory would not notice a record that fails to round-trip through
//! bytes. The restart legs are file-only by definition.

use rmule_core::{
    AppConfigStore, CoreSettingsHandle, DurableAppConfig, ManagedServer, Preference,
    ServerListStore, ServerMerge, ServerPriority, Setting,
};
use rmule_primitives::{Ed2kText, ServerEndpoint};

use crate::fixture::{file_config_store, memory_config_store, open_store};

/// Run one contract assertion against both backends.
fn on_both_backends(assert: impl Fn(&DurableAppConfig)) {
    assert(&memory_config_store());
    let dir = tempfile::tempdir().unwrap();
    assert(&file_config_store(dir.path()));
}

fn endpoint(host: &str, port: u16) -> ServerEndpoint {
    ServerEndpoint::new(host, port).expect("valid endpoint")
}

// ---- generate-once identity material ---------------------------------------

#[test]
fn ensure_identity_is_generate_once_stable() {
    on_both_backends(|store| {
        let first = store.ensure_identity().unwrap();
        let second = store.ensure_identity().unwrap();
        assert_eq!(first.user_hash(), second.user_hash());
        assert_eq!(first.nickname().as_bytes(), b"rmule");
        assert_eq!(first.tcp_port(), rmule_core::DEFAULT_TCP_PORT);
        assert_eq!(
            first.protocol_version(),
            rmule_core::DEFAULT_PROTOCOL_VERSION
        );
        let bytes = first.user_hash();
        assert_eq!(bytes.as_bytes()[5], 14, "eMule client marker at byte 5");
        assert_eq!(bytes.as_bytes()[14], 111, "eMule client marker at byte 14");
    });
}

#[test]
fn ensure_kad_identity_is_generate_once_stable() {
    on_both_backends(|store| {
        let first = store.ensure_kad_identity().unwrap();
        let second = store.ensure_kad_identity().unwrap();
        assert_eq!(first, second);
        assert_eq!(first.udp_port, rmule_core::DEFAULT_UDP_PORT);
        assert_ne!(
            first.id.as_bytes(),
            store.ensure_identity().unwrap().user_hash().as_bytes(),
            "the Kad ID is random, never derived from the User Hash"
        );
    });
}

#[test]
fn ensure_secure_ident_key_is_generate_once_stable() {
    on_both_backends(|store| {
        let first = store.ensure_secure_ident_key().unwrap();
        let second = store.ensure_secure_ident_key().unwrap();
        // The same keypair: deterministic PKCS1v15 signatures match.
        assert_eq!(first.sign(b"challenge"), second.sign(b"challenge"));
    });
}

/// Nothing minted is shared between two stores: each draws its own entropy.
#[test]
fn fresh_stores_mint_distinct_identity_material() {
    let (a, b) = (memory_config_store(), memory_config_store());
    assert_ne!(
        a.ensure_identity().unwrap().user_hash(),
        b.ensure_identity().unwrap().user_hash()
    );
    assert_ne!(
        a.ensure_kad_identity().unwrap().id,
        b.ensure_kad_identity().unwrap().id
    );
    assert_ne!(
        a.ensure_secure_ident_key().unwrap().public_key_der(),
        b.ensure_secure_ident_key().unwrap().public_key_der()
    );
}

// ---- preferences ------------------------------------------------------------

/// The three answers a settings read defaults through: unset, set, and
/// replaced — and the keys are distinct, so one edit cannot shadow another.
#[test]
fn preferences_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    for opened in [rmule_testkit::memory_store(), open_store(dir.path())] {
        let store = DurableAppConfig::new(opened.clone());
        let settings = CoreSettingsHandle::open(opened);
        assert_eq!(store.preference(Preference::ServerMetUrl).unwrap(), None);
        for url in ["http://a.example/server.met", "http://b.example/server.met"] {
            settings.set(Setting::ServerMetUrl(url.to_owned())).unwrap();
        }
        assert_eq!(
            store
                .preference(Preference::ServerMetUrl)
                .unwrap()
                .as_deref(),
            Some("http://b.example/server.met")
        );
        assert_eq!(store.preference(Preference::NodesDatUrl).unwrap(), None);
    }
}

// ---- the managed server list -----------------------------------------------

#[test]
fn servers_fold_duplicates_and_preserve_insertion_order() {
    on_both_backends(|store| {
        let (a, b) = (endpoint("1.2.3.4", 4661), endpoint("5.6.7.8", 4242));
        assert_eq!(
            store
                .merge_server(ManagedServer::listed(a.clone()))
                .unwrap(),
            ServerMerge::Added
        );
        store
            .merge_server(ManagedServer::listed(b.clone()))
            .unwrap();
        assert_eq!(
            store
                .merge_server(ManagedServer::listed(a.clone()))
                .unwrap(),
            ServerMerge::Updated
        );
        let endpoints: Vec<_> = store
            .servers()
            .unwrap()
            .into_iter()
            .map(|server| server.endpoint)
            .collect();
        assert_eq!(endpoints, vec![a, b]);
    });
}

/// A removal frees the endpoint for a later row, and the freed row does not
/// come back ahead of what was appended after it.
#[test]
fn a_re_added_endpoint_lands_at_the_end_of_the_list() {
    on_both_backends(|store| {
        let (a, b) = (endpoint("1.2.3.4", 4661), endpoint("5.6.7.8", 4242));
        store
            .merge_server(ManagedServer::listed(a.clone()))
            .unwrap();
        store
            .merge_server(ManagedServer::listed(b.clone()))
            .unwrap();
        assert!(store.remove_server(&a).unwrap());
        assert_eq!(
            store
                .merge_server(ManagedServer::listed(a.clone()))
                .unwrap(),
            ServerMerge::Added,
            "the endpoint index released the removed row"
        );
        let endpoints: Vec<_> = store
            .servers()
            .unwrap()
            .into_iter()
            .map(|server| server.endpoint)
            .collect();
        assert_eq!(endpoints, vec![b, a]);
    });
}

#[test]
fn mutators_report_whether_the_row_existed() {
    on_both_backends(|store| {
        let (listed, absent) = (endpoint("1.2.3.4", 4661), endpoint("9.9.9.9", 4661));
        store
            .merge_server(ManagedServer::listed(listed.clone()))
            .unwrap();

        assert!(
            store
                .set_server_priority(&listed, ServerPriority::Low)
                .unwrap()
        );
        assert!(store.set_server_static(&listed, true).unwrap());
        assert!(store.set_server_fail_count(&listed, 3).unwrap());
        assert!(
            !store
                .set_server_priority(&absent, ServerPriority::Low)
                .unwrap()
        );
        assert!(!store.set_server_static(&absent, true).unwrap());
        assert!(!store.set_server_fail_count(&absent, 3).unwrap());
        assert!(!store.remove_server(&absent).unwrap());

        let row = &store.servers().unwrap()[0];
        assert_eq!(row.priority, ServerPriority::Low);
        assert!(row.is_static);
        assert_eq!(row.fail_count, 3);

        assert!(store.remove_server(&listed).unwrap());
        assert!(store.servers().unwrap().is_empty());
    });
}

/// The counting half of the failure tally is the store's own step: it reads
/// the row and writes it in one transaction, so two counts are two, and an
/// endpoint the list does not hold is reported rather than invented.
#[test]
fn counting_a_server_failure_increments_the_row_it_finds() {
    on_both_backends(|store| {
        let (listed, absent) = (endpoint("1.2.3.4", 4661), endpoint("9.9.9.9", 4661));
        store
            .merge_server(ManagedServer::listed(listed.clone()))
            .unwrap();

        assert!(store.count_server_failure(&listed).unwrap());
        assert!(store.count_server_failure(&listed).unwrap());
        assert_eq!(store.servers().unwrap()[0].fail_count, 2);

        // Absolution is still the `set_*` half, and it resets what the counts
        // built up.
        assert!(store.set_server_fail_count(&listed, 0).unwrap());
        assert_eq!(store.servers().unwrap()[0].fail_count, 0);

        assert!(!store.count_server_failure(&absent).unwrap());
        assert_eq!(store.servers().unwrap().len(), 1);
    });
}

// ---- what a restart reads back ---------------------------------------------

/// The presentation half of the identity rows is editable and the minted half
/// is not: a nickname/port edit must leave the User Hash and the Kad ID
/// exactly where entropy put them, across a restart.
#[test]
fn editing_nickname_and_ports_never_disturbs_the_minted_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    let (minted, kad) = {
        let opened = open_store(path);
        let store = DurableAppConfig::new(opened.clone());
        let minted = store.ensure_identity().unwrap();
        let kad = store.ensure_kad_identity().unwrap();
        let settings = CoreSettingsHandle::open(opened);
        for setting in [
            Setting::Nickname("hübsch".to_owned()),
            Setting::TcpPort(4711),
            Setting::UdpPort(4722),
        ] {
            settings.set(setting).unwrap();
        }
        (minted, kad)
    };

    let reopened = file_config_store(path);
    let identity = reopened.ensure_identity().unwrap();
    assert_eq!(identity.nickname().to_display_string(), "hübsch");
    assert_eq!(identity.tcp_port(), 4711);
    assert_eq!(identity.user_hash(), minted.user_hash());
    assert_eq!(identity.protocol_version(), minted.protocol_version());
    let reopened_kad = reopened.ensure_kad_identity().unwrap();
    assert_eq!(reopened_kad.udp_port, 4722);
    assert_eq!(
        reopened_kad.id, kad.id,
        "a port move keeps the keyspace slot"
    );
}

/// The keypair and the preference table are the other two rows a restarted
/// session re-reads.
#[test]
fn secure_ident_key_and_preferences_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    let signature = {
        let opened = open_store(path);
        let store = DurableAppConfig::new(opened.clone());
        CoreSettingsHandle::open(opened)
            .set(Setting::DownloadDir {
                dir: dir.path().to_path_buf(),
                share_confirmed: false,
            })
            .unwrap();
        store.ensure_secure_ident_key().unwrap().sign(b"challenge")
    };

    let opened = open_store(path);
    let reopened = DurableAppConfig::new(opened.clone());
    assert_eq!(
        reopened
            .ensure_secure_ident_key()
            .unwrap()
            .sign(b"challenge"),
        signature,
        "the persisted keypair reproduces the same deterministic signature"
    );
    assert_eq!(
        CoreSettingsHandle::open(opened)
            .read()
            .unwrap()
            .download_dir
            .as_deref(),
        Some(dir.path())
    );
}

/// The Kad UDP Key is the seed every verify key a counterparty learned for us
/// derives from: minted once, it must come back unchanged after a restart, or
/// each learned key turns into a mismatch.
#[test]
fn the_kad_udp_key_is_minted_once_and_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let minted = file_config_store(dir.path()).ensure_kad_udp_key().unwrap();
    assert_eq!(
        file_config_store(dir.path()).ensure_kad_udp_key().unwrap(),
        minted
    );
}

/// Every field of the managed-server model survives the file, and the fold is
/// the durable store's too: a downloaded row renames and fills an empty
/// description, but never re-prioritises, unpins, or absolves.
#[test]
fn server_rows_round_trip_every_model_field_and_fold_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    let server = endpoint("1.2.3.4", 4661);
    {
        let store = file_config_store(path);
        store
            .merge_server(ManagedServer {
                endpoint: server.clone(),
                // Not UTF-8: a real server banner routinely is not
                // (ADR-0019), and the store must keep the bytes.
                name: Ed2kText::from_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
                description: Ed2kText::from_utf8("A described server"),
                priority: ServerPriority::High,
                is_static: true,
                fail_count: 0,
                figures: None,
                grants: None,
                udp_crypt: None,
                aux_ports: None,
                listed_udp_flags: None,
            })
            .unwrap();
        store.set_server_fail_count(&server, 5).unwrap();
    }

    let reopened = file_config_store(path);
    let rows = reopened.servers().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name.as_bytes(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(
        rows[0].description.to_display_string(),
        "A described server"
    );
    assert_eq!(rows[0].priority, ServerPriority::High);
    assert!(rows[0].is_static);
    assert_eq!(rows[0].fail_count, 5);

    reopened
        .merge_server(ManagedServer {
            endpoint: server.clone(),
            name: Ed2kText::from_utf8("Renamed"),
            description: Ed2kText::from_bytes(Vec::new()),
            priority: ServerPriority::Low,
            is_static: false,
            fail_count: 0,
            figures: None,
            grants: None,
            udp_crypt: None,
            aux_ports: None,
            listed_udp_flags: None,
        })
        .unwrap();
    let folded = &reopened.servers().unwrap()[0];
    assert_eq!(folded.name.to_display_string(), "Renamed");
    assert_eq!(folded.description.to_display_string(), "A described server");
    assert_eq!(folded.priority, ServerPriority::High);
    assert!(folded.is_static);
    assert_eq!(folded.fail_count, 5);

    assert!(reopened.remove_server(&server).unwrap());
    assert!(reopened.servers().unwrap().is_empty());
}
