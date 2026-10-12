//! The handle opened on the store alone: what a set persists, what it answers,
//! and what it refuses.

use std::path::PathBuf;

use rmule_net::peer::ObfuscationPolicy;

use super::*;

fn handle() -> (CoreSettingsHandle, Arc<DurableStore>) {
    let store = rmule_testkit::memory_store();
    (CoreSettingsHandle::open(Arc::clone(&store)), store)
}

/// A cold store reads as a fresh install runs: the minted identity's ports,
/// mapping on, the mirrors' defaults and both fetches on.
#[test]
fn a_cold_store_reads_as_a_fresh_install_runs() {
    let (settings, _store) = handle();
    assert_eq!(
        settings.read().expect("read"),
        CoreSettings {
            tcp_port: crate::DEFAULT_TCP_PORT,
            udp_port: crate::DEFAULT_UDP_PORT,
            ..CoreSettings::default()
        }
    );
}

/// Every key set on the store alone persists, reads back as set, and waits
/// for the next start: no core runs behind the handle to take it up.
#[test]
fn every_setting_set_on_the_store_alone_persists_for_the_next_start() {
    let (settings, _store) = handle();
    let dir = rmule_testkit::absolute_path("srv/rmule/incoming");
    let policy = ServerPolicy {
        dead_after: 7,
        withhold_from_related_search: true,
    };
    for setting in [
        Setting::DownloadDir {
            dir: dir.clone(),
            share_confirmed: false,
        },
        Setting::Nickname("  hübsch ".to_owned()),
        Setting::TcpPort(4711),
        Setting::UdpPort(4722),
        Setting::Obfuscation(Some(ObfuscationPolicy::Required)),
        Setting::PortMapping(PortMappingMode::Off),
        Setting::RememberPeers(RememberPeers::new(std::num::NonZeroU8::MIN)),
        Setting::DeadServerRetries(policy.dead_after),
        Setting::WithholdShares(policy.withhold_from_related_search),
        Setting::ServerMetUrl("http://mirror.example/server.met".to_owned()),
        Setting::AutoFetchServerMet(false),
        Setting::NodesDatUrl("http://mirror.example/nodes.dat".to_owned()),
        Setting::AutoFetchNodesDat(false),
    ] {
        assert_eq!(settings.set(setting), Ok(TakesEffect::NextStart));
    }
    assert_eq!(
        settings.read().expect("read"),
        CoreSettings {
            download_dir: Some(dir),
            nickname: "hübsch".to_owned(),
            tcp_port: 4711,
            udp_port: 4722,
            obfuscation: Some(ObfuscationPolicy::Required),
            port_mapping: PortMappingMode::Off,
            remember_peers: RememberPeers::new(std::num::NonZeroU8::MIN),
            server_policy: policy,
            server_met_url: "http://mirror.example/server.met".to_owned(),
            auto_fetch_server_met: false,
            nodes_dat_url: "http://mirror.example/nodes.dat".to_owned(),
            auto_fetch_nodes_dat: false,
        }
    );
}

/// A value the key cannot take is refused and nothing is written.
#[test]
fn a_value_the_key_cannot_take_is_refused_and_nothing_is_written() {
    let (settings, _store) = handle();
    let before = settings.read().expect("read");
    let file = tempfile::NamedTempFile::new().expect("a file");
    for (setting, refusal) in [
        (Setting::TcpPort(0), SettingRefusal::PortZero),
        (Setting::UdpPort(0), SettingRefusal::PortZero),
        (
            Setting::DeadServerRetries(0),
            SettingRefusal::DeadServerRetriesZero,
        ),
        (
            Setting::DownloadDir {
                dir: PathBuf::from("relative/dir"),
                share_confirmed: true,
            },
            SettingRefusal::DownloadDirNotAbsolute,
        ),
        (
            Setting::DownloadDir {
                dir: file.path().to_path_buf(),
                share_confirmed: true,
            },
            SettingRefusal::DownloadDirNotADirectory,
        ),
        (
            Setting::Nickname("  ".to_owned()),
            SettingRefusal::NicknameUnfit,
        ),
        (
            Setting::Nickname("a\u{7}b".to_owned()),
            SettingRefusal::NicknameUnfit,
        ),
        (
            Setting::ServerMetUrl(" ".to_owned()),
            SettingRefusal::UrlBlank,
        ),
    ] {
        assert_eq!(settings.set(setting), Err(SettingError::Refused(refusal)));
    }
    assert_eq!(settings.read().expect("read"), before);
}

/// A download directory the share guards refuse is refused at the set with
/// the add's reason (ADR-0101) — where it would be made, when it is not made
/// yet — and nothing is written: not the directory, not the confirm's yes.
#[test]
fn a_download_dir_the_share_guards_refuse_is_refused_with_their_reason() {
    let machine = tempfile::tempdir().expect("a machine");
    let home = std::fs::canonicalize(machine.path()).expect("canonical");
    let data = home.join(".local/share/rmule");
    std::fs::create_dir_all(&data).expect("the data directory");
    let store = rmule_testkit::memory_store();
    let settings = CoreSettingsHandle::open(Arc::clone(&store)).share_guards(ShareGuards {
        home: Some(home.clone()),
        data_dir: Some(data.clone()),
    });
    let registry = DurableSharedFileRegistry::new(store);
    let root = home.ancestors().last().expect("a root").to_path_buf();
    for (dir, guard) in [
        (home.clone(), DirectoryRefusal::HomeDirectory),
        (data.clone(), DirectoryRefusal::DataDirectory),
        (data.join("incoming/new"), DirectoryRefusal::DataDirectory),
        (home.join(".local"), DirectoryRefusal::HoldsDataDirectory),
        (root, DirectoryRefusal::FilesystemRoot),
    ] {
        assert_eq!(
            settings.set(Setting::DownloadDir {
                dir: dir.clone(),
                share_confirmed: true,
            }),
            Err(SettingError::Refused(SettingRefusal::DownloadDirRefused(
                guard
            ))),
            "{}",
            dir.display()
        );
        assert_eq!(registry.directory_answer(&dir), Ok(None));
    }
    assert_eq!(settings.read().expect("read").download_dir, None);
}

/// The ADR-0101 confirm's yes rides the download directory and is recorded,
/// so the scan of that directory asks nothing more; a set with no confirm
/// records nothing and leaves the guard to ask.
#[test]
fn a_confirmed_download_dir_records_the_share_answer() {
    let (settings, store) = handle();
    let registry = DurableSharedFileRegistry::new(store);
    let (confirmed, unconfirmed) = (
        rmule_testkit::absolute_path("srv/a"),
        rmule_testkit::absolute_path("srv/b"),
    );
    settings
        .set(Setting::DownloadDir {
            dir: confirmed.clone(),
            share_confirmed: true,
        })
        .expect("set");
    settings
        .set(Setting::DownloadDir {
            dir: unconfirmed.clone(),
            share_confirmed: false,
        })
        .expect("set");
    assert_eq!(registry.directory_answer(&confirmed), Ok(Some(true)));
    assert_eq!(registry.directory_answer(&unconfirmed), Ok(None));
}

/// A front end's own keys share the table under the names it gives them,
/// and core keeps them as given; a key of core's own is not the front end's
/// to write or read there.
#[test]
fn the_front_end_keeps_its_own_keys_and_cannot_reach_core_s() {
    let (settings, _store) = handle();
    assert_eq!(settings.front_end_value("theme"), Ok(None));
    settings.set_front_end_value("theme", "light").expect("set");
    settings.set_front_end_value("theme", "256").expect("set");
    assert_eq!(
        settings.front_end_value("theme"),
        Ok(Some("256".to_owned()))
    );

    settings
        .set(Setting::DeadServerRetries(4))
        .expect("a core key, through the door");
    assert_eq!(
        settings.set_front_end_value("dead_server_retries", "1"),
        Err(SettingError::Refused(SettingRefusal::CoreKey))
    );
    assert_eq!(settings.front_end_value("dead_server_retries"), Ok(None));
    assert_eq!(settings.read().expect("read").server_policy.dead_after, 4);
}
