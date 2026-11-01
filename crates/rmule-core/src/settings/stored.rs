//! Where each Core Setting is kept and how it is spelled there: the nickname
//! and the two ports in the identity rows, every other key as text in the
//! preferences table. The one place a stored spelling is read or written, so
//! no reader can drift from the writer.

use std::path::{Path, PathBuf};

use rmule_net::peer::ObfuscationPolicy;
use rmule_primitives::Ed2kText;

use super::{CoreSettings, FlagTable, Flags, Setting, SettingRefusal, flag_reads, flag_text};
use crate::app_config::{AppConfigStore, Preference};
use crate::directory_scan::guard_in_place;
use crate::port_mapping::PortMappingMode;
use crate::server_list::ServerPolicy;
use crate::store::app_config::DurableAppConfig;
use crate::{CoreError, RememberPeers, ShareGuards};

/// Every core-owned key as `store` holds it, defaults filling what is unset.
pub(super) fn read(store: &DurableAppConfig) -> Result<CoreSettings, CoreError> {
    let identity = store.ensure_identity()?;
    let kad = store.ensure_kad_identity()?;
    let text = |preference| store.preference(preference);
    Ok(CoreSettings {
        download_dir: text(Preference::DownloadDir)?.map(PathBuf::from),
        temp_dir: store.temp_dir()?,
        nickname: identity.nickname().to_display_string(),
        tcp_port: identity.tcp_port(),
        udp_port: kad.udp_port,
        obfuscation: parse_obfuscation(text(Preference::Obfuscation)?.as_deref()),
        // ADR-0086's Auto, unless the operator turned it off.
        port_mapping: if flag_reads(text(Preference::PortMapping)?.as_deref(), true) {
            PortMappingMode::Auto
        } else {
            PortMappingMode::Off
        },
        remember_peers: RememberPeers::parse(text(Preference::RememberPeers)?.as_deref()),
        server_policy: server_policy(store)?,
        server_met_url: text(Preference::ServerMetUrl)?
            .unwrap_or_else(|| rmule_bootstrap::DEFAULT_SERVER_MET_URL.to_owned()),
        server_met_auto_update_urls: text(Preference::ServerMetAutoUpdateUrls)?
            .map(|urls| urls.lines().map(str::to_owned).collect())
            .unwrap_or_default(),
        nodes_dat_url: text(Preference::NodesDatUrl)?
            .unwrap_or_else(|| rmule_bootstrap::DEFAULT_NODES_DAT_URL.to_owned()),
        flags: Flags::read(|key| store.value(key))?,
    })
}

/// The **Server Policy** `store` holds, defaults filling what is unset.
pub(super) fn server_policy(store: &DurableAppConfig) -> Result<ServerPolicy, CoreError> {
    Ok(ServerPolicy {
        dead_after: ServerPolicy::parse_dead_after(
            store.preference(Preference::DeadServerRetries)?.as_deref(),
        ),
        withhold_from_related_search: flag_reads(
            store
                .preference(Preference::WithholdSharesFromRelatedSearch)?
                .as_deref(),
            false,
        ),
    })
}

/// Refuse a value the key cannot take, before anything is written. The two
/// directories are judged by the handle, against what the store holds.
pub(super) fn validate(setting: &Setting) -> Result<(), SettingRefusal> {
    match setting {
        Setting::Nickname(nickname) => {
            let trimmed = nickname.trim();
            if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
                Err(SettingRefusal::NicknameUnfit)
            } else {
                Ok(())
            }
        }
        Setting::TcpPort(0) | Setting::UdpPort(0) => Err(SettingRefusal::PortZero),
        Setting::DeadServerRetries(0) => Err(SettingRefusal::DeadServerRetriesZero),
        Setting::ServerMetUrl(url) | Setting::NodesDatUrl(url) if url.trim().is_empty() => {
            Err(SettingRefusal::UrlBlank)
        }
        Setting::ServerMetAutoUpdateUrls(urls) if urls.iter().any(|url| url.trim().is_empty()) => {
            Err(SettingRefusal::UrlBlank)
        }
        Setting::DownloadDir { .. }
        | Setting::TempDir(_)
        | Setting::TcpPort(_)
        | Setting::UdpPort(_)
        | Setting::Obfuscation(_)
        | Setting::PortMapping(_)
        | Setting::RememberPeers(_)
        | Setting::DeadServerRetries(_)
        | Setting::WithholdShares(_)
        | Setting::ServerMetUrl(_)
        | Setting::ServerMetAutoUpdateUrls(_)
        | Setting::NodesDatUrl(_)
        | Setting::Flag(..) => Ok(()),
    }
}

/// An absolute, UTF-8 path that is not an existing file, and that the
/// guards a shared directory must pass do not refuse where it is or would be
/// made — the check core's scan makes of it at attach, made at the set, so a
/// refused directory is never stored. `temp_dir` is the Temp Directory it
/// may neither be nor hold. Not "must exist": aMule creates its incoming
/// directory, and refusing a path the operator is about to make would
/// misstate what rmule can do.
pub(super) fn validate_download_dir(
    dir: &Path,
    guards: &ShareGuards,
    temp_dir: Option<&Path>,
) -> Result<(), SettingRefusal> {
    if dir.to_str().is_none() {
        return Err(SettingRefusal::DownloadDirNotUtf8);
    }
    if !dir.is_absolute() {
        return Err(SettingRefusal::DownloadDirNotAbsolute);
    }
    if dir.exists() && !dir.is_dir() {
        return Err(SettingRefusal::DownloadDirNotADirectory);
    }
    guard_in_place(dir, guards, temp_dir).map_err(SettingRefusal::DownloadDirRefused)
}

/// Write a validated `setting` where its key is kept.
pub(super) fn persist(store: &DurableAppConfig, setting: &Setting) -> Result<(), CoreError> {
    match setting {
        Setting::DownloadDir { dir, .. } => store.set_download_dir(dir),
        Setting::TempDir(Some(dir)) => store.set_temp_dir(dir),
        Setting::TempDir(None) => store.clear_preference(Preference::TempDir),
        Setting::Nickname(nickname) => store.set_nickname(&Ed2kText::from_utf8(nickname.trim())),
        Setting::TcpPort(port) => store.set_tcp_port(*port),
        Setting::UdpPort(port) => store.set_udp_port(*port),
        Setting::Obfuscation(policy) => {
            store.set_preference(Preference::Obfuscation, obfuscation_name(*policy))
        }
        Setting::PortMapping(mode) => store.set_preference(
            Preference::PortMapping,
            flag_text(*mode == PortMappingMode::Auto),
        ),
        Setting::RememberPeers(peers) => {
            store.set_preference(Preference::RememberPeers, &peers.get().to_string())
        }
        Setting::DeadServerRetries(limit) => {
            store.set_preference(Preference::DeadServerRetries, &limit.to_string())
        }
        Setting::WithholdShares(on) => {
            store.set_preference(Preference::WithholdSharesFromRelatedSearch, flag_text(*on))
        }
        Setting::ServerMetUrl(url) => store.set_preference(Preference::ServerMetUrl, url.trim()),
        // One URL per line, as aMule's `addresses.dat` holds them.
        Setting::ServerMetAutoUpdateUrls(urls) => store.set_preference(
            Preference::ServerMetAutoUpdateUrls,
            &urls
                .iter()
                .map(|url| url.trim())
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        Setting::NodesDatUrl(url) => store.set_preference(Preference::NodesDatUrl, url.trim()),
        Setting::Flag(flag, on) => store.set_value(flag.key(), flag_text(*on)),
    }
}

/// The stored spelling of a policy: aMule's three nested checkboxes as one
/// word, `off` for none.
const fn obfuscation_name(policy: Option<ObfuscationPolicy>) -> &'static str {
    match policy {
        None => "off",
        Some(ObfuscationPolicy::Supported) => "supported",
        Some(ObfuscationPolicy::Requested) => "requested",
        Some(ObfuscationPolicy::Required) => "required",
    }
}

/// A stored policy; anything unrecognised, or unset, is none.
fn parse_obfuscation(name: Option<&str>) -> Option<ObfuscationPolicy> {
    [
        ObfuscationPolicy::Supported,
        ObfuscationPolicy::Requested,
        ObfuscationPolicy::Required,
    ]
    .into_iter()
    .find(|policy| Some(obfuscation_name(Some(*policy))) == name)
}
