//! Where each Core Setting is kept and how it is spelled there: the nickname
//! and the two ports in the identity rows, every other key as text in the
//! preferences table. The one place a stored spelling is read or written, so
//! no reader can drift from the writer.

use std::path::{Path, PathBuf};

use rmule_net::peer::ObfuscationPolicy;
use rmule_primitives::Ed2kText;

use super::{CoreSettings, Setting, SettingRefusal};
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
        nickname: identity.nickname().to_display_string(),
        tcp_port: identity.tcp_port(),
        udp_port: kad.udp_port,
        obfuscation: parse_obfuscation(text(Preference::Obfuscation)?.as_deref()),
        // ADR-0086's Auto, unless the operator turned it off.
        port_mapping: if text(Preference::PortMapping)?.is_none_or(|value| value == "true") {
            PortMappingMode::Auto
        } else {
            PortMappingMode::Off
        },
        remember_peers: RememberPeers::parse(text(Preference::RememberPeers)?.as_deref()),
        server_policy: server_policy(store)?,
        server_met_url: text(Preference::ServerMetUrl)?
            .unwrap_or_else(|| rmule_bootstrap::DEFAULT_SERVER_MET_URL.to_owned()),
        // ADR-0065's first-run fetch, on unless the operator turned it off.
        auto_fetch_server_met: text(Preference::AutoFetchServerMet)?
            .is_none_or(|value| value == "true"),
        nodes_dat_url: text(Preference::NodesDatUrl)?
            .unwrap_or_else(|| rmule_bootstrap::DEFAULT_NODES_DAT_URL.to_owned()),
        // The ADR-0067 amendment's opt-in, on unless the operator turned it off.
        auto_fetch_nodes_dat: text(Preference::AutoFetchNodesDat)?
            .is_none_or(|value| value == "true"),
    })
}

/// The **Server Policy** `store` holds, defaults filling what is unset.
pub(super) fn server_policy(store: &DurableAppConfig) -> Result<ServerPolicy, CoreError> {
    Ok(ServerPolicy {
        dead_after: ServerPolicy::parse_dead_after(
            store.preference(Preference::DeadServerRetries)?.as_deref(),
        ),
        withhold_from_related_search: store
            .preference(Preference::WithholdSharesFromRelatedSearch)?
            .is_some_and(|value| value == "true"),
    })
}

/// Refuse a value the key cannot take, before anything is written: a
/// download directory is judged by `guards` too.
pub(super) fn validate(setting: &Setting, guards: &ShareGuards) -> Result<(), SettingRefusal> {
    match setting {
        Setting::DownloadDir { dir, .. } => validate_download_dir(dir, guards),
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
        _ => Ok(()),
    }
}

/// An absolute, UTF-8 path that is not an existing file, and that the
/// guards a shared directory must pass do not refuse where it is or would be
/// made — the check core's scan makes of it at attach, made at the set, so a
/// refused directory is never stored. Not "must exist": aMule creates its
/// incoming directory, and refusing a path the operator is about to make
/// would misstate what rmule can do.
fn validate_download_dir(dir: &Path, guards: &ShareGuards) -> Result<(), SettingRefusal> {
    if dir.to_str().is_none() {
        return Err(SettingRefusal::DownloadDirNotUtf8);
    }
    if !dir.is_absolute() {
        return Err(SettingRefusal::DownloadDirNotAbsolute);
    }
    if dir.exists() && !dir.is_dir() {
        return Err(SettingRefusal::DownloadDirNotADirectory);
    }
    guard_in_place(dir, guards).map_err(SettingRefusal::DownloadDirRefused)
}

/// Write a validated `setting` where its key is kept.
pub(super) fn persist(store: &DurableAppConfig, setting: &Setting) -> Result<(), CoreError> {
    let flag = |on: bool| if on { "true" } else { "false" };
    match setting {
        Setting::DownloadDir { dir, .. } => store.set_download_dir(dir),
        Setting::Nickname(nickname) => store.set_nickname(&Ed2kText::from_utf8(nickname.trim())),
        Setting::TcpPort(port) => store.set_tcp_port(*port),
        Setting::UdpPort(port) => store.set_udp_port(*port),
        Setting::Obfuscation(policy) => {
            store.set_preference(Preference::Obfuscation, obfuscation_name(*policy))
        }
        Setting::PortMapping(mode) => store.set_preference(
            Preference::PortMapping,
            flag(*mode == PortMappingMode::Auto),
        ),
        Setting::RememberPeers(peers) => {
            store.set_preference(Preference::RememberPeers, &peers.get().to_string())
        }
        Setting::DeadServerRetries(limit) => {
            store.set_preference(Preference::DeadServerRetries, &limit.to_string())
        }
        Setting::WithholdShares(on) => {
            store.set_preference(Preference::WithholdSharesFromRelatedSearch, flag(*on))
        }
        Setting::ServerMetUrl(url) => store.set_preference(Preference::ServerMetUrl, url.trim()),
        Setting::AutoFetchServerMet(on) => {
            store.set_preference(Preference::AutoFetchServerMet, flag(*on))
        }
        Setting::NodesDatUrl(url) => store.set_preference(Preference::NodesDatUrl, url.trim()),
        Setting::AutoFetchNodesDat(on) => {
            store.set_preference(Preference::AutoFetchNodesDat, flag(*on))
        }
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
