//! The Software cell: a peer's client identification written the way aMule's
//! client list writes it (`CUpDownClient::ReGetClientSoft`,
//! `BaseClient.cpp:1771` @ aMule 2.3.3) — family name, then the version in that
//! family's notation, then the mod.
//!
//! Only the rendering lives here; the identification is core's. A table that
//! sorts this column compares [`ClientSoftware`] itself (family rank, then
//! version), never this text.

use rmule_core::diagnostics::{ClientFamily, ClientMod, ClientSoftware, ClientVersion};

/// A family's name as aMule's `GetSoftName` spells it (`DataToText.cpp:82`).
/// A code no table names shows as that code.
fn family_name(family: ClientFamily) -> String {
    match family {
        ClientFamily::Emule | ClientFamily::EmuleOld => "eMule",
        ClientFamily::Cdonkey => "cDonkey",
        ClientFamily::Xmule => "xMule",
        ClientFamily::Amule => "aMule",
        ClientFamily::Rmule => "rmule",
        ClientFamily::Shareaza => "Shareaza",
        ClientFamily::EmulePlus => "eMule+",
        ClientFamily::HydraNode => "HydraNode",
        ClientFamily::MlDonkey => "MLDonkey",
        ClientFamily::MlDonkeyOld => "Old MLDonkey",
        ClientFamily::Lphant => "lphant",
        ClientFamily::EdonkeyHybrid => "eDonkeyHybrid",
        ClientFamily::Edonkey => "eDonkey",
        ClientFamily::Compatible(code) => return format!("eMule Compatible({code:#x})"),
        ClientFamily::Unknown => "Unknown",
    }
    .to_string()
}

/// The letter eMule writes for an update number: `0` is `a`.
fn update_letter(update: u32) -> char {
    char::from_u32(u32::from('a') + update).unwrap_or('?')
}

/// The version in the family's own notation (`BaseClient.cpp:1855-1890`,
/// `:1893-1951`).
fn version_text(family: ClientFamily, v: ClientVersion) -> String {
    let ClientVersion {
        major,
        minor,
        update,
    } = v;
    match family {
        ClientFamily::Amule
        | ClientFamily::Rmule
        | ClientFamily::Xmule
        | ClientFamily::HydraNode
        | ClientFamily::MlDonkey => format!("v{major}.{minor}.{update}"),
        ClientFamily::Lphant => format!(
            "v{}.{minor:02}{}",
            major.saturating_sub(1),
            update_letter(update)
        ),
        ClientFamily::EmulePlus => {
            let mut text = format!("v{major}");
            if minor != 0 {
                text.push_str(&format!(".{minor}"));
            }
            if update != 0 {
                text.push(update_letter(update - 1));
            }
            text
        }
        ClientFamily::EdonkeyHybrid if update != 0 => format!("v{major}.{minor}.{update}"),
        ClientFamily::EdonkeyHybrid
        | ClientFamily::Edonkey
        | ClientFamily::MlDonkeyOld
        | ClientFamily::EmuleOld => format!("v{major}.{minor}"),
        ClientFamily::Emule
        | ClientFamily::Cdonkey
        | ClientFamily::Shareaza
        | ClientFamily::Compatible(_)
        | ClientFamily::Unknown => format!("v{major}.{minor}{}", update_letter(update)),
    }
}

fn mod_text(client_mod: &ClientMod) -> String {
    match client_mod {
        ClientMod::Named(text) => text.to_display_string(),
        ClientMod::Numbered(id) => format!("ModID={id}"),
    }
}

/// The Software cell for one peer. aMule names a non-eMule client by its mod
/// when it sent one (`aMule GIT v3.0.1`) and appends an eMule mod after the
/// version (`eMule v0.70b - eMule Qt 0.4.2`).
pub(crate) fn software_label(software: &ClientSoftware) -> String {
    let family = software.family();
    let named_by_mod = family != ClientFamily::Emule && family != ClientFamily::EmuleOld;
    let client_mod = software.client_mod().map(mod_text);
    let name = match &client_mod {
        Some(text) if named_by_mod => text.clone(),
        _ => family_name(family),
    };
    let mut label = name;
    if let Some(version) = software.version() {
        label.push(' ');
        label.push_str(&version_text(family, version));
    }
    if let Some(text) = client_mod.filter(|_| !named_by_mod) {
        label.push_str(" - ");
        label.push_str(&text);
    }
    label
}

/// Each client the rows of one table name, in [`ClientSoftware`]'s own order
/// (family rank, then version, then mod): a Software column's sort value is
/// its client's place here, so it sorts as a quantity and never by
/// [`software_label`]'s text.
pub(crate) struct SoftwareRanks(Vec<ClientSoftware>);

impl SoftwareRanks {
    /// The ranks of every client in `clients`.
    pub(crate) fn new<'a>(clients: impl Iterator<Item = &'a ClientSoftware>) -> Self {
        let mut clients: Vec<ClientSoftware> = clients.cloned().collect();
        clients.sort();
        clients.dedup();
        Self(clients)
    }

    /// `client`'s rank; `None` for a peer that named none, which sorts last.
    pub(crate) fn rank(&self, client: Option<&ClientSoftware>) -> Option<u64> {
        let at = self.0.binary_search(client?).ok()?;
        u64::try_from(at).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{amule_233, client_software, emule_qt};

    #[test]
    fn the_captured_clients_read_as_amule_writes_them() {
        // The words and mods of the captured aMule 2.3.3, kno aMule and
        // emule-qt hellos.
        assert_eq!(software_label(&amule_233()), "aMule v2.3.3");
        assert_eq!(
            software_label(&client_software(0x0306_0080, Some("aMule GIT"))),
            "aMule GIT v3.0.1"
        );
        assert_eq!(software_label(&emule_qt()), "eMule v0.70b - eMule Qt 0.4.2");
    }

    #[test]
    fn an_unnamed_code_shows_the_code_the_peer_sent() {
        let word = (0xF0 << 24) | (49 << 10) | (2 << 7);
        assert_eq!(
            software_label(&client_software(word, None)),
            "eMule Compatible(0xf0) v0.49c"
        );
    }
}
