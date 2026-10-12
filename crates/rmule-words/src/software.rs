//! A peer's Software cell, written from the parts core hands over the way
//! aMule's client list writes it (`CUpDownClient::ReGetClientSoft`,
//! `BaseClient.cpp:1771` @ aMule 2.3.3): what names the client, then `v` and
//! its version, then an eMule's mod after a dash.

use rmule_core::diagnostics::{
    ClientFamily, ClientMod, ClientSoftware, SoftwareName, software_parts,
};

/// The Software cell for one peer.
#[must_use]
pub fn label(software: &ClientSoftware) -> String {
    let parts = software_parts(software);
    let mut label = match parts.name {
        SoftwareName::Family(family) => family_name(family),
        SoftwareName::Mod(client_mod) => mod_name(client_mod),
    };
    if let Some(version) = parts.version {
        label.push_str(" v");
        label.push_str(&version);
    }
    if let Some(client_mod) = parts.emule_mod {
        label.push_str(" - ");
        label.push_str(&mod_name(client_mod));
    }
    label
}

/// A family's name as aMule's `GetSoftName` spells it (`DataToText.cpp:82`);
/// a code no table names shows as that code.
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
        ClientFamily::Compatible(code) => return format!("eMule compatible {code:#04x}"),
        ClientFamily::Unknown => "unknown client",
    }
    .to_owned()
}

/// A mod as the client sent it: its name, or its number.
fn mod_name(client_mod: &ClientMod) -> String {
    match client_mod {
        ClientMod::Named(text) => text.to_display_string(),
        ClientMod::Numbered(id) => format!("mod {id}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmule_testkit::{amule_233, client_software, emule_qt};

    #[test]
    fn the_captured_clients_read_as_amule_writes_them() {
        // The words and mods of the captured aMule 2.3.3, kno aMule and
        // emule-qt hellos.
        assert_eq!(label(&amule_233()), "aMule v2.3.3");
        assert_eq!(
            label(&client_software(0x0306_0080, Some("aMule GIT"))),
            "aMule GIT v3.0.1"
        );
        assert_eq!(label(&emule_qt()), "eMule v0.70b - eMule Qt 0.4.2");
    }

    #[test]
    fn an_unnamed_code_shows_the_code_the_peer_sent_without_brackets() {
        let word = (0xF0 << 24) | (49 << 10) | (2 << 7);
        assert_eq!(
            label(&client_software(word, None)),
            "eMule compatible 0xf0 v0.49c"
        );
    }
}
