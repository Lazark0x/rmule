//! A peer's client identification in the parts aMule's client list composes
//! its Software text from (`CUpDownClient::ReGetClientSoft`,
//! `BaseClient.cpp:1771` @ aMule 2.3.3): what names the client, its version
//! in that family's notation, and the mod written after it. A front end's
//! Software cell writes the words from these parts, and the Run Log writes
//! them as codes; core writes no sentence of its own.
//!
//! The identification is the peer codec's; a table that sorts by client
//! compares [`ClientSoftware`] itself (family rank, then version), never the
//! words.

use super::{ClientFamily, ClientMod, ClientSoftware, ClientVersion};

/// One peer's client identification, in parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SoftwareParts<'a> {
    /// What names the client.
    pub name: SoftwareName<'a>,
    /// The version in the family's own notation (`BaseClient.cpp:1855-1890`,
    /// `:1893-1951`): digits, dots and the update letter, such as `2.3.3` or
    /// `0.70b`.
    pub version: Option<String>,
    /// The mod an eMule sent, which aMule writes after the version
    /// (`eMule v0.70b - eMule Qt 0.4.2`).
    pub emule_mod: Option<&'a ClientMod>,
}

/// What names a client: its family, or, for a client other than eMule that
/// sent a mod, that mod (`aMule GIT v3.0.1`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoftwareName<'a> {
    /// The family the hello's software word names.
    Family(ClientFamily),
    /// The mod the client sent.
    Mod(&'a ClientMod),
}

/// The letter eMule writes for an update number: `0` is `a`.
fn update_letter(update: u32) -> char {
    char::from_u32(u32::from('a') + update).unwrap_or('?')
}

/// The version in the family's own notation (`BaseClient.cpp:1855-1890`,
/// `:1893-1951`).
fn version_notation(family: ClientFamily, v: ClientVersion) -> String {
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
        | ClientFamily::MlDonkey => format!("{major}.{minor}.{update}"),
        ClientFamily::Lphant => format!(
            "{}.{minor:02}{}",
            major.saturating_sub(1),
            update_letter(update)
        ),
        ClientFamily::EmulePlus => {
            let mut text = major.to_string();
            if minor != 0 {
                text.push_str(&format!(".{minor}"));
            }
            if update != 0 {
                text.push(update_letter(update - 1));
            }
            text
        }
        ClientFamily::EdonkeyHybrid if update != 0 => format!("{major}.{minor}.{update}"),
        ClientFamily::EdonkeyHybrid
        | ClientFamily::Edonkey
        | ClientFamily::MlDonkeyOld
        | ClientFamily::EmuleOld => format!("{major}.{minor}"),
        ClientFamily::Emule
        | ClientFamily::Cdonkey
        | ClientFamily::Shareaza
        | ClientFamily::Compatible(_)
        | ClientFamily::Unknown => format!("{major}.{minor}{}", update_letter(update)),
    }
}

/// The parts one peer's Software cell is written from. aMule names a
/// non-eMule client by its mod when it sent one and appends an eMule's mod
/// after the version.
#[must_use]
pub fn software_parts(software: &ClientSoftware) -> SoftwareParts<'_> {
    let family = software.family();
    let named_by_mod = family != ClientFamily::Emule && family != ClientFamily::EmuleOld;
    let client_mod = software.client_mod();
    SoftwareParts {
        name: match client_mod {
            Some(client_mod) if named_by_mod => SoftwareName::Mod(client_mod),
            _ => SoftwareName::Family(family),
        },
        version: software
            .version()
            .map(|version| version_notation(family, version)),
        emule_mod: client_mod.filter(|_| !named_by_mod),
    }
}

/// The client a mule hello names: its `CT_EMULE_VERSION` word and, when it
/// sent one, its mod — read by the peer codec, as core reads a live hello.
#[cfg(test)]
pub(crate) fn client_software(word: u32, client_mod: Option<&str>) -> ClientSoftware {
    use rmule_primitives::{ClientId, Ed2kText, Ipv4Endpoint, Tag, TagName, TagValue, UserHash};
    let mut hash = [0x42; UserHash::BYTE_LEN];
    // eMule's user-hash mark, as every mule writes it.
    hash[5] = 14;
    hash[14] = 111;
    let mut tags = vec![
        Tag::new(
            TagName::compact_id(0x01),
            TagValue::String(Ed2kText::from_utf8("peer")),
        ),
        Tag::new(TagName::compact_id(0xFB), TagValue::U32(word)),
    ];
    if let Some(text) = client_mod {
        tags.push(Tag::new(
            TagName::compact_id(0x55),
            TagValue::String(Ed2kText::from_utf8(text)),
        ));
    }
    ClientSoftware::from_hello_body(&rmule_peer::PeerHelloBody {
        user_hash: UserHash::from_bytes(hash),
        client_id: ClientId::from_u32(0),
        tcp_port: 4662,
        tags,
        connected_server: Ipv4Endpoint::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
    })
}

#[cfg(test)]
mod tests {
    use rmule_primitives::Ed2kText;

    use super::*;

    #[test]
    fn the_captured_clients_split_as_amule_writes_them() {
        // The words and mods of the captured aMule 2.3.3, kno aMule and
        // emule-qt hellos.
        assert_eq!(
            software_parts(&client_software(0x0304_0D80, None)),
            SoftwareParts {
                name: SoftwareName::Family(ClientFamily::Amule),
                version: Some("2.3.3".to_owned()),
                emule_mod: None,
            }
        );
        let git = ClientMod::Named(Ed2kText::from_utf8("aMule GIT"));
        assert_eq!(
            software_parts(&client_software(0x0306_0080, Some("aMule GIT"))),
            SoftwareParts {
                name: SoftwareName::Mod(&git),
                version: Some("3.0.1".to_owned()),
                emule_mod: None,
            }
        );
        let qt = ClientMod::Named(Ed2kText::from_utf8("eMule Qt 0.4.2"));
        assert_eq!(
            software_parts(&client_software(0x0001_1880, Some("eMule Qt 0.4.2"))),
            SoftwareParts {
                name: SoftwareName::Family(ClientFamily::Emule),
                version: Some("0.70b".to_owned()),
                emule_mod: Some(&qt),
            }
        );
    }

    #[test]
    fn an_unnamed_code_keeps_the_code_the_peer_sent() {
        let word = (0xF0 << 24) | (49 << 10) | (2 << 7);
        let software = client_software(word, None);
        let parts = software_parts(&software);
        assert_eq!(
            parts.name,
            SoftwareName::Family(ClientFamily::Compatible(0xF0))
        );
        assert_eq!(parts.version.as_deref(), Some("0.49c"));
    }
}
