//! A peer's own words about a hello rmule refused (ADR-0050). The sentence names the peer by what it said of itself — its
//! mod and its name, as it wrote them — and never by its address.

use rmule_core::{HelloRefusal, HelloRefusalCode};
use rmule_primitives::Ed2kText;

use super::Sentence;

/// Text the peer supplied, on one line: control characters dropped.
fn peer_text(text: &Ed2kText) -> String {
    text.to_display_string()
        .chars()
        .filter(|c| !c.is_control())
        .collect()
}

/// Who sent the refused hello, by what it said of itself.
fn who(refusal: &HelloRefusal) -> String {
    let client_mod = refusal.client_mod.as_ref().map(peer_text);
    let name = refusal.name.as_ref().map(peer_text);
    match (client_mod, name) {
        (Some(client_mod), Some(name)) => {
            format!("a client calling itself “{client_mod}” (name “{name}”)")
        }
        (Some(client_mod), None) => format!("a client calling itself “{client_mod}”"),
        (None, Some(name)) => format!("a client named “{name}”"),
        (None, None) => "a client that gave no name".to_string(),
    }
}

/// The Networks log line for a refused peer hello.
#[must_use]
pub fn hello_refused(refusal: &HelloRefusal) -> Sentence {
    let why = match refusal.code {
        HelloRefusalCode::TagCountShort { declared, written } => format!(
            "its hello counts {declared} tags but carries {written}, which aMule and eMule \
             refuse as well"
        ),
    };
    Sentence::owned(format!("Refused {}: {why}", who(refusal)))
}

/// The Statistics view's label for the count of refused peer hellos.
pub const HELLOS_LABEL: &str = "Peer hellos";

/// The Statistics view's value for the count of refused peer hellos.
#[must_use]
pub fn hellos_refused(count: u64) -> String {
    format!("{count} refused")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_names_the_peer_by_what_it_wrote_and_drops_control_characters() {
        let refusal = HelloRefusal {
            code: HelloRefusalCode::TagCountShort {
                declared: 10,
                written: 9,
            },
            name: Some(Ed2kText::from_utf8("https://amule-org.github.io")),
            client_mod: Some(Ed2kText::from_utf8("aMule GIT\n")),
        };
        assert_eq!(
            hello_refused(&refusal).as_str(),
            "Refused a client calling itself “aMule GIT” (name “https://amule-org.github.io”): \
             its hello counts 10 tags but carries 9, which aMule and eMule refuse as well"
        );
    }
}
