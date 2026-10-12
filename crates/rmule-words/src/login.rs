//! The words of a login's steps in the Networks log: what rmule claimed, what
//! the server did with it, and where the login stopped.

use rmule_core::{
    AssignedAddress, DialFailure, IdAssignment, Ipv6Probe, LoginClaim, LoginCloseCause, LoginLink,
    LoginStep, PlainLinkReason, PortTestAdmission, PortTestClosedBy, PortTestEnd,
    PortTestLateAdmission, ServerGrants,
};
use rmule_primitives::{AddressFamily, ServerEndpoint};

use super::Sentence;
use super::os::{kind_words, refusal_words};
use super::server::id_class;
use super::units::server_label;

/// What became of a test that came after its window: refused plain, or let
/// in as any peer.
const fn late_admission_words(admission: PortTestLateAdmission) -> &'static str {
    match admission {
        PortTestLateAdmission::Refused => {
            "and was turned away: obfuscation is required and no test was awaited any more"
        }
        PortTestLateAdmission::Peer => "let in like any peer",
    }
}

/// A Kad helper's firewall-check connect-back that came after its window, as
/// one line of the Networks log. The helper is a stranger peer, so the line
/// never names its address.
#[must_use]
pub fn kad_helper_test_late(
    late_by: std::time::Duration,
    admission: PortTestLateAdmission,
) -> Sentence {
    Sentence::owned(format!(
        "Kad firewall check: a helper's test came {} ms after its window closed, {}",
        late_by.as_millis(),
        late_admission_words(admission)
    ))
}

/// A login step as one line of the Networks log.
#[must_use]
pub fn step_line(server: &ServerEndpoint, step: &LoginStep) -> Sentence {
    let server = server_label(server);
    Sentence::owned(match step {
        LoginStep::MappingWait {
            port,
            settled: true,
        } => format!("login to {server}: port {port} mapped, logging in"),
        LoginStep::MappingWait {
            port,
            settled: false,
        } => format!(
            "login to {server}: port {port} not mapped yet, logging in anyway — the server's \
             check may miss it"
        ),
        LoginStep::LinkChosen { link } => {
            format!("login to {server}: {}", link_words(*link))
        }
        LoginStep::DialFailed { cause } => {
            format!("login to {server}: dial failed — {}", dial_words(*cause))
        }
        LoginStep::LoginSent { claim } => {
            format!("login to {server}: sent, {}", claim_words(claim))
        }
        LoginStep::ClosedBeforeAnswer { cause } => format!(
            "login to {server}: closed before an answer — {}",
            close_words(*cause)
        ),
        LoginStep::PortTestAwaited => {
            format!("login to {server}: waiting for the server to test our port")
        }
        LoginStep::PortTestArrived { admission } => format!(
            "login to {server}: the server's port test reached us, {}",
            match admission {
                PortTestAdmission::TestConnection => "let in as a test only",
                PortTestAdmission::Peer => "let in like any peer",
            }
        ),
        LoginStep::PortTestEnded { end } => {
            format!(
                "login to {server}: port test over, {}",
                test_end_words(*end)
            )
        }
        LoginStep::PortTestLate { late_by, admission } => format!(
            "login to {server}: the server's port test came {} ms after its window closed, {}",
            late_by.as_millis(),
            late_admission_words(*admission)
        ),
        LoginStep::PortTestWindowClosed { arrived: true } => {
            format!("login to {server}: port test window closed, the test came")
        }
        LoginStep::PortTestWindowClosed { arrived: false } => {
            format!("login to {server}: port test window closed, the server never reached our port")
        }
        LoginStep::Answered { assignment } => {
            format!(
                "login to {server}: answered {}",
                assignment_words(assignment)
            )
        }
        LoginStep::Reassigned { assignment } => format!(
            "server {server} assigned us again: {}",
            assignment_words(assignment)
        ),
        LoginStep::Ipv6Probe { verdict } => {
            format!("login to {server}: {}", probe_words(*verdict))
        }
        LoginStep::KadRecheck => {
            format!("login to {server}: HighID while Kad reads firewalled — Kad checks again")
        }
    })
}

/// Why a TCP dial did not come up: a server's or a buddy's.
pub(super) fn dial_words(cause: DialFailure) -> String {
    match cause {
        DialFailure::TimedOut => "no answer in time".to_string(),
        DialFailure::Os { kind, os_code } => refusal_words(kind, os_code),
        DialFailure::DriverEnded => "the connection ended before it came up".to_string(),
        DialFailure::CryptHandshake { kind } => format!(
            "the obfuscation handshake did not complete: {}",
            kind_words(kind)
        ),
    }
}

/// How the link to a server is opened, and why plain when it is.
fn link_words(link: LoginLink) -> String {
    match link {
        LoginLink::Obfuscated { port } => format!("dialing obfuscated, to port {port}"),
        LoginLink::Plain { why } => format!(
            "dialing plain — {}",
            match why {
                PlainLinkReason::PolicyDoesNotInitiate =>
                    "our obfuscation setting does not ask for it",
                PlainLinkReason::ServerNotKnownToObfuscate => {
                    "the server has not said it takes obfuscation"
                }
                PlainLinkReason::ObfuscatedAttemptFailed => {
                    "the obfuscated attempt failed, and obfuscation is requested, not required"
                }
            }
        ),
    }
}

fn claim_words(claim: &LoginClaim) -> String {
    let family = match claim.family {
        Some(AddressFamily::V4) => "over IPv4",
        Some(AddressFamily::V6) => "over IPv6",
        None => "over an unnamed family",
    };
    let udp = match claim.client_udp_port {
        Some(port) => format!("UDP {port}"),
        None => "no UDP port".to_string(),
    };
    let kad = match claim.kad_udp_port {
        Some(port) => format!("Kad {port}"),
        None => "no Kad port".to_string(),
    };
    let ipv6 = match claim.advertised_ipv6 {
        Some(address) => format!("IPv6 {address}"),
        None => "no IPv6".to_string(),
    };
    format!("{family}, TCP {}, {udp}, {kad}, {ipv6}", claim.tcp_port)
}

fn test_end_words(end: PortTestEnd) -> String {
    match end {
        PortTestEnd::TesterClosed => "the server hung up, nothing served",
        PortTestEnd::AskedToBeServed => "it asked to be served and was closed",
        PortTestEnd::Lapsed => "it stayed too long and was closed",
        PortTestEnd::IpFiltered => "the IP filter turned it away",
        PortTestEnd::Banned => "a ban on its address turned it away",
        PortTestEnd::PeerConnectionEnded { closed_by } => return closed_by_words(closed_by),
    }
    .to_string()
}

/// The end of a port test let in like any peer, by who closed it.
fn closed_by_words(closed_by: PortTestClosedBy) -> String {
    let how = match closed_by {
        PortTestClosedBy::Us => "was closed by rmule",
        PortTestClosedBy::Peer => "was closed by the peer",
        PortTestClosedBy::ProtocolViolation => "was closed: the server broke the peer protocol",
        PortTestClosedBy::Io { kind } => {
            return format!(
                "its connection, let in like any peer, failed: {}",
                kind_words(kind)
            );
        }
        PortTestClosedBy::Timeout => "was closed: no hello came in time",
        PortTestClosedBy::DriverEnded => "ended without saying who closed it",
        PortTestClosedBy::Unlisted { .. } => "ended for a reason rmule does not name yet",
    };
    format!("its connection, let in like any peer, {how}")
}

fn assignment_words(assignment: &IdAssignment) -> String {
    let class = id_class(assignment.client_id);
    let address = match assignment.address {
        AssignedAddress::Ours(ip) => format!("our address {ip}"),
        AssignedAddress::Unnamed => "no address of ours named".to_string(),
        AssignedAddress::ServerOwnRefused(ip) => {
            format!("the server named its own address {ip} as ours, refused")
        }
    };
    format!("{class}, {address}, {}", grant_words(assignment.grants))
}

fn grant_words(grants: ServerGrants) -> String {
    let ServerGrants {
        compression,
        new_tags,
        unicode,
        related_search,
        type_tag_integer,
        large_files,
        tcp_obfuscation,
        ipv6,
    } = grants;
    let named: Vec<&str> = [
        (compression, "compression"),
        (new_tags, "new tags"),
        (unicode, "Unicode"),
        (related_search, "related search"),
        (type_tag_integer, "integer file types"),
        (large_files, "large files"),
        (tcp_obfuscation, "obfuscation"),
        (ipv6, "IPv6"),
    ]
    .into_iter()
    .filter_map(|(granted, name)| granted.then_some(name))
    .collect();
    if named.is_empty() {
        "grants nothing".to_string()
    } else {
        format!("grants {}", named.join(", "))
    }
}

const fn close_words(cause: LoginCloseCause) -> &'static str {
    match cause {
        LoginCloseCause::Local => "rmule closed it",
        LoginCloseCause::ServerClosed => "the server hung up",
        LoginCloseCause::ProtocolViolation => "the server sent what a login cannot take",
        LoginCloseCause::Io { kind } => kind_words(kind),
        LoginCloseCause::ConnectTimeout => "the dial timed out",
        LoginCloseCause::LoginTimeout => "no answer in time",
        LoginCloseCause::Refused => "the server refused the login",
        LoginCloseCause::Unlisted { .. } => "a cause rmule does not name yet",
    }
}

const fn probe_words(verdict: Ipv6Probe) -> &'static str {
    match verdict {
        Ipv6Probe::Unknown => "the server did not probe our IPv6",
        Ipv6Probe::ProbedReachable => "the server reached our IPv6",
        Ipv6Probe::ProbedUnreachable => "the server could not reach our IPv6",
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_late_port_test_names_the_server_how_late_and_why_it_was_refused() {
        let server = ServerEndpoint::new("203.0.113.7", 4661).expect("endpoint");
        let step = LoginStep::PortTestLate {
            late_by: Duration::from_millis(1_250),
            admission: PortTestLateAdmission::Refused,
        };
        assert_eq!(
            step_line(&server, &step).as_str(),
            format!(
                "login to {}: the server's port test came 1250 ms after its window closed, and \
                 was turned away: obfuscation is required and no test was awaited any more",
                server_label(&server)
            )
        );
    }

    /// A test let in like any peer ends by its connection's close, and the
    /// line names who closed it.
    #[test]
    fn a_port_test_let_in_as_a_peer_names_who_closed_it() {
        let server = ServerEndpoint::new("203.0.113.7", 4661).expect("endpoint");
        let ended = |closed_by| LoginStep::PortTestEnded {
            end: PortTestEnd::PeerConnectionEnded { closed_by },
        };
        assert_eq!(
            step_line(&server, &ended(PortTestClosedBy::Peer)).as_str(),
            format!(
                "login to {}: port test over, its connection, let in like any peer, was closed \
                 by the peer",
                server_label(&server)
            )
        );
        assert!(
            step_line(&server, &ended(PortTestClosedBy::Us))
                .as_str()
                .ends_with("was closed by rmule")
        );
    }

    #[test]
    fn a_late_kad_helper_test_says_how_late_and_never_names_the_helper() {
        assert_eq!(
            kad_helper_test_late(Duration::from_millis(3_400), PortTestLateAdmission::Refused)
                .as_str(),
            "Kad firewall check: a helper's test came 3400 ms after its window closed, and was \
             turned away: obfuscation is required and no test was awaited any more"
        );
    }
}
