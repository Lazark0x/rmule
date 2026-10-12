//! The records of a login's steps (ADR-0075, Run Log): every field is rmule's
//! own or the server's, so a step's record is the same at both levels.

use crate::{
    AssignedAddress, IdAssignment, Ipv6Probe, LoginCloseCause, LoginLink, LoginStep,
    PlainLinkReason, PortTestAdmission, PortTestClosedBy, PortTestEnd, PortTestLateAdmission,
    ServerGrants,
};
use rmule_primitives::ServerEndpoint;

use crate::run_log::codes;
use crate::run_log::record::Record;

/// A Kad helper's late test: how late and what became of it are ours and
/// lean; the helper is a stranger peer, its address the full level's alone.
pub(super) fn kad_helper_test_late(
    helper: std::net::Ipv4Addr,
    late_by: std::time::Duration,
    admission: PortTestLateAdmission,
) -> Record {
    Record::new("kad.helper_test_late")
        .peer_address("helper", &helper)
        .count("late_by_ms", late_by.as_millis())
        .code("admission", late_admission(admission))
}

const fn late_admission(admission: PortTestLateAdmission) -> &'static str {
    match admission {
        PortTestLateAdmission::Refused => "refused",
        PortTestLateAdmission::Peer => "peer",
    }
}

pub(super) fn record(server: &ServerEndpoint, step: &LoginStep) -> Record {
    let record = Record::new("server.login").server_endpoint("server", server);
    match step {
        LoginStep::MappingWait { port, settled } => record
            .code("step", "mapping_wait")
            .port("port", *port)
            .flag("settled", *settled),
        LoginStep::LinkChosen { link } => {
            let record = record.code("step", "link_chosen");
            match link {
                LoginLink::Obfuscated { port } => {
                    record.code("link", "obfuscated").port("port", *port)
                }
                LoginLink::Plain { why } => record.code("link", "plain").code(
                    "why",
                    match why {
                        PlainLinkReason::PolicyDoesNotInitiate => "policy_does_not_initiate",
                        PlainLinkReason::ServerNotKnownToObfuscate => {
                            "server_not_known_to_obfuscate"
                        }
                        PlainLinkReason::ObfuscatedAttemptFailed => "obfuscated_attempt_failed",
                    },
                ),
            }
        }
        LoginStep::DialFailed { cause } => {
            codes::dial_failure(record.code("step", "dial_failed"), *cause)
        }
        LoginStep::LoginSent { claim } => {
            let record = record.code("step", "login_sent");
            let record = match claim.family {
                Some(family) => record.code("family", codes::family(family)),
                None => record.code("family", "none"),
            };
            let record = record.port("tcp_port", claim.tcp_port);
            let record = match claim.client_udp_port {
                Some(port) => record.port("client_udp_port", port),
                None => record.code("client_udp_port", "none"),
            };
            let record = match claim.kad_udp_port {
                Some(port) => record.port("kad_udp_port", port),
                None => record.code("kad_udp_port", "none"),
            };
            match &claim.advertised_ipv6 {
                Some(address) => record.own_address("advertised_ipv6", address),
                None => record.code("advertised_ipv6", "none"),
            }
        }
        LoginStep::ClosedBeforeAnswer { cause } => {
            close_cause(record.code("step", "closed_before_answer"), *cause)
        }
        LoginStep::PortTestAwaited => record.code("step", "port_test_awaited"),
        LoginStep::PortTestArrived { admission } => record.code("step", "port_test_arrived").code(
            "admission",
            match admission {
                PortTestAdmission::TestConnection => "test_connection",
                PortTestAdmission::Peer => "peer",
            },
        ),
        LoginStep::PortTestEnded { end } => test_end(record.code("step", "port_test_ended"), *end),
        LoginStep::PortTestLate { late_by, admission } => record
            .code("step", "port_test_late")
            .count("late_by_ms", late_by.as_millis())
            .code("admission", late_admission(*admission)),
        LoginStep::PortTestWindowClosed { arrived } => record
            .code("step", "port_test_window_closed")
            .flag("arrived", *arrived),
        LoginStep::Answered { assignment } => assigned(record.code("step", "answered"), assignment),
        LoginStep::Reassigned { assignment } => {
            assigned(record.code("step", "reassigned"), assignment)
        }
        LoginStep::Ipv6Probe { verdict } => record.code("step", "ipv6_probe").code(
            "verdict",
            match verdict {
                Ipv6Probe::Unknown => "not_probed",
                Ipv6Probe::ProbedReachable => "reachable",
                Ipv6Probe::ProbedUnreachable => "unreachable",
            },
        ),
        LoginStep::KadRecheck => record.code("step", "kad_recheck"),
    }
}

/// What an `OP_IDCHANGE` assigned: our id, our address or the server's own
/// refused as ours, and each grant by name.
fn assigned(record: Record, assignment: &IdAssignment) -> Record {
    let record = record.own_id("client_id", assignment.client_id);
    let record = match &assignment.address {
        AssignedAddress::Ours(ip) => record.own_address("public_ip", ip),
        AssignedAddress::Unnamed => record.code("public_ip", "none"),
        AssignedAddress::ServerOwnRefused(ip) => record
            .code("public_ip", "refused_server_own")
            .server_address("reported", ip),
    };
    grants(record, assignment.grants)
}

fn grants(record: Record, grants: ServerGrants) -> Record {
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
    record
        .flag("compression", compression)
        .flag("new_tags", new_tags)
        .flag("unicode", unicode)
        .flag("related_search", related_search)
        .flag("type_tag_integer", type_tag_integer)
        .flag("large_files", large_files)
        .flag("tcp_obfuscation", tcp_obfuscation)
        .flag("ipv6", ipv6)
}

fn test_end(record: Record, end: PortTestEnd) -> Record {
    let code = |code| record.code("end", code);
    match end {
        PortTestEnd::TesterClosed => code("tester_closed"),
        PortTestEnd::AskedToBeServed => code("asked_to_be_served"),
        PortTestEnd::Lapsed => code("lapsed"),
        PortTestEnd::IpFiltered => code("ip_filtered"),
        PortTestEnd::Banned => code("banned"),
        PortTestEnd::PeerConnectionEnded { closed_by } => {
            let record = code("peer_connection_ended");
            match closed_by {
                PortTestClosedBy::Us => record.code("closed_by", "us"),
                PortTestClosedBy::Peer => record.code("closed_by", "peer"),
                PortTestClosedBy::ProtocolViolation => {
                    record.code("closed_by", "protocol_violation")
                }
                PortTestClosedBy::Io { kind } => {
                    record.code("closed_by", "io").os_error(kind, None)
                }
                PortTestClosedBy::Timeout => record.code("closed_by", "timeout"),
                PortTestClosedBy::DriverEnded => record.code("closed_by", "driver_ended"),
                PortTestClosedBy::Unlisted { label } => {
                    record.code("closed_by", "unlisted").code("label", label)
                }
            }
        }
    }
}

fn close_cause(record: Record, cause: LoginCloseCause) -> Record {
    match cause {
        LoginCloseCause::Local => record.code("cause", "local"),
        LoginCloseCause::ServerClosed => record.code("cause", "server_closed"),
        LoginCloseCause::ProtocolViolation => record.code("cause", "protocol_violation"),
        LoginCloseCause::Io { kind } => record.code("cause", "io").os_error(kind, None),
        LoginCloseCause::ConnectTimeout => record.code("cause", "connect_timeout"),
        LoginCloseCause::LoginTimeout => record.code("cause", "login_timeout"),
        LoginCloseCause::Refused => record.code("cause", "refused"),
        LoginCloseCause::Unlisted { label } => {
            record.code("cause", "unlisted").code("label", label)
        }
    }
}
