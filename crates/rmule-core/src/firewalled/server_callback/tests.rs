//! The server-relayed callback's refusal matrix and crypt reading.

use std::net::{IpAddr, Ipv4Addr};

use rmule_ed2k::PeerCallbackCrypt;
use rmule_net::peer::ObfuscationPolicy;
use rmule_primitives::{
    ClientId, Informant, Ipv4Endpoint, PeerEndpoint, SourceCryptOptions, UserHash,
};

use super::{
    ServerCallbackConsume, ServerCallbackContext, ServerCallbackRefusal, ServerCallbackVerdict,
    consume_server_callback,
};
use crate::address_learning::AddressObservation;
use crate::own_identity::SharedOwnIdentity;
use crate::reachability::OwnListenEndpoint;

const LOW_ID: ClientId = ClientId::from_u32(0x0000_2A57);
const OUR_PORT: u16 = 4662;
const REQUESTER_HASH: UserHash = UserHash::from_bytes([0xBB; UserHash::BYTE_LEN]);

fn server() -> Informant {
    Informant::Party(IpAddr::V4(Ipv4Addr::new(45, 55, 200, 1)))
}

fn context() -> ServerCallbackContext {
    ServerCallbackContext {
        session_id: LOW_ID,
        server: server(),
        own: OwnListenEndpoint::current(&SharedOwnIdentity::default(), OUR_PORT),
        serving: true,
        crypt: Some(ObfuscationPolicy::Supported),
    }
}

fn plain(requester: &str) -> ServerCallbackConsume {
    ServerCallbackConsume {
        requester: requester.parse().expect("an endpoint"),
        crypt: None,
    }
}

fn stating(requester: &str, connect_options: u8) -> ServerCallbackConsume {
    ServerCallbackConsume {
        crypt: Some(PeerCallbackCrypt {
            connect_options: SourceCryptOptions::from_byte(connect_options),
            user_hash: REQUESTER_HASH,
        }),
        ..plain(requester)
    }
}

fn refused(reason: ServerCallbackRefusal) -> ServerCallbackVerdict {
    ServerCallbackVerdict::Refuse { reason }
}

fn dialed(requester: &str, obfuscate_toward: Option<UserHash>) -> ServerCallbackVerdict {
    ServerCallbackVerdict::DialBack {
        requester: requester.parse().expect("an endpoint"),
        obfuscate_toward,
    }
}

/// A Low-ID session dials a public requester back, and every guard ahead of
/// the crypt reading refuses on its own: a High-ID session, a node that does
/// not serve.
#[test]
fn a_low_id_serving_session_dials_back_and_each_session_guard_refuses_alone() {
    let requester = "198.51.100.7:4662";
    assert_eq!(
        consume_server_callback(&plain(requester), &context()),
        dialed(requester, None),
        "the default port is not ours while our address is unknown"
    );
    let high = ServerCallbackContext {
        session_id: ClientId::from_u32(0x0A00_0001),
        ..context()
    };
    assert_eq!(
        consume_server_callback(&plain(requester), &high),
        refused(ServerCallbackRefusal::HighId)
    );
    let idle = ServerCallbackContext {
        serving: false,
        ..context()
    };
    assert_eq!(
        consume_server_callback(&plain(requester), &idle),
        refused(ServerCallbackRefusal::NotServing)
    );
}

/// The address gate is the Reserved Range check with the server as
/// Informant, in both families: loopback stands only on a server on this
/// host, every other reserved range never, and a LAN address is a peer.
#[test]
fn the_requester_address_is_judged_with_the_server_as_informant() {
    for reserved in [
        "127.0.0.1:4662",
        "0.0.0.5:4662",
        "255.255.255.255:4662",
        "224.0.0.1:4662",
        "[fe80::1]:4662",
        "[::1]:4662",
    ] {
        assert_eq!(
            consume_server_callback(&plain(reserved), &context()),
            refused(ServerCallbackRefusal::ReservedAddress),
            "{reserved}"
        );
    }
    for peer in ["10.0.0.8:4662", "[2001:db8::7]:4662", "[fd00::7]:4662"] {
        assert_eq!(
            consume_server_callback(&plain(peer), &context()),
            dialed(peer, None),
            "{peer}"
        );
    }
    let local_server = ServerCallbackContext {
        server: Informant::Party(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ..context()
    };
    assert_eq!(
        consume_server_callback(&plain("127.0.0.1:4662"), &local_server),
        dialed("127.0.0.1:4662", None),
        "a server on this host names this host truly"
    );
}

/// The self-connect guard reads our public address and port in the
/// requester's family: our own IPv4 or IPv6 at our port is refused, the same
/// address at another port is somebody else's listener.
#[test]
fn our_own_listen_endpoint_is_refused_in_either_family() {
    let own = SharedOwnIdentity::default();
    own.addresses()
        .observe(AddressObservation::server_high_id(Ipv4Addr::new(
            203, 0, 113, 4,
        )));
    // An IPv6 reflection stands only once this host holds the address.
    let ipv6: IpAddr = "2001:db8::4".parse().unwrap();
    own.addresses().refresh_interfaces(&[ipv6]);
    own.addresses()
        .observe(AddressObservation::server_reflection(ipv6));
    assert!(own.public_ip().is_some() && own.public_ipv6().is_some());
    let ctx = ServerCallbackContext {
        own: OwnListenEndpoint::current(&own, OUR_PORT),
        ..context()
    };
    for us in ["203.0.113.4:4662", "[2001:db8::4]:4662"] {
        assert_eq!(
            consume_server_callback(&plain(us), &ctx),
            refused(ServerCallbackRefusal::SelfConnect),
            "{us}"
        );
    }
    for other in ["203.0.113.4:4663", "[2001:db8::4]:4663", "203.0.113.5:4662"] {
        assert_eq!(
            consume_server_callback(&plain(other), &ctx),
            dialed(other, None),
            "{other}"
        );
    }
    assert!(
        !OwnListenEndpoint::current(&own, OUR_PORT).matches(PeerEndpoint::V4(Ipv4Endpoint::new(
            Ipv4Addr::new(203, 0, 113, 4),
            4663
        ))),
        "the port is half the match"
    );
}

/// The `0x35` crypt extension is the requester's stance for this one dial,
/// met with ours by ADR-0049's rule: obfuscated toward the extension's own
/// hash when both support and one asks, plaintext when neither asks, refused
/// before a socket when the pair cannot meet — including the 6-byte form and
/// every `0x26`, which state no stance, under a policy that requires crypt.
#[test]
fn the_crypt_extension_is_the_dials_stance_and_its_absence_reads_unknown() {
    let requester = "198.51.100.7:4662";
    let under = |crypt| ServerCallbackContext { crypt, ..context() };
    // supports + requests
    assert_eq!(
        consume_server_callback(
            &stating(requester, 0x03),
            &under(Some(ObfuscationPolicy::Supported))
        ),
        dialed(requester, Some(REQUESTER_HASH))
    );
    // supports only, met by a node that only supports
    assert_eq!(
        consume_server_callback(
            &stating(requester, 0x01),
            &under(Some(ObfuscationPolicy::Supported))
        ),
        dialed(requester, None)
    );
    // supports only, met by a node that requests
    assert_eq!(
        consume_server_callback(
            &stating(requester, 0x01),
            &under(Some(ObfuscationPolicy::Requested))
        ),
        dialed(requester, Some(REQUESTER_HASH))
    );
    // requires, met by a node with crypt off
    assert_eq!(
        consume_server_callback(&stating(requester, 0x07), &under(None)),
        refused(ServerCallbackRefusal::CryptIncompatible)
    );
    // no extension: plaintext under Requested, refused under Required
    assert_eq!(
        consume_server_callback(
            &plain(requester),
            &under(Some(ObfuscationPolicy::Requested))
        ),
        dialed(requester, None)
    );
    for no_stance in [requester, "[2001:db8::7]:4662"] {
        assert_eq!(
            consume_server_callback(&plain(no_stance), &under(Some(ObfuscationPolicy::Required))),
            refused(ServerCallbackRefusal::CryptIncompatible),
            "{no_stance}"
        );
    }
}
