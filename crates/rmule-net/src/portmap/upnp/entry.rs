//! `GetSpecificPortMappingEntry`, the one UPnP-IGD question that says whom an
//! external port forwards to, asked before every delete (ADR-0086, "A release
//! takes down only rmule's own mapping"). `igd-next` does not issue it.
//!
//! It is spoken the way `igd-next` speaks every other action: the same
//! blocking HTTP client, the same control URL, and the same `WANIPConnection:1`
//! service type in the `SOAPAction` header and the body. So the check reaches
//! every device the delete it guards reaches.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use igd_next::PortMappingProtocol;

use super::super::{MappingError, MappingRefusal};
use super::{refusal, transport};

/// The action, as the `SOAPAction` header names it: quoted, the way
/// `igd-next` sends its own.
const ACTION: &str =
    r#""urn:schemas-upnp-org:service:WANIPConnection:1#GetSpecificPortMappingEntry""#;

/// `NoSuchEntryInArray`: the gateway holds no entry on that port.
const NO_SUCH_ENTRY: u16 = 714;

/// `Invalid Action`: the device does not implement the question.
const INVALID_ACTION: u16 = 401;

/// `Action not authorized`: the device will not answer this host.
const NOT_AUTHORIZED: u16 = 606;

/// How long the check may take. A LAN gateway answers in milliseconds; this
/// bounds the blocking thread a gateway that stopped answering would hold.
const CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// The internal endpoint `external_port` forwards to, or `None` when the
/// gateway holds no entry on it.
pub(super) fn forwards_to(
    device: &igd_next::Gateway,
    protocol: PortMappingProtocol,
    external_port: u16,
) -> Result<Option<SocketAddr>, MappingError> {
    let answer = attohttpc::post(format!("http://{}{}", device.addr, device.control_url))
        .header("SOAPAction", ACTION)
        .header("Content-Type", "text/xml")
        .connect_timeout(CHECK_TIMEOUT)
        .timeout(CHECK_TIMEOUT)
        .text(question(protocol, external_port))
        .send()
        .and_then(attohttpc::Response::text)
        .map_err(|error| transport(&error))?;
    read_answer(&answer)
}

/// The SOAP envelope asking about `external_port`.
fn question(protocol: PortMappingProtocol, external_port: u16) -> String {
    format!(
        r#"<?xml version="1.0"?>
<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body><u:GetSpecificPortMappingEntry xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewRemoteHost></NewRemoteHost><NewExternalPort>{external_port}</NewExternalPort><NewProtocol>{protocol}</NewProtocol></u:GetSpecificPortMappingEntry></s:Body>
</s:Envelope>"#
    )
}

/// Read the gateway's answer: the entry's internal endpoint, no entry, or the
/// fault it named instead.
fn read_answer(answer: &str) -> Result<Option<SocketAddr>, MappingError> {
    let unreadable = |why: &str| refusal(&why, MappingRefusal::BadAnswer);
    let envelope = xmltree::Element::parse(answer.as_bytes())
        .map_err(|error| refusal(&error, MappingRefusal::BadAnswer))?;
    let body = envelope
        .get_child("Body")
        .ok_or_else(|| unreadable("an answer with no SOAP body"))?;
    if let Some(entry) = body.get_child("GetSpecificPortMappingEntryResponse") {
        let field = |name: &str| {
            entry
                .get_child(name)
                .and_then(xmltree::Element::get_text)
                .map(|text| text.trim().to_owned())
        };
        // The spec lets a gateway name the internal client by host name; one
        // that does cannot be compared with our address, so it is unreadable
        // here rather than taken for ours.
        let client = field("NewInternalClient")
            .and_then(|text| text.parse::<IpAddr>().ok())
            .ok_or_else(|| unreadable("an entry naming no internal address"))?;
        let port = field("NewInternalPort")
            .and_then(|text| text.parse::<u16>().ok())
            .ok_or_else(|| unreadable("an entry naming no internal port"))?;
        return Ok(Some(SocketAddr::new(client, port)));
    }
    let code = body
        .get_child("Fault")
        .and_then(|fault| fault.get_child("detail"))
        .and_then(|detail| detail.get_child("UPnPError"))
        .and_then(|error| error.get_child("errorCode"))
        .and_then(xmltree::Element::get_text)
        .and_then(|text| text.trim().parse::<u16>().ok())
        .ok_or_else(|| unreadable("an answer that is neither an entry nor a UPnP fault"))?;
    match code {
        NO_SUCH_ENTRY => Ok(None),
        INVALID_ACTION => Err(refusal(&code, MappingRefusal::Unsupported)),
        NOT_AUTHORIZED => Err(refusal(&code, MappingRefusal::NotAuthorized)),
        other => Err(refusal(&other, MappingRefusal::UnknownCode(other))),
    }
}
