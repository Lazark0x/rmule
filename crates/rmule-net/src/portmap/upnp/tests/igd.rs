//! A UPnP-IGD gateway on loopback that keeps a port-mapping table the way
//! miniupnpd does with `secure_mode=no`: a mapping is keyed by external port
//! and protocol, an add on a port another client holds is refused with
//! `ConflictInMappingEntry` (718), and a delete is obeyed whoever sends it.
//! Its answers are shaped like miniupnpd 2.3.10's. It is a fake: what it
//! proves is the order of rmule's questions, never a real gateway's answers.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

/// Where `AddAnyPortMapping` starts looking when the asked port is taken.
const FIRST_SPARE_PORT: u16 = 53906;

/// One running fake gateway.
pub(super) struct FakeIgd {
    address: SocketAddr,
    state: Arc<Mutex<State>>,
}

#[derive(Default)]
struct State {
    /// (external port, protocol) → the internal endpoint it forwards to.
    table: BTreeMap<(u16, String), SocketAddr>,
    /// The external port of every `DeletePortMapping` asked, in order.
    deletes: Vec<u16>,
    /// A fault code to answer `GetSpecificPortMappingEntry` with instead.
    check_fault: Option<u16>,
}

impl FakeIgd {
    /// Start answering on a loopback port.
    pub(super) fn start() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind the fake gateway");
        let address = listener.local_addr().expect("fake gateway address");
        let state = Arc::new(Mutex::new(State::default()));
        let served = Arc::clone(&state);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                answer(stream, &served);
            }
        });
        Self { address, state }
    }

    /// The device as SSDP discovery would hand it to `igd-next`.
    pub(super) fn device(&self) -> igd_next::Gateway {
        let schema = |arguments: &[&str]| arguments.iter().map(|&a| a.to_owned()).collect();
        let add = [
            "NewRemoteHost",
            "NewExternalPort",
            "NewProtocol",
            "NewInternalPort",
            "NewInternalClient",
            "NewEnabled",
            "NewPortMappingDescription",
            "NewLeaseDuration",
        ];
        igd_next::Gateway {
            addr: self.address,
            root_url: "/rootDesc.xml".to_owned(),
            control_url: "/ctl/IPConn".to_owned(),
            control_schema_url: "/WANIPCn.xml".to_owned(),
            control_schema: [
                ("AddPortMapping".to_owned(), schema(&add)),
                ("AddAnyPortMapping".to_owned(), schema(&add)),
                (
                    "DeletePortMapping".to_owned(),
                    schema(&["NewRemoteHost", "NewExternalPort", "NewProtocol"]),
                ),
            ]
            .into_iter()
            .collect(),
        }
    }

    /// What TCP `external_port` forwards to now.
    pub(super) fn forwards(&self, external_port: u16) -> Option<SocketAddr> {
        let state = self.state.lock().expect("fake gateway state");
        state.table.get(&(external_port, "TCP".to_owned())).copied()
    }

    /// Every TCP mapping in the table.
    pub(super) fn rows(&self) -> Vec<(u16, SocketAddr)> {
        let state = self.state.lock().expect("fake gateway state");
        state
            .table
            .iter()
            .map(|((port, _), internal)| (*port, *internal))
            .collect()
    }

    /// The external port of every `DeletePortMapping` asked so far.
    pub(super) fn deletes(&self) -> Vec<u16> {
        self.state
            .lock()
            .expect("fake gateway state")
            .deletes
            .clone()
    }

    /// Answer every `GetSpecificPortMappingEntry` from now on with `code`.
    pub(super) fn fail_checks_with(&self, code: u16) {
        self.state.lock().expect("fake gateway state").check_fault = Some(code);
    }
}

/// Read one request, act on the table, answer, close.
fn answer(stream: TcpStream, state: &Mutex<State>) {
    let mut reader = BufReader::new(stream);
    let mut action = String::new();
    let mut length = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "soapaction" => {
                action = value
                    .trim()
                    .trim_matches('"')
                    .rsplit('#')
                    .next()
                    .unwrap_or("")
                    .to_owned();
            }
            "content-length" => length = value.trim().parse().unwrap_or(0),
            _ => {}
        }
    }
    let mut body = vec![0; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let body = String::from_utf8_lossy(&body);
    let reply = act(
        &action,
        &body,
        &mut state.lock().expect("fake gateway state"),
    );
    let (status, envelope) = match reply {
        Ok(arguments) => (
            "200 OK",
            format!(
                r#"<u:{action}Response xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">{arguments}</u:{action}Response>"#
            ),
        ),
        Err((code, description)) => (
            "500 Internal Server Error",
            format!(
                r#"<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>{code}</errorCode><errorDescription>{description}</errorDescription></UPnPError></detail></s:Fault>"#
            ),
        ),
    };
    let envelope = format!(
        "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>{envelope}</s:Body></s:Envelope>\r\n"
    );
    let mut stream = reader.into_inner();
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{envelope}",
        envelope.len()
    );
}

/// One action against the table: the response's arguments, or a UPnP fault.
fn act(action: &str, body: &str, state: &mut State) -> Result<String, (u16, &'static str)> {
    let argument = |name: &str| {
        let open = format!("<{name}>");
        let start = body.find(&open)? + open.len();
        let end = body[start..].find(&format!("</{name}>"))? + start;
        Some(body[start..end].trim().to_owned())
    };
    let external = argument("NewExternalPort").and_then(|port| port.parse::<u16>().ok());
    let key = |port: u16| (port, argument("NewProtocol").unwrap_or_default());
    let internal = || {
        let address = argument("NewInternalClient")?.parse::<IpAddr>().ok()?;
        let port = argument("NewInternalPort")?.parse::<u16>().ok()?;
        Some(SocketAddr::new(address, port))
    };
    match action {
        "GetExternalIPAddress" => {
            Ok("<NewExternalIPAddress>203.0.113.9</NewExternalIPAddress>".to_owned())
        }
        "AddPortMapping" => {
            let (port, internal) = external.zip(internal()).ok_or((402, "Invalid Args"))?;
            match state.table.get(&key(port)) {
                Some(held) if held.ip() != internal.ip() => Err((718, "ConflictInMappingEntry")),
                _ => {
                    state.table.insert(key(port), internal);
                    Ok(String::new())
                }
            }
        }
        "AddAnyPortMapping" => {
            let (asked, internal) = external.zip(internal()).ok_or((402, "Invalid Args"))?;
            let free = |port: u16| {
                state
                    .table
                    .get(&key(port))
                    .is_none_or(|held| held.ip() == internal.ip())
            };
            let port = std::iter::once(asked)
                .chain(FIRST_SPARE_PORT..)
                .find(|port| free(*port))
                .ok_or((728, "NoPortMapsAvailable"))?;
            state.table.insert(key(port), internal);
            Ok(format!("<NewReservedPort>{port}</NewReservedPort>"))
        }
        "GetSpecificPortMappingEntry" => {
            if let Some(code) = state.check_fault {
                return Err((code, "ActionFailed"));
            }
            let port = external.ok_or((402, "Invalid Args"))?;
            let held = state
                .table
                .get(&key(port))
                .ok_or((714, "NoSuchEntryInArray"))?;
            Ok(format!(
                "<NewInternalPort>{}</NewInternalPort><NewInternalClient>{}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>rmule</NewPortMappingDescription><NewLeaseDuration>120</NewLeaseDuration>",
                held.port(),
                held.ip()
            ))
        }
        "DeletePortMapping" => {
            let port = external.ok_or((402, "Invalid Args"))?;
            state.deletes.push(port);
            state
                .table
                .remove(&key(port))
                .map(|_| String::new())
                .ok_or((714, "NoSuchEntryInArray"))
        }
        _ => Err((401, "Invalid Action")),
    }
}
