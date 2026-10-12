//! The knobs a caller sets before dialing an eD2k server: the two timeouts the
//! runtime distinguishes, where captures land, the crypt stance the login
//! states and whether the link is opened obfuscated.

use std::path::PathBuf;
use std::time::Duration;

use crate::driver::ObfuscationConfig;

/// Tunables for [`Connection::connect_with_options`](crate::ed2k::Connection::connect_with_options).
///
/// Defaults are tighter than aMule's combined `CONSERVTIMEOUT` (25 s) and
/// split into the two failure modes consumers actually distinguish: TCP
/// connect (DNS + SYN) vs. login response (server is up but silent at the
/// protocol layer). See `docs/reference/notes/ed2k-runtime.md`.
#[derive(Clone, Debug)]
pub struct ConnectOptions {
    /// Maximum time `TcpStream::connect` may take before
    /// `DriverError::ConnectTimeout`. Default: 10 s.
    pub connect_timeout: Duration,
    /// Maximum time after TCP is up to observe `LoginAccepted` or
    /// `LoginRejected`. On expiry the session is closed with
    /// `CloseReason::LoginTimeout`. Default: 15 s.
    pub login_timeout: Duration,
    /// If set, the driver writes per-session capture artifacts to this
    /// directory (see ADR-0022); `None` runs without a capture task at all.
    pub capture_dir: Option<PathBuf>,
    /// Our obfuscation policy (ADR-0042), or `None` for none: the crypt
    /// stance the login's `CT_SERVER_FLAGS` states (ADR-0047), whether or not
    /// this link is obfuscated — aMule writes its preference there either
    /// way (`ServerConnect.cpp:273-288`). It opens no obfuscated link by
    /// itself; [`obfuscated_port`](Self::obfuscated_port) does.
    pub obfuscation: Option<ObfuscationConfig>,
    /// Dial this port, the server's obfuscation TCP port, and run the server
    /// form of the crypt handshake (768-bit DH, ADR-0042) before the login;
    /// `None` dials the endpoint's own port plain. Set by a caller whose policy
    /// initiates obfuscation toward a server known to take it there (aMule's
    /// dial gate, `ServerSocket.cpp:786-795`). One attempt: a failed dial or
    /// handshake is returned, and falling back to a plain link is the
    /// caller's call, because only the caller knows its policy allows one.
    pub obfuscated_port: Option<u16>,
    /// Our Known IPv6, when the Advertised Endpoints chooser settled one
    /// (ADR-0084/0087): the login carries `CT_MOD_IP_V6` and the coupled
    /// `SRVCAP_IPV6` bit. `None` sends neither — which is the honest state for
    /// a node that has learned no address it can be reached at.
    pub advertised_ipv6: Option<std::net::Ipv6Addr>,
    /// The login's `CT_EMULE_UDPPORTS` (`0xF9`) — ed2k-server's NAT-T
    /// capability claim (ADR-0091). Set only by a caller holding a bound
    /// client-UDP socket; `None` sends no tag.
    pub udp_ports: Option<rmule_ed2k::UdpPortsAdvert>,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            login_timeout: Duration::from_secs(15),
            capture_dir: None,
            obfuscation: None,
            obfuscated_port: None,
            advertised_ipv6: None,
            udp_ports: None,
        }
    }
}
