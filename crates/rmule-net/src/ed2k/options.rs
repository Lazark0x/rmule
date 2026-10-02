//! The knobs a caller sets before dialing an eD2k server: the two timeouts the
//! runtime distinguishes, where captures land, and the obfuscation policy for
//! the connection.

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
    /// Protocol obfuscation policy for this server connection (ADR-0042), or
    /// `None` to connect plaintext. `Requested`/`Required` attempt an obfuscated
    /// DH handshake first; `Requested` falls back to plaintext on failure.
    pub obfuscation: Option<ObfuscationConfig>,
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
            advertised_ipv6: None,
            udp_ports: None,
        }
    }
}
