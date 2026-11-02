//! The Networks tab's own words: the servers pane's title and figures, and the
//! Kad panel's rows.

/// How the bottom border names the Kad panel when it gave way, and its title.
pub const KAD: &str = "Kad";
/// The Kad panel's title.
pub const KAD_TITLE: &str = " Kad ";
/// A Kad fact with no firewall check run yet.
pub const NOT_CHECKED: &str = "not checked yet";
/// The firewall verdicts.
pub const OPEN: &str = "open";
/// A check under way.
pub const CHECKING: &str = "checking";
/// A closed verdict.
pub const FIREWALLED: &str = "firewalled";
/// A UDP check whose helpers concluded firewalled.
pub const UDP_FIREWALLED: &str = "firewalled · helpers failed";
/// A UDP check with no helper yet.
pub const UDP_UNVERIFIED: &str = "unverified · no helper yet";
/// A node someone answered.
pub const YES: &str = "yes";
/// A row's known no.
pub const NO: &str = "no";
/// A node nobody answered yet: nobody has answered us, never that it fails.
pub const NOT_YET: &str = "not yet";
/// Joined.
pub const JOINED: &str = "Joined";
/// Contacts.
pub const CONTACTS: &str = "Contacts";
/// Firewall.
pub const FIREWALL: &str = "Firewall";
/// UDP.
pub const UDP: &str = "UDP";
/// Keywords.
pub const KEYWORDS: &str = "Keywords";
/// Node id.
pub const NODE_ID: &str = "Node id";
/// Received.
pub const RECEIVED: &str = "Received";
/// Sent.
pub const SENT: &str = "Sent";
/// Every label on the panel, which its label column is sized to.
pub const KAD_LABELS: [&str; 8] = [
    JOINED, CONTACTS, FIREWALL, UDP, KEYWORDS, NODE_ID, RECEIVED, SENT,
];
/// A list update under way.
pub const UPDATING: &str = " updating… ";
/// The menu item's wait while one is out.
pub const UPDATE_IN_FLIGHT: &str = "update in flight";
/// A row action with no row.
pub const NO_SERVER_SELECTED: &str = "no server selected";
/// The empty servers pane.
pub const NO_SERVERS: &str = "no servers — press a to add one, or U to update the list from a URL";
/// A low priority, in its four cells.
pub const PRIO_LOW: &str = "Low";
/// A normal priority.
pub const PRIO_NORMAL: &str = "Norm";
/// A high priority.
pub const PRIO_HIGH: &str = "High";

/// The firewall row: the verdict, then why.
#[must_use]
pub fn firewall(verdict: &str, why: &str) -> String {
    format!("{verdict} · {why}")
}

/// How many dial-backs a check drew.
#[must_use]
pub fn dial_backs(acks: impl std::fmt::Display, needed: impl std::fmt::Display) -> String {
    format!("{acks}/{needed} dial-backs")
}

/// A UDP check a helper reached.
#[must_use]
pub fn udp_open(port: u16) -> String {
    format!("open · port {port}")
}

/// One direction of Kad traffic.
#[must_use]
pub fn traffic(rate: &str, bytes: &str) -> String {
    format!("{rate} · {bytes}")
}

/// The menu's priority row, what it is and what a press makes it.
#[must_use]
pub fn priority_step(now: &str, next: &str) -> String {
    format!("Priority: {now} → {next}")
}

/// A measured round trip in milliseconds.
#[must_use]
pub fn ping_ms(ms: u128) -> String {
    format!("{ms}ms")
}

/// A measured round trip in seconds.
#[must_use]
pub fn ping_s(seconds: f64) -> String {
    format!("{}s", crate::words::units::decimal(seconds))
}

/// How long ago a server answered, in three cells.
#[must_use]
pub fn age(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs}s"),
        60..3_600 => format!("{}m", secs / 60),
        3_600..172_800 => format!("{}h", secs / 3_600),
        172_800..8_640_000 => format!("{}d", secs / 86_400),
        _ => format!("{}w", secs / 604_800),
    }
}

/// The servers pane's title with a session.
#[must_use]
pub fn servers_connected(count: usize, server: &str, high_id: bool) -> String {
    let class = if high_id { "HighID" } else { "LowID" };
    format!(" Servers ({count}) · {server} {class} ")
}

/// The servers pane's title around a clause.
#[must_use]
pub fn servers_title(count: usize, clause: &str) -> String {
    format!(" Servers ({count}) · {clause} ")
}

/// The servers pane's title with no session.
#[must_use]
pub fn servers_off(count: usize) -> String {
    servers_title(count, "not connected")
}

/// The status bar's reading of the connected server.
#[must_use]
pub fn users_and_files(users: &str, files: &str) -> String {
    format!("Users: {users} · Files: {files}")
}
