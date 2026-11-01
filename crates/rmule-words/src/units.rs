//! The units for the data a sentence carries: an address as `host:port`, a
//! hash or a Kad id as its short hex form, a wait in whole seconds, a byte
//! quantity in binary units. Fragments, never sentences of their own.

use std::net::IpAddr;
use std::time::Duration;

use crate::absent;

use rmule_primitives::{FileHash, PeerEndpoint, ServerEndpoint};

/// How many hex digits a short hash keeps.
const SHORT_HEX_DIGITS: usize = 10;

/// A peer as `host:port`; an IPv6 host in brackets, so the port reads apart.
#[must_use]
pub fn address(peer: PeerEndpoint) -> String {
    match peer.ip() {
        IpAddr::V4(ip) => format!("{ip}:{}", peer.port()),
        IpAddr::V6(ip) => format!("[{ip}]:{}", peer.port()),
    }
}

/// A server as `host:port` — the one spelling the status feed, the log and
/// the Servers tab's modals share, so a flash and a confirm never name the
/// same server differently.
#[must_use]
pub fn server_label(server: &ServerEndpoint) -> String {
    format!("{}:{}", server.host(), server.port())
}

/// The short hex form of a file hash, a user hash or a Kad id (spec §3.5):
/// its first ten upper-case hex digits and `…`, so every
/// surface that abbreviates an identity reads alike.
#[must_use]
pub fn short_hex(bytes: &[u8]) -> String {
    let mut short: String = bytes
        .iter()
        .flat_map(|byte| {
            let hex = format!("{byte:02X}");
            hex.chars().collect::<Vec<_>>()
        })
        .take(SHORT_HEX_DIGITS)
        .collect();
    short.push('…');
    short
}

/// A file hash in its short hex form.
#[must_use]
pub fn short_hash(hash: FileHash) -> String {
    short_hex(hash.as_bytes())
}

/// [`short_hash`], or the word for a hash not yet known.
#[must_use]
pub fn short_hash_or_unknown(hash: Option<FileHash>) -> String {
    hash.map_or_else(|| absent::UNKNOWN.to_string(), short_hash)
}

/// A wait in whole seconds, rounded up: a request due in 300 ms is "1 s",
/// never "0 s".
#[must_use]
pub fn seconds(wait: Duration) -> u64 {
    wait.as_millis()
        .div_ceil(1000)
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Bytes → a compact binary-unit size (KB/MB/GB, 1 decimal), matching the
/// status bar's `KB/s` convention (÷1024).
///
/// Shared by every surface that renders a byte quantity — a download's size,
/// the Statistics session totals, a sentence that names one: two renderers of
/// the same quantity must not disagree about unit or precision.
#[must_use]
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{} {}", decimal(value), UNITS[unit])
    }
}

/// `value` to one decimal place, the one spelling of a fraction: a language
/// writes its point here.
#[must_use]
pub fn decimal(value: f64) -> String {
    format!("{value:.1}")
}

/// A whole percent.
#[must_use]
pub fn percent(value: u64) -> String {
    format!("{value}%")
}

/// A count in five cells at most, rounded to the nearest: exact under ten
/// thousand, then one decimal while that fits, so `1,999,999` reads `2.0M` and
/// never the `1M` a cut would say.
#[must_use]
pub fn short_count(n: u64) -> String {
    const KILO: f64 = 1_000.0;
    const MEGA: f64 = 1_000_000.0;
    if n < 10_000 {
        return n.to_string();
    }
    let n = n as f64;
    // What rounding would carry past 999k reads in the next unit.
    let (value, unit) = if n < 999_500.0 {
        (n / KILO, "k")
    } else {
        (n / MEGA, "M")
    };
    if value < 99.95 {
        format!("{}{unit}", decimal(value))
    } else {
        format!("{value:.0}{unit}")
    }
}

/// The units a rate reads in, each 1024 of the one before it, whole and in
/// the short form.
const RATE_UNITS: [(&str, &str); 4] = [("KB/s", "K"), ("MB/s", "M"), ("GB/s", "G"), ("TB/s", "T")];

/// `bps` in the first unit that holds it in three digits before the point.
/// The test is on what one decimal prints, so `999.96` reads `1.0 MB/s`
/// rather than `1000.0 KB/s`.
fn scaled_rate(bps: f64) -> (f64, usize) {
    let mut value = bps / 1024.0;
    let mut unit = 0;
    while value >= 999.95 && unit + 1 < RATE_UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    (value, unit)
}

/// Bytes/sec → the rate text every meter renders: the status bar's ▼/▲, the
/// downloads **Speed** column, the sources pane, the upload-peers pane. One
/// definition, so no two meters can disagree about unit or precision.
#[must_use]
pub fn rate(bps: f64) -> String {
    let (value, unit) = scaled_rate(bps);
    format!("{} {}", decimal(value), RATE_UNITS[unit].0)
}

/// The same reading for a frame too narrow for [`rate`]: `45.6K`.
#[must_use]
pub fn rate_short(bps: f64) -> String {
    let (value, unit) = scaled_rate(bps);
    format!("{}{}", decimal(value), RATE_UNITS[unit].1)
}

/// The cells the widest [`rate`] takes. A meter that must not move
/// right-aligns in this many; a column of rates keeps it as its floor.
#[must_use]
pub fn rate_cells() -> usize {
    RATE_UNITS
        .iter()
        .map(|(unit, _)| unit.chars().count())
        .max()
        .unwrap_or(0)
        + decimal(999.9).chars().count()
        + 1
}

/// The cells the widest [`rate_short`] takes.
#[must_use]
pub fn rate_short_cells() -> usize {
    RATE_UNITS
        .iter()
        .map(|(_, unit)| unit.chars().count())
        .max()
        .unwrap_or(0)
        + decimal(999.9).chars().count()
}

/// The size a column of sizes keeps room for.
pub const WIDEST_SIZE: u64 = 1_073_636_966;

/// What a typed size unit multiplies by; nothing for a unit it is not.
#[must_use]
pub fn size_unit(unit: &str) -> Option<u64> {
    match unit.to_lowercase().as_str() {
        "" | "b" => Some(1),
        "k" | "kb" => Some(1024),
        "m" | "mb" => Some(1024 * 1024),
        "g" | "gb" => Some(1024 * 1024 * 1024),
        "t" | "tb" => Some(1024_u64.pow(4)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rounded count says the nearest, never the one a cut would: it rides
    /// beside exact figures, and `1M` beside `2M` reads as half.
    #[test]
    fn a_count_rounds_to_the_nearest_and_fits_five_cells() {
        for (n, reads) in [
            (9_999, "9999"),
            (10_000, "10.0k"),
            (12_345, "12.3k"),
            (99_949, "99.9k"),
            (99_950, "100k"),
            (431_000, "431k"),
            (999_499, "999k"),
            (999_500, "1.0M"),
            (1_000_000, "1.0M"),
            (1_999_999, "2.0M"),
            (99_949_999, "99.9M"),
            (u64::from(u32::MAX), "4295M"),
        ] {
            assert_eq!(short_count(n), reads);
        }
    }

    #[test]
    fn sizes_step_through_the_binary_units_at_one_decimal() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1536), "1.5 KB");
        assert_eq!(human_size(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.0 GB");
        assert_eq!(human_size(1 << 40), "1.0 TB");
    }
}
