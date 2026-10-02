//! Identity conversions: the forms a flow hands to containers and reads back
//! out of captures — lowercase hex for Kad IDs and hashes, dotted-quad IPv4
//! for static addresses, and the ed2k link with an explicit source. Pure
//! functions; nothing here touches the bench.

use std::net::Ipv4Addr;

use anyhow::{Context, Result, anyhow};

/// Lowercase hex, two digits per byte, no separator.
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Dotted-quad text for static-IP octets.
pub(crate) fn ipv4_string(octets: [u8; 4]) -> String {
    Ipv4Addr::from(octets).to_string()
}

/// Parse dotted-quad IPv4 into octets for a `KadNodeSpec`.
pub(crate) fn parse_ipv4_octets(ip: &str) -> Result<[u8; 4]> {
    let addr: Ipv4Addr = ip
        .parse()
        .with_context(|| format!("parse ipv4 address {ip}"))?;
    Ok(addr.octets())
}

/// Parse the 16-byte ED2K file hash out of `ed2k://|file|NAME|SIZE|HEX32|/`.
pub(crate) fn parse_ed2k_file_hash(link: &str) -> Result<[u8; 16]> {
    let hex = link
        .split('|')
        .nth(4)
        .ok_or_else(|| anyhow!("ed2k link has no hash field: {link}"))?;
    hex.parse_hex16()
        .ok_or_else(|| anyhow!("ed2k link hash is not 32 hex chars: {hex:?}"))
}

/// `link` with `ip:port` appended as an explicit source, the form aMule dials
/// directly.
pub(crate) fn ed2k_link_with_source(link: &str, ip: &str, port: u16) -> String {
    if let Some(prefix) = link.strip_suffix("|/") {
        format!("{prefix}|/|sources,{ip}:{port}|/")
    } else {
        format!("{link}|sources,{ip}:{port}|/")
    }
}

/// Parse a 32-hex string into 16 bytes; `None` on malformed input.
pub(crate) trait ParseHex16 {
    /// The 16 bytes, or `None` unless exactly 32 hex digits.
    fn parse_hex16(&self) -> Option<[u8; 16]>;
}

impl ParseHex16 for str {
    fn parse_hex16(&self) -> Option<[u8; 16]> {
        if self.len() != 32 || !self.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let mut out = [0u8; 16];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&self[index * 2..index * 2 + 2], 16).ok()?;
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed2k_link_hash_field_is_the_fifth_pipe_field() {
        let link = "ed2k://|file|shared.bin|65536|8E302DB5B806A25C9385FC23F21062D2|/";
        let hash = parse_ed2k_file_hash(link).unwrap();
        assert_eq!(hash[0], 0x8E);
        assert_eq!(hash[15], 0xD2);
        assert!(parse_ed2k_file_hash("ed2k://|file|x|1|fakehash|/").is_err());
    }

    #[test]
    fn link_with_source_keeps_the_trailing_slash_form() {
        assert_eq!(
            ed2k_link_with_source("ed2k://|file|a|1|00|/", "10.0.0.2", 4663),
            "ed2k://|file|a|1|00|/|sources,10.0.0.2:4663|/"
        );
    }
}
