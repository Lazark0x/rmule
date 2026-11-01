//! The seed list the binary carries, the root of trust of a cold start
//! (ADR-0120).
//!
//! `seeds.txt` beside this crate's manifest is one checked-in data file,
//! refreshed by each release and compiled in. A [`Seeds`] value travels on
//! [`BootstrapConfig`](crate::BootstrapConfig), which starts with none: only a
//! deployment that means to name public hosts asks for [`Seeds::embedded`].

use std::net::{IpAddr, SocketAddr, SocketAddrV4};

use rmule_primitives::{Informant, ServerEndpoint};
use thiserror::Error;

/// The file `Seeds::embedded` reads.
const SEED_FILE: &str = include_str!("../seeds.txt");

/// Why a seed file does not read. The compiled-in file is proven to read by a
/// test, so this is what a release's edit of it trips on.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SeedFileError {
    /// A line that is neither blank, a comment, nor a `server` or `kad` entry.
    #[error("seed file line {line}: not an entry")]
    NotAnEntry {
        /// The line, counted from one.
        line: usize,
    },
    /// An entry whose address and port do not read, a `kad` entry on IPv6
    /// included (Kad is IPv4 here), or whose port is zero.
    #[error("seed file line {line}: not an address and port")]
    BadAddress {
        /// The line, counted from one.
        line: usize,
    },
    /// An entry in a Reserved Range: no seed can be at it.
    #[error("seed file line {line}: a reserved address")]
    Reserved {
        /// The line, counted from one.
        line: usize,
    },
}

/// The servers and Kad nodes a cold start begins from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Seeds {
    servers: Vec<ServerEndpoint>,
    kad_nodes: Vec<SocketAddrV4>,
}

impl Seeds {
    /// The list compiled into this binary. An unreadable file reads as no
    /// seeds, which a cold start states: a test keeps it from shipping.
    #[must_use]
    pub fn embedded() -> Self {
        Self::parse(SEED_FILE).unwrap_or_else(|error| {
            tracing::error!(%error, "the compiled-in seed list does not read");
            Self::default()
        })
    }

    /// Read a seed file.
    ///
    /// # Errors
    /// The first line that is not an entry, or names no address a seed can be
    /// at.
    pub fn parse(text: &str) -> Result<Self, SeedFileError> {
        let mut seeds = Self::default();
        for (index, line) in text.lines().enumerate() {
            let line_number = index + 1;
            let entry = line.split('#').next().unwrap_or_default().trim();
            if entry.is_empty() {
                continue;
            }
            let (kind, address) = entry
                .split_once(char::is_whitespace)
                .ok_or(SeedFileError::NotAnEntry { line: line_number })?;
            let address = address.trim();
            match kind {
                "server" => seeds.servers.push(server(address, line_number)?),
                "kad" => seeds.kad_nodes.push(kad_node(address, line_number)?),
                _ => return Err(SeedFileError::NotAnEntry { line: line_number }),
            }
        }
        Ok(seeds)
    }

    /// The eD2k servers, in file order.
    #[must_use]
    pub fn servers(&self) -> &[ServerEndpoint] {
        &self.servers
    }

    /// The Kad nodes, in file order.
    #[must_use]
    pub fn kad_nodes(&self) -> &[SocketAddrV4] {
        &self.kad_nodes
    }

    /// Whether this list holds no entry at all: a build with no root of trust.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty() && self.kad_nodes.is_empty()
    }
}

/// An address and non-zero port rmule's own word can stand behind.
fn checked(address: &str, line: usize) -> Result<SocketAddr, SeedFileError> {
    let parsed: SocketAddr = address
        .parse()
        .map_err(|_| SeedFileError::BadAddress { line })?;
    if parsed.port() == 0 {
        return Err(SeedFileError::BadAddress { line });
    }
    if !Informant::Own.admits(parsed.ip()) {
        return Err(SeedFileError::Reserved { line });
    }
    Ok(parsed)
}

fn server(address: &str, line: usize) -> Result<ServerEndpoint, SeedFileError> {
    let parsed = checked(address, line)?;
    let host = match parsed.ip() {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => ip.to_string(),
    };
    ServerEndpoint::new(host, parsed.port()).map_err(|_| SeedFileError::BadAddress { line })
}

fn kad_node(address: &str, line: usize) -> Result<SocketAddrV4, SeedFileError> {
    match checked(address, line)? {
        SocketAddr::V4(node) => Ok(node),
        SocketAddr::V6(_) => Err(SeedFileError::BadAddress { line }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a release ships must read: `embedded` would turn a bad edit into
    /// a build that silently has no root of trust.
    #[test]
    fn the_shipped_seed_file_reads() {
        Seeds::parse(SEED_FILE).expect("seeds.txt");
    }

    #[test]
    fn a_seed_file_reads_entries_in_order_past_comments_and_blanks() {
        let seeds = Seeds::parse(
            "# a comment\n\
             \n\
             server 192.0.2.1:4661  # the first\n\
             server [2001:db8::1]:4242\n\
             kad 198.51.100.1:4672\n\
             \tserver 203.0.113.9:4661\n",
        )
        .expect("a well-formed file");

        assert_eq!(seeds.servers().len(), 3);
        assert_eq!(seeds.servers()[0].host(), "192.0.2.1");
        assert_eq!(seeds.servers()[1].host(), "2001:db8::1");
        assert_eq!(seeds.servers()[1].port(), 4242);
        assert_eq!(seeds.servers()[2].host(), "203.0.113.9");
        assert_eq!(
            seeds.kad_nodes(),
            ["198.51.100.1:4672".parse::<SocketAddrV4>().unwrap()]
        );
    }

    #[test]
    fn a_bad_line_is_named_not_skipped() {
        for (text, expected) in [
            ("# ok\nnonsense\n", SeedFileError::NotAnEntry { line: 2 }),
            ("peer 192.0.2.1:4661", SeedFileError::NotAnEntry { line: 1 }),
            ("server 192.0.2.1", SeedFileError::BadAddress { line: 1 }),
            ("server 192.0.2.1:0", SeedFileError::BadAddress { line: 1 }),
            (
                "server mirror.example:4661",
                SeedFileError::BadAddress { line: 1 },
            ),
            (
                "kad [2001:db8::1]:4672",
                SeedFileError::BadAddress { line: 1 },
            ),
            ("server 224.0.0.1:4661", SeedFileError::Reserved { line: 1 }),
            ("kad 169.254.0.1:4672", SeedFileError::Reserved { line: 1 }),
        ] {
            assert_eq!(Seeds::parse(text), Err(expected), "{text}");
        }
    }

    #[test]
    fn a_file_of_comments_is_no_seeds_at_all() {
        assert!(Seeds::parse("# nothing yet\n\n").expect("legal").is_empty());
    }
}
