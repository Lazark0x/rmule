//! The `ed2k parse-link` / `canonical-link` commands: decode an `ed2k://` URI
//! and print it back, either field by field or in its canonical spelling.

use anyhow::Result;
use rmule_primitives::{Ed2kFileLink, Ed2kLink};

pub(crate) fn parse_link(link: &str) -> Result<()> {
    let parsed = Ed2kLink::parse(link)?;
    print_link_summary(&parsed);
    Ok(())
}

pub(crate) fn canonical_link(link: &str) -> Result<()> {
    let parsed = Ed2kLink::parse(link)?;
    println!("{parsed}");
    Ok(())
}

fn print_link_summary(link: &Ed2kLink) {
    match link {
        Ed2kLink::File(file) => {
            println!("kind: file");
            println!("name: {}", file.name.to_display_string());
            println!("size: {}", file.size);
            println!("file_hash: {}", file.file_hash.to_hex_upper());
            let part_hashes = file.part_hash_set.as_ref().map_or(&[][..], |s| s.hashes());
            println!("part_hash_count: {}", part_hashes.len());
            for hash in part_hashes {
                println!("part_hash: {}", hash.to_hex_upper());
            }
            match &file.aich_root {
                Some(root) => println!("aich_root: {}", root.to_base32_upper()),
                None => println!("aich_root: none"),
            }
            print_file_sources(file);
        }
        Ed2kLink::Server(server) => {
            println!("kind: server");
            println!("host: {}", server.endpoint.host());
            println!("port: {}", server.endpoint.port());
        }
        Ed2kLink::ServerList(list) => {
            println!("kind: serverlist");
            println!("address: {}", list.address);
        }
    }
    println!("canonical_link: {link}");
}

/// The link's source hints (ADR-0089): the `sources,` peers
/// with what each named beside its address, the `s6=` IPv6 sources, and the
/// `s=` web sources.
fn print_file_sources(file: &Ed2kFileLink) {
    let peers = file.sources.peers();
    println!("source_count: {}", peers.len());
    for peer in peers {
        let mut line = format!("source: {}:{}", peer.host, peer.port);
        if let Some(crypt) = peer.crypt {
            line.push_str(&format!(" crypt=0x{:02X}", crypt.as_byte()));
        }
        if let Some(hash) = peer.user_hash {
            line.push_str(&format!(" user_hash={}", hash.to_hex_upper()));
        }
        if let Some(expires) = peer.expires {
            line.push_str(&format!(
                " expires={:04}-{:02}-{:02}",
                expires.year(),
                expires.month(),
                expires.day()
            ));
        }
        println!("{line}");
    }
    println!("ipv6_source_count: {}", file.ipv6_sources.len());
    for source in &file.ipv6_sources {
        println!("ipv6_source: {source}");
    }
    let web = file.sources.web();
    println!("web_source_count: {}", web.len());
    for url in web {
        println!("web_source: {url}");
    }
}
