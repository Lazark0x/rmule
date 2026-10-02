//! The offline packet inspectors: decode a recorded frame from disk and print
//! its fields. `inspect-packet` reports the envelope alone; the server- and
//! client-packet inspectors walk the body of every opcode the tools capture.

use std::path::Path;

use anyhow::Result;
use rmule_ed2k::{ClientPacket, GetSourcesRequest, LoginRequest, ServerPacket};
use rmule_primitives::{Packet, PeerSource};

use crate::capture::decode_packet_path;

/// Which of the three things a source record can name this one is (ADR-0085).
fn id_kind(source: PeerSource) -> &'static str {
    match source {
        PeerSource::HighId(_) => "high",
        PeerSource::LowId { .. } => "low",
        PeerSource::Ipv6(_) => "ipv6",
    }
}

pub(crate) fn inspect_packet(path: &Path) -> Result<()> {
    let packet = decode_packet_path(path)?;
    println!("protocol: {}", packet.protocol().name());
    println!("opcode: 0x{:02X}", packet.opcode());
    println!("length: {}", packet.encoded_payload_len());
    println!("payload_len: {}", packet.payload().len());
    Ok(())
}

pub(crate) fn inspect_login(path: &Path) -> Result<()> {
    let packet = decode_packet_path(path)?;
    let login = LoginRequest::decode_packet(&packet)?;
    println!("kind: login_request");
    println!("user_hash: {}", login.user_hash().to_hex_upper());
    println!("client_id: {}", login.client_id().as_u32());
    println!("tcp_port: {}", login.tcp_port());
    println!("tag_count: {}", login.tags().len());
    Ok(())
}

pub(super) fn packet_short_name(packet: &Packet) -> &'static str {
    match ServerPacket::decode(packet) {
        Ok(ServerPacket::IdChange(_)) => "id_change",
        Ok(ServerPacket::Reject(_)) => "reject",
        Ok(ServerPacket::ServerMessage(_)) => "server_message",
        Ok(ServerPacket::ServerStatus(_)) => "server_status",
        Ok(ServerPacket::ServerList(_)) => "server_list",
        Ok(ServerPacket::ServerIdent(_)) => "server_ident",
        Ok(ServerPacket::FoundSources(_)) => "found_sources",
        Ok(ServerPacket::FoundSourcesObfu(_)) => "found_sources_obfu",
        Ok(ServerPacket::SearchResults(_)) => "search_results",
        Ok(ServerPacket::PeerCallback(_)) => "peer_callback",
        Ok(ServerPacket::PeerCallbackIpv6(_)) => "peer_callback_ipv6",
        Ok(ServerPacket::CallbackFailed(_)) => "callback_failed",
        Ok(ServerPacket::HolepunchInfo(_)) => "holepunch_info",
        Ok(ServerPacket::HolepunchFail(_)) => "holepunch_fail",
        Ok(ServerPacket::Unknown { .. }) | Err(_) => "unknown",
    }
}

pub(crate) fn inspect_server_packet(path: &Path) -> Result<()> {
    let packet = decode_packet_path(path)?;
    let server_packet = ServerPacket::decode(&packet)?;
    println!("protocol: {}", packet.protocol().name());
    println!("opcode: 0x{:02X}", packet.opcode());
    println!("payload_len: {}", packet.payload().len());
    match server_packet {
        ServerPacket::IdChange(id) => {
            println!("kind: id_change");
            println!("client_id: {}", id.client_id.as_u32());
            match id.tcp_flags {
                Some(flags) => println!("tcp_flags: 0x{:08X}", flags.bits()),
                None => println!("tcp_flags: none"),
            }
        }
        ServerPacket::Reject(_) => {
            println!("kind: reject");
        }
        ServerPacket::ServerMessage(msg) => {
            println!("kind: server_message");
            println!("text_len: {}", msg.text().as_bytes().len());
            println!("text: {}", msg.text().to_display_string());
        }
        ServerPacket::ServerStatus(status) => {
            let report = status.report();
            println!("kind: server_status");
            println!("user_count: {}", report.user_count);
            println!("file_count: {}", report.file_count);
        }
        ServerPacket::ServerList(list) => {
            println!("kind: server_list");
            println!("server_count: {}", list.servers().len());
            for (index, endpoint) in list.servers().iter().enumerate() {
                println!("{index}: {}:{}", endpoint.ip, endpoint.port);
            }
        }
        ServerPacket::ServerIdent(ident) => {
            let identity = ident.identity();
            println!("kind: server_ident");
            println!(
                "server_hash: {}",
                identity
                    .server_hash
                    .map(|h| h.to_hex_upper())
                    .unwrap_or_else(|| "none".to_owned())
            );
            println!(
                "advertised: {}:{}",
                ident.advertised().ip,
                ident.advertised().port
            );
            println!(
                "name: {}",
                identity
                    .name
                    .as_ref()
                    .map(|t| t.to_display_string())
                    .unwrap_or_else(|| "none".to_owned())
            );
            println!(
                "description: {}",
                identity
                    .description
                    .as_ref()
                    .map(|t| t.to_display_string())
                    .unwrap_or_else(|| "none".to_owned())
            );
            println!("extra_tag_count: {}", identity.extra_tags.len());
        }
        ServerPacket::FoundSources(found) => {
            println!("kind: found_sources");
            println!("file_hash: {}", found.file_hash().to_hex_upper());
            println!("source_count: {}", found.sources().len());
            for (index, source) in found.sources().iter().enumerate() {
                println!(
                    "{index}: client_id={} tcp_port={} id_kind={}",
                    source.wire_id(),
                    source.tcp_port(),
                    id_kind(*source)
                );
            }
        }
        ServerPacket::FoundSourcesObfu(found) => {
            println!("kind: found_sources_obfu");
            println!("file_hash: {}", found.file_hash().to_hex_upper());
            println!("source_count: {}", found.sources().len());
            for (index, source) in found.sources().iter().enumerate() {
                let crypt = source.crypt_options().map_or(0, |c| c.as_byte());
                let stance = source.peer_crypt().stance();
                println!(
                    "{index}: client_id={} tcp_port={} id_kind={} crypt_options=0x{crypt:02X} crypt_stance=supports:{}/requests:{}/requires:{}",
                    source.peer_source().wire_id(),
                    source.tcp_port(),
                    id_kind(source.peer_source()),
                    stance.supports(),
                    stance.requests(),
                    stance.requires(),
                );
            }
        }
        ServerPacket::SearchResults(results) => {
            println!("kind: search_results");
            println!("result_count: {}", results.results().len());
            for (index, result) in results.results().iter().enumerate() {
                let availability = result
                    .reported_availability()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_owned());
                println!(
                    "{index}: file_hash={} size={} primary_name={} source_count={} availability={availability}",
                    result.file_hash().to_hex_upper(),
                    result.file_size(),
                    result.primary_name().to_display_string(),
                    result.sources().len(),
                );
            }
        }
        ServerPacket::PeerCallback(cb) => {
            println!("kind: peer_callback");
            println!("peer_ip: {}", cb.peer.ip);
            println!("peer_port: {}", cb.peer.port);
        }
        ServerPacket::PeerCallbackIpv6(cb) => {
            println!("kind: peer_callback_ipv6");
            println!("peer_ip: {}", cb.peer.ip);
            println!("peer_port: {}", cb.peer.port);
        }
        ServerPacket::CallbackFailed(_) => {
            println!("kind: callback_failed");
        }
        ServerPacket::HolepunchInfo(info) => {
            println!("kind: holepunch_info");
            println!("peer_udp: {}", info.peer_udp);
            println!("peer_tcp_port: {}", info.peer_tcp_port);
            println!("peer_hash: {}", info.peer_hash.to_hex_upper());
            println!("role: {:?}", info.role);
        }
        ServerPacket::HolepunchFail(fail) => {
            println!("kind: holepunch_fail");
            println!("target: {}", fail.target.as_u32());
            println!("reason: {:?}", fail.reason);
        }
        ServerPacket::Unknown { opcode, payload } => {
            println!("kind: unknown");
            println!("unknown_opcode: 0x{opcode:02X}");
            println!("unknown_payload_len: {}", payload.len());
        }
    }
    Ok(())
}

pub(crate) fn inspect_client_packet(path: &Path) -> Result<()> {
    let packet = decode_packet_path(path)?;
    let client_packet = ClientPacket::decode(&packet)?;
    println!("protocol: {}", packet.protocol().name());
    println!("opcode: 0x{:02X}", packet.opcode());
    println!("payload_len: {}", packet.payload().len());
    match client_packet {
        ClientPacket::LoginRequest(login) => {
            println!("kind: login_request");
            println!("user_hash: {}", login.user_hash().to_hex_upper());
            println!("client_id: {}", login.client_id().as_u32());
            println!("tcp_port: {}", login.tcp_port());
            println!("tag_count: {}", login.tags().len());
        }
        ClientPacket::GetServerList(_) => {
            println!("kind: get_server_list");
        }
        ClientPacket::QueryMoreResults(_) => {
            println!("kind: query_more_results");
        }
        ClientPacket::SearchRequest(request) => {
            let query = request.query();
            println!("kind: search_request");
            println!("phrase: {}", query.phrase().to_display_string());
            match query.file_type() {
                Some(file_type) => println!("file_type: {file_type:?}"),
                None => println!("file_type: none"),
            }
            match query.min_size() {
                Some(value) => println!("min_size: {value}"),
                None => println!("min_size: none"),
            }
            match query.max_size() {
                Some(value) => println!("max_size: {value}"),
                None => println!("max_size: none"),
            }
            match query.min_availability() {
                Some(value) => println!("min_availability: {value}"),
                None => println!("min_availability: none"),
            }
            match query.extension() {
                Some(value) => println!("extension: {}", value.to_display_string()),
                None => println!("extension: none"),
            }
        }
        ClientPacket::GetSources(request) => {
            println!("kind: get_sources");
            match request {
                GetSourcesRequest::Legacy { file_hash } => {
                    println!("wire_form: legacy");
                    println!("file_hash: {}", file_hash.to_hex_upper());
                }
                GetSourcesRequest::Normal { target } => {
                    println!("wire_form: normal");
                    println!("file_hash: {}", target.file_hash().to_hex_upper());
                    println!("file_size: {}", target.file_size());
                }
                GetSourcesRequest::Large { target } => {
                    println!("wire_form: large");
                    println!("file_hash: {}", target.file_hash().to_hex_upper());
                    println!("file_size: {}", target.file_size());
                }
            }
        }
        ClientPacket::CallbackRequest(request) => {
            println!("kind: callback_request");
            println!("low_id: {}", request.low_id.as_u32());
        }
        ClientPacket::OfferFiles(offer) => {
            println!("kind: offer_files");
            println!("file_count: {}", offer.entries().len());
            for entry in offer.entries() {
                println!("file_hash: {}", entry.file_hash().to_hex_upper());
                println!("client_id: {}", entry.client_id().as_u32());
                println!("client_port: {}", entry.client_port());
                println!("tag_count: {}", entry.tags().len());
            }
        }
        ClientPacket::Unknown { opcode, payload } => {
            println!("kind: unknown");
            println!("unknown_opcode: 0x{opcode:02X}");
            println!("unknown_payload_len: {}", payload.len());
        }
    }
    Ok(())
}
