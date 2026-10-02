//! The offline peer-packet inspector: decode a recorded peer frame from disk
//! and print its fields, opcode by opcode.

use std::path::Path;

use anyhow::Result;
use rmule_peer::PeerPacket;

use crate::capture::decode_packet_path;

pub(crate) fn inspect_packet(path: &Path) -> Result<()> {
    let packet = decode_packet_path(path)?;
    let decoded = PeerPacket::decode(&packet)?;
    println!("protocol: {}", packet.protocol().name());
    println!("opcode: 0x{:02X}", packet.opcode());
    println!("payload_len: {}", packet.payload().len());
    match decoded {
        PeerPacket::Hello(h) => {
            print_hello_body("hello", h.body());
            println!("trailer: {:?}", h.trailer());
        }
        PeerPacket::HelloAnswer(h) => {
            print_hello_body("hello_answer", h.body());
            println!("trailer: {:?}", h.trailer());
        }
        PeerPacket::RequestFileName(r) => print_file_hash_only("request_filename", r.file_hash),
        PeerPacket::ReqFileNameAnswer(r) => {
            println!("kind: req_filename_answer");
            println!("file_hash: {}", r.file_hash.to_hex_upper());
            println!("file_name: {}", r.file_name);
        }
        PeerPacket::FileReqAnsNoFil(r) => print_file_hash_only("file_req_ans_no_fil", r.file_hash),
        PeerPacket::SetReqFileId(r) => print_file_hash_only("set_req_file_id", r.file_hash),
        PeerPacket::FileStatus(r) => {
            println!("kind: file_status");
            println!("file_hash: {}", r.file_hash.to_hex_upper());
            println!("part_count: {}", r.bitmap.part_count());
            let present: Vec<u32> = r
                .bitmap
                .iter_present()
                .map(rmule_peer::PartIndex::value)
                .collect();
            println!("present_parts: {present:?}");
        }
        PeerPacket::HashSetRequest(r) => print_file_hash_only("hash_set_request", r.file_hash),
        PeerPacket::HashSetAnswer(r) => {
            println!("kind: hash_set_answer");
            println!("file_hash: {}", r.file_hash.to_hex_upper());
            println!("part_hash_count: {}", r.part_hashes.len());
            for (i, h) in r.part_hashes.iter().enumerate() {
                println!("part_hash[{i}]: {}", h.to_hex_upper());
            }
        }
        PeerPacket::StartUploadReq(r) => print_file_hash_only("start_upload_req", r.file_hash),
        PeerPacket::AcceptUploadReq(_) => println!("kind: accept_upload_req"),
        PeerPacket::CancelTransfer(_) => println!("kind: cancel_transfer"),
        PeerPacket::OutOfPartReqs(_) => println!("kind: out_of_part_reqs"),
        PeerPacket::QueueRanking(r) => {
            println!("kind: queue_ranking");
            println!("rank: {}", r.rank);
        }
        PeerPacket::RequestParts(r) => {
            println!("kind: request_parts");
            println!("file_hash: {}", r.file_hash.to_hex_upper());
            for (i, (start, end)) in r.ranges.as_array().iter().enumerate() {
                println!("range[{i}]: start={start} end={end}");
            }
        }
        PeerPacket::SendingPart(sp) => {
            println!("kind: sending_part");
            println!("file_hash: {}", sp.file_hash.to_hex_upper());
            println!("start: {}", sp.start);
            println!("end: {}", sp.end);
            println!("data_len: {}", sp.data.len());
        }
        PeerPacket::CompressedPart(cp) => {
            println!("kind: compressed_part");
            println!("file_hash: {}", cp.file_hash.to_hex_upper());
            println!("start: {}", cp.start);
            println!("compressed_block_len: {}", cp.compressed_block_len);
            println!("compressed_chunk_len: {}", cp.compressed_chunk.len());
        }
        PeerPacket::RequestSources(r) => print_file_hash_only("request_sources", r.file_hash),
        PeerPacket::RequestSources2(r) => {
            println!("kind: request_sources2");
            println!("file_hash: {}", r.file_hash.to_hex_upper());
            println!("version: {}", r.version);
            println!("options: {}", r.options);
        }
        PeerPacket::AnswerSources(a) => {
            println!("kind: answer_sources");
            println!("file_hash: {}", a.file_hash.to_hex_upper());
            println!("source_count: {}", a.sources.len());
        }
        PeerPacket::AnswerSources2(a) => {
            println!("kind: answer_sources2");
            println!("file_hash: {}", a.file_hash.to_hex_upper());
            println!("version: {}", a.version.as_u8());
            println!("source_count: {}", a.sources.len());
        }
        PeerPacket::AichRequest(r) => {
            println!("kind: aich_request");
            println!("file_hash: {}", r.file_hash.to_hex_upper());
            println!("part: {}", r.part);
            println!("root: {}", r.root.to_base32_upper());
        }
        PeerPacket::AichAnswer(a) => {
            println!("kind: aich_answer");
            println!("file_hash: {}", a.file_hash.to_hex_upper());
            println!("part: {}", a.part);
            println!("root: {}", a.root.to_base32_upper());
            println!("recovery_len: {}", a.recovery_data.len());
        }
        PeerPacket::AichFileHashReq(r) => {
            println!("kind: aich_file_hash_req");
            println!("file_hash: {}", r.file_hash.to_hex_upper());
        }
        PeerPacket::AichFileHashAns(a) => {
            println!("kind: aich_file_hash_ans");
            println!("root: {}", a.root.to_base32_upper());
        }
        PeerPacket::SecIdentState(p) => {
            println!("kind: sec_ident_state");
            println!("state: {:?}", p.state);
            println!("challenge: 0x{:08X}", p.challenge);
        }
        PeerPacket::PublicKey(p) => {
            println!("kind: public_key");
            println!("public_key_len: {}", p.der.len());
        }
        PeerPacket::Signature(p) => {
            println!("kind: signature");
            println!("signature_len: {}", p.signature.len());
        }
        PeerPacket::MultiPacketRequest(r) => {
            println!("kind: multipacket_request");
            println!("file_hash: {}", r.file_hash.to_hex_upper());
            if let Some(size) = r.file_size {
                println!("file_size: {size}");
            }
            println!("item_count: {}", r.items.len());
            for (i, item) in r.items.iter().enumerate() {
                println!("item[{i}]: {item:?}");
            }
            if let Some(unknown) = r.unknown_sub {
                println!("unknown_sub_opcode: 0x{:02X}", unknown.opcode);
                println!("unknown_sub_remaining: {}", unknown.remaining);
            }
        }
        PeerPacket::MultiPacketAnswer(a) => {
            println!("kind: multipacket_answer");
            println!("file_hash: {}", a.file_hash.to_hex_upper());
            println!("item_count: {}", a.items.len());
            for (i, item) in a.items.iter().enumerate() {
                println!("item[{i}]: {item:?}");
            }
            if let Some(unknown) = a.unknown_sub {
                println!("unknown_sub_opcode: 0x{:02X}", unknown.opcode);
                println!("unknown_sub_remaining: {}", unknown.remaining);
            }
        }
        PeerPacket::KadFirewallAck => {
            println!("kind: kad_fwtcpcheck_ack");
        }
        PeerPacket::KadUdpFirewallRequest(request) => {
            println!("kind: kad_fwcheckudpreq");
            println!("request_len: {}", request.len());
        }
        PeerPacket::BuddyPing => {
            println!("kind: buddy_ping");
        }
        PeerPacket::BuddyPong => {
            println!("kind: buddy_pong");
        }
        PeerPacket::BuddyCallback(c) => {
            println!("kind: buddy_callback");
            println!("buddy_id: {}", crate::capture::hex_lower(&c.buddy_id));
            println!("file_hash: {}", c.file_hash.to_hex_upper());
            println!("requester: {}", c.requester);
        }
        PeerPacket::BuddyReaskCallback(r) => {
            println!("kind: buddy_reask_callback");
            println!("requester: {}", r.requester);
            println!("forwarded_len: {}", r.forwarded.len());
        }
        PeerPacket::AskSharedFiles => println!("kind: ask_shared_files"),
        PeerPacket::AskSharedDirs => println!("kind: ask_shared_dirs"),
        PeerPacket::AskSharedFilesDir => println!("kind: ask_shared_files_dir"),
        PeerPacket::AskSharedDeniedAns => println!("kind: ask_shared_denied_ans"),
        PeerPacket::AskSharedFilesAnswer => println!("kind: ask_shared_files_answer"),
        PeerPacket::AskSharedDirsAns => println!("kind: ask_shared_dirs_ans"),
        PeerPacket::AskSharedFilesDirAns => println!("kind: ask_shared_files_dir_ans"),
        PeerPacket::PublicIpReq => println!("kind: public_ip_req"),
        PeerPacket::PublicIpAnswer(a) => {
            println!("kind: public_ip_answer");
            println!("ip: {}", a.ip);
        }
        PeerPacket::Message(m) => {
            println!("kind: message");
            println!("text: {}", m.text);
        }
        PeerPacket::EmuleInfo { answer, info, .. } => {
            println!(
                "kind: {}",
                if answer {
                    "emule_info_answer"
                } else {
                    "emule_info"
                }
            );
            println!("info: {info:?}");
        }
        PeerPacket::FileDesc(d) => {
            println!("kind: file_desc");
            println!("rating: {}", d.rating);
            println!("comment: {}", d.comment);
        }
        PeerPacket::ChangeClientId(c) => {
            println!("kind: change_client_id");
            println!("new_id: {}", c.new_id.as_u32());
            println!("new_server_ip: {}", c.new_server_ip);
        }
        PeerPacket::ChangeClientIpV6(c) => {
            println!("kind: change_client_ip_v6");
            println!("address: {}", c.address());
        }
        PeerPacket::ChatCaptchaReq => println!("kind: chat_captcha_req"),
        PeerPacket::ChatCaptchaRes => println!("kind: chat_captcha_res"),
        PeerPacket::Unknown {
            protocol,
            opcode,
            payload,
        } => {
            println!("kind: unknown");
            println!("unknown_protocol: {}", protocol.name());
            println!("opcode: 0x{opcode:02X}");
            println!("payload_len: {}", payload.len());
        }
    }
    Ok(())
}

fn print_file_hash_only(kind: &str, file_hash: rmule_primitives::FileHash) {
    println!("kind: {kind}");
    println!("file_hash: {}", file_hash.to_hex_upper());
}

fn print_hello_body(kind: &str, body: &rmule_peer::PeerHelloBody) {
    let identity = rmule_peer::PeerIdentity::from_hello_body(body);
    println!("kind: {kind}");
    println!("user_hash: {}", identity.user_hash().to_hex_upper());
    println!("client_id: {}", identity.client_id().as_u32());
    println!("tcp_port: {}", identity.tcp_port());
    if let Some(nick) = identity.nickname() {
        println!("nickname: {}", nick.to_display_string());
    }
    if let Some(v) = identity.protocol_version() {
        println!("protocol_version: {v}");
    }
    if let Some(srv) = identity.connected_server() {
        println!("connected_server: {}:{}", srv.ip, srv.port);
    } else {
        println!("connected_server: none");
    }
    println!("unknown_tag_count: {}", identity.unknown_tags().len());
}
