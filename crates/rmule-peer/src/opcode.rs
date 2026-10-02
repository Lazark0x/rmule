//! Every peer-to-peer eD2k opcode rmule models, with its byte defined exactly
//! once.
//!
//! Each opcode records the [`PacketProtocol`]
//! it is canonical under, because the byte alone is ambiguous: `0x60` is
//! `QueueRanking` under the eMule protocol and a shared-files answer under
//! eDonkey. Dispatch is always `(protocol, opcode)`-qualified.

use rmule_primitives::{PacketProtocol, opcodes};

opcodes! {
    /// Every peer-to-peer eD2k opcode rmule models. Bytes are defined
    /// once here; `protocol()` records each opcode's canonical
    /// `PacketProtocol` so dispatch is `(protocol, opcode)`-qualified
    /// (e.g. `0x60` is `QueueRanking` only under `Emule`).
    pub enum PeerOpcode {
        Hello = 0x01,
        HelloAnswer = 0x4C,
        RequestFileName = 0x58,
        ReqFileNameAnswer = 0x59,
        FileReqAnsNoFil = 0x48,
        SetReqFileId = 0x4F,
        FileStatus = 0x50,
        HashSetRequest = 0x51,
        HashSetAnswer = 0x52,
        StartUploadReq = 0x54,
        AcceptUploadReq = 0x55,
        CancelTransfer = 0x56,
        OutOfPartReqs = 0x57,
        QueueRanking = 0x60,
        RequestParts = 0x47,
        RequestPartsI64 = 0xA3,
        SendingPart = 0x46,
        SendingPartI64 = 0xA2,
        CompressedPart = 0x40,
        CompressedPartI64 = 0xA1,
        RequestSources = 0x81,
        AnswerSources = 0x82,
        RequestSources2 = 0x83,
        AnswerSources2 = 0x84,
        AichRequest = 0x9B,
        AichAnswer = 0x9C,
        AichFileHashAns = 0x9D,
        AichFileHashReq = 0x9E,
        // ADR-0061 buddy/callback, over the eMule extension protocol.
        // `Callback`/`ReaskCallbackTcp` are the TCP relay outputs a buddy sends
        // its firewalled client (the `0x52`→`0x99` and `0x94`→`0x9A` relays);
        // `BuddyPing`/`BuddyPong` keep the buddy link alive.
        Callback = 0x99,
        ReaskCallbackTcp = 0x9A,
        BuddyPing = 0x9F,
        BuddyPong = 0xA0,
        PublicKey = 0x85,
        Signature = 0x86,
        SecIdentState = 0x87,
        MultiPacket = 0x92,
        MultiPacketAnswer = 0x93,
        MultiPacketExt = 0xA4,
        // `OP_KAD_FWTCPCHECK_ACK` — the empty-body ack a Kad firewall-check
        // dial-back sends over the TCP link it opened, proving the requester is
        // TCP-reachable (ADR-0058 responder, v7+ path). The dial-back and this
        // send are the capture-bearing enactment the core broker drives;
        // the registry entry is the seam the ADR names. Byte `0xA8` is aMule's
        // `OP_KAD_FWTCPCHECK_ACK` (`kad2/Client2Client/TCP.h` @4e8f2b3c) — the
        // sibling of `OP_FWCHECKUDPREQ` (`0xA7`); it must match or a firewalled
        // aMule never counts our connect-back and stays firewalled.
        KadFwTcpCheckAck = 0xA8,
        // `OP_FWCHECKUDPREQ` — a Kad node asking this link's peer to prove
        // its Kad UDP port reachable by answering `KADEMLIA2_FIREWALLUDP`
        // (ADR-0058, UDP Firewall Helper). aMule handles it at
        // `ClientTCPSocket.cpp:1942-1948` and writes it at
        // `BaseClient.cpp:3982-3986` (@ab483654).
        FwCheckUdpReq = 0xA7,
        // ADR-0068 human-layer catalog, Private-Citizen Parity. `0x60`
        // (`OP_ASKSHAREDFILESDIRANS`, Edonkey) and `0x61`
        // (`OP_ASKSHAREDDENIEDANS`, Edonkey / `OP_FILEDESC`, Emule) are
        // deliberately NOT listed here: both bytes already carry a meaning
        // under the *other* protocol that this registry's byte-keyed
        // `try_from_u8` cannot also claim (`0x60` is `QueueRanking` above under
        // Emule; a second `0x60`/`0x61` entry would make `try_from_u8` return
        // only whichever variant lists it first). `packet.rs` special-cases
        // those two raw bytes ahead of this registry — see `human_layer`.
        AskSharedFiles = 0x4A,
        AskSharedFilesAnswer = 0x4B,
        ChangeClientId = 0x4D,
        Message = 0x4E,
        AskSharedDirs = 0x5D,
        AskSharedFilesDir = 0x5E,
        AskSharedDirsAns = 0x5F,
        PublicIpReq = 0x97,
        PublicIpAnswer = 0x98,
        ChatCaptchaReq = 0xA5,
        ChatCaptchaRes = 0xA6,
        // ADR-0087 `OP_CHANGE_CLIENT_IP`: sixteen raw address bytes under
        // `OP_EDONKEYPROT`, so a stock client reads an unknown eDonkey opcode
        // and ignores it rather than desyncing.
        ChangeClientIpV6 = 0xAC,
    }
}

impl PeerOpcode {
    /// The protocol byte this opcode travels under on the wire.
    #[must_use]
    pub const fn protocol(self) -> PacketProtocol {
        match self {
            Self::QueueRanking
            | Self::RequestPartsI64
            | Self::SendingPartI64
            | Self::CompressedPart
            | Self::CompressedPartI64
            | Self::RequestSources
            | Self::AnswerSources
            | Self::RequestSources2
            | Self::AnswerSources2
            | Self::AichRequest
            | Self::AichAnswer
            | Self::AichFileHashAns
            | Self::AichFileHashReq
            | Self::PublicKey
            | Self::Signature
            | Self::SecIdentState
            | Self::MultiPacket
            | Self::MultiPacketAnswer
            | Self::MultiPacketExt
            | Self::Callback
            | Self::ReaskCallbackTcp
            | Self::BuddyPing
            | Self::BuddyPong
            | Self::KadFwTcpCheckAck
            | Self::FwCheckUdpReq
            | Self::PublicIpReq
            | Self::PublicIpAnswer
            | Self::ChatCaptchaReq
            | Self::ChatCaptchaRes => PacketProtocol::Emule,
            _ => PacketProtocol::Edonkey,
        }
    }
}
