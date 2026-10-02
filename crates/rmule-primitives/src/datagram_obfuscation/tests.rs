//! Unit tests for the datagram obfuscation layer: RC4 keystream vectors,
//! per-family key derivation, marker discrimination, and the round trips of
//! each client and server datagram direction.

use super::*;

fn keystream(mut c: Rc4, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    c.apply(&mut buf);
    buf
}

/// An RC4 stream keyed directly on an explicitly-built MD5 input, with no
/// drop-1024 — the independent oracle each key-family KAT compares against.
fn expected_rc4(md5_input: &[u8]) -> Rc4 {
    Rc4::new(&Md5::digest(md5_input))
}

// --- KATs per key family: the exact MD5 concatenation order + no discard ---

#[test]
fn ed2k_key_hashes_userhash_ip_magic_randomkey_without_discard() {
    let uh = UserHash::from_bytes([0x11; 16]);
    let ip = [10u8, 0, 0, 7];
    let rk = 0xBEEFu16;
    let mut input = Vec::new();
    input.extend_from_slice(uh.as_bytes());
    input.extend_from_slice(&ip);
    input.push(MAGICVALUE_UDP);
    input.extend_from_slice(&rk.to_le_bytes());

    assert_eq!(
        keystream(
            datagram_key_ed2k(&uh, DatagramSenderAddress::V4(ip), rk),
            32
        ),
        keystream(expected_rc4(&input), 32),
        "ed2k key = RC4(MD5(user_hash ‖ ip ‖ 0x5B ‖ random_key_le)), no drop-1024",
    );
}

#[test]
fn kad_node_key_hashes_kadid_randomkey() {
    let kad_id = [0x22u8; 16];
    let rk = 0x1234u16;
    let mut input = Vec::new();
    input.extend_from_slice(&kad_id);
    input.extend_from_slice(&rk.to_le_bytes());
    assert_eq!(
        keystream(datagram_key_kad_node(&kad_id, rk), 32),
        keystream(expected_rc4(&input), 32),
    );
}

#[test]
fn kad_verify_key_hashes_verifykey_randomkey() {
    let vk = 0xDEAD_BEEFu32;
    let rk = 0x5678u16;
    let mut input = Vec::new();
    input.extend_from_slice(&vk.to_le_bytes());
    input.extend_from_slice(&rk.to_le_bytes());
    assert_eq!(
        keystream(datagram_key_kad_verify(vk, rk), 32),
        keystream(expected_rc4(&input), 32),
    );
}

#[test]
fn server_key_hashes_basekey_directionmagic_randomkey() {
    let base = 0x0A0B_0C0Du32;
    let rk = 0x9999u16;
    for (dir, magic) in [
        (ServerCryptDirection::ToServer, MAGICVALUE_UDP_CLIENTSERVER),
        (
            ServerCryptDirection::FromServer,
            MAGICVALUE_UDP_SERVERCLIENT,
        ),
    ] {
        let mut input = Vec::new();
        input.extend_from_slice(&base.to_le_bytes());
        input.push(magic);
        input.extend_from_slice(&rk.to_le_bytes());
        assert_eq!(
            keystream(datagram_key_server(base, dir, rk), 32),
            keystream(expected_rc4(&input), 32),
            "{dir:?} keyed with magic {magic:#04x}",
        );
    }
}

// --- Derivation-flip traps: every input actually feeds the key ---

#[test]
fn ed2k_key_changes_with_each_input() {
    let uh = UserHash::from_bytes([1u8; 16]);
    let base = keystream(
        datagram_key_ed2k(&uh, DatagramSenderAddress::V4([1, 2, 3, 4]), 10),
        16,
    );
    // Flip the IP, the random key, and the user hash independently.
    assert_ne!(
        base,
        keystream(
            datagram_key_ed2k(&uh, DatagramSenderAddress::V4([9, 2, 3, 4]), 10),
            16
        )
    );
    assert_ne!(
        base,
        keystream(
            datagram_key_ed2k(&uh, DatagramSenderAddress::V4([1, 2, 3, 4]), 11),
            16
        )
    );
    let uh2 = UserHash::from_bytes([2u8; 16]);
    assert_ne!(
        base,
        keystream(
            datagram_key_ed2k(&uh2, DatagramSenderAddress::V4([1, 2, 3, 4]), 10),
            16
        )
    );
}

#[test]
fn server_key_direction_flip_changes_the_key() {
    // The absolute-direction trap: flipping the CLIENTSERVER/SERVERCLIENT
    // magic must change the derived stream, so client-send and
    // server-reply keys never collide on one datagram.
    let base = 0x1122_3344u32;
    assert_ne!(
        keystream(
            datagram_key_server(base, ServerCryptDirection::ToServer, 7),
            16
        ),
        keystream(
            datagram_key_server(base, ServerCryptDirection::FromServer, 7),
            16
        ),
    );
}

// --- Marker semantics: bypass set + family selection ---

#[test]
fn plaintext_markers_are_exactly_the_six_bypass_bytes() {
    for b in [0xC5u8, 0xE4, 0xE5, 0xD4, 0xA3, 0xB2] {
        assert!(is_udp_plaintext_marker(b), "{b:#04x} bypasses decryption");
    }
    // The stream form's 0xE3 is NOT in the UDP bypass set; nor is anything else.
    for b in [0x00u8, 0x01, 0xE3, 0x5B, 0x6B, 0xA5, 0xFF] {
        assert!(!is_udp_plaintext_marker(b), "{b:#04x} is obfuscated");
    }
}

#[test]
fn marker_low_bits_pick_the_family_with_three_aliasing_ed2k() {
    assert_eq!(marker_family(0b1111_1100), DatagramKeyFamily::KadNodeId); // ..00
    assert_eq!(marker_family(0b1111_1101), DatagramKeyFamily::Ed2kUserHash); // ..01
    assert_eq!(marker_family(0b1111_1110), DatagramKeyFamily::KadVerifyKey); // ..10
    assert_eq!(marker_family(0b1111_1111), DatagramKeyFamily::Ed2kUserHash); // ..11 → ed2k
}

// --- Crossed-role datagram loopbacks, one per client family ---

fn nonce(marker: u8, rk: u16, pad: &[u8]) -> DatagramNonce {
    DatagramNonce {
        marker_byte: marker,
        random_key: rk,
        padding: pad.to_vec(),
    }
}

#[test]
fn ed2k_datagram_round_trips_sender_to_receiver() {
    let uh = UserHash::from_bytes([0x33; 16]);
    let sender_ip = DatagramSenderAddress::V4([192u8, 168, 1, 50]);
    let payload = b"reask: file part please".to_vec();
    let dgram = encrypt_datagram_client(
        &payload,
        &ClientEncryptKey::Ed2k {
            user_hash: &uh,
            sender: sender_ip,
        },
        &nonce(0x40, 0xABCD, &[0xEE; 5]),
    );
    // The receiver holds its own user hash and knows the sender's IP.
    let keys = ClientDecryptKeys {
        user_hash: Some(&uh),
        sender: sender_ip,
        ..Default::default()
    };
    let got = decrypt_datagram_client(&dgram, &keys).expect("decrypts");
    assert_eq!(got.family, DatagramKeyFamily::Ed2kUserHash);
    assert_eq!(got.payload, payload);
    assert_eq!(got.receiver_verify_key, None, "ed2k carries no trailer");
}

#[test]
fn kad_node_datagram_round_trips_with_verify_trailer() {
    let kad_id = [0x44u8; 16];
    let payload = b"kad2 res".to_vec();
    let dgram = encrypt_datagram_client(
        &payload,
        &ClientEncryptKey::KadNode {
            kad_id: &kad_id,
            receiver_verify_key: 0x1111_2222,
            sender_verify_key: 0x3333_4444,
        },
        &nonce(0x00, 0x0102, &[]),
    );
    let keys = ClientDecryptKeys {
        kad_id: Some(&kad_id),
        ..Default::default()
    };
    let got = decrypt_datagram_client(&dgram, &keys).expect("decrypts");
    assert_eq!(got.family, DatagramKeyFamily::KadNodeId);
    assert_eq!(got.payload, payload);
    assert_eq!(got.receiver_verify_key, Some(0x1111_2222));
    assert_eq!(got.sender_verify_key, Some(0x3333_4444));
}

#[test]
fn kad_verify_datagram_round_trips_on_receiver_key() {
    let vk = 0x00C0_FFEEu32;
    let payload = b"kad verify-keyed".to_vec();
    let dgram = encrypt_datagram_client(
        &payload,
        &ClientEncryptKey::KadVerify {
            verify_key: vk,
            receiver_verify_key: vk,
            sender_verify_key: 0x5555_6666,
        },
        &nonce(0x02, 0xFFFF, &[0x01, 0x02]),
    );
    let keys = ClientDecryptKeys {
        receiver_verify_key: Some(vk),
        ..Default::default()
    };
    let got = decrypt_datagram_client(&dgram, &keys).expect("decrypts");
    assert_eq!(got.family, DatagramKeyFamily::KadVerifyKey);
    assert_eq!(got.payload, payload);
    assert_eq!(got.sender_verify_key, Some(0x5555_6666));
}

// --- Dual-path receive: key-try order, bypass, garbage, wrong key ---

#[test]
fn receiver_holding_only_the_wrong_family_key_drops_the_datagram() {
    // ed2k datagram, but the receiver holds only a KadID → the symmetric-key
    // trap: a mismatched family must not spuriously validate the sync word.
    let uh = UserHash::from_bytes([7u8; 16]);
    let sender_ip = DatagramSenderAddress::V4([1u8, 1, 1, 1]);
    let dgram = encrypt_datagram_client(
        b"secret",
        &ClientEncryptKey::Ed2k {
            user_hash: &uh,
            sender: sender_ip,
        },
        &nonce(0x00, 0x4242, &[]),
    );
    let wrong = ClientDecryptKeys {
        kad_id: Some(&[0x99u8; 16]),
        sender: sender_ip,
        ..Default::default()
    };
    assert!(decrypt_datagram_client(&dgram, &wrong).is_none());
}

#[test]
fn decrypt_tries_marker_family_but_recovers_regardless_of_marker_bits() {
    // The marker bits set the *first* family to try; a receiver holding only
    // the true key still recovers even if the marker points elsewhere.
    let uh = UserHash::from_bytes([0x5A; 16]);
    let sender_ip = DatagramSenderAddress::V4([8u8, 8, 8, 8]);
    // Encrypt as ed2k, then rewrite the marker's low bits to claim KadNodeId.
    let mut dgram = encrypt_datagram_client(
        b"payload",
        &ClientEncryptKey::Ed2k {
            user_hash: &uh,
            sender: sender_ip,
        },
        &nonce(0x41, 0x0001, &[]),
    );
    dgram[0] &= 0xFC; // now marker_family == KadNodeId, but the key is ed2k
    let keys = ClientDecryptKeys {
        user_hash: Some(&uh),
        sender: sender_ip,
        ..Default::default()
    };
    let got = decrypt_datagram_client(&dgram, &keys).expect("falls through to ed2k");
    assert_eq!(got.family, DatagramKeyFamily::Ed2kUserHash);
    assert_eq!(got.payload, b"payload");
}

#[test]
fn plaintext_marker_datagram_is_not_decrypted() {
    let keys = ClientDecryptKeys {
        user_hash: Some(&UserHash::from_bytes([0; 16])),
        ..Default::default()
    };
    let mut dgram = vec![0xE4u8]; // OP_KADEMLIAHEADER — plaintext
    dgram.extend_from_slice(b"plain kad body");
    assert!(decrypt_datagram_client(&dgram, &keys).is_none());
}

#[test]
fn garbage_and_truncated_datagrams_return_none() {
    let keys = ClientDecryptKeys {
        user_hash: Some(&UserHash::from_bytes([3; 16])),
        sender: DatagramSenderAddress::V4([1, 2, 3, 4]),
        ..Default::default()
    };
    assert!(decrypt_datagram_client(&[], &keys).is_none(), "empty");
    assert!(
        decrypt_datagram_client(&[0x40, 0x01], &keys).is_none(),
        "shorter than the header"
    );
    // A full-length datagram of noise (non-marker first byte) fails the sync.
    let noise: Vec<u8> = (0u8..40)
        .map(|i| i.wrapping_mul(37).wrapping_add(1))
        .collect();
    assert!(decrypt_datagram_client(&noise, &keys).is_none(), "noise");
}

// --- Server datagram loopback + direction trap ---

#[test]
fn server_datagram_round_trips_in_one_direction_only() {
    let base_key = 0xCAFE_1234u32;
    let payload = b"0x96 crypt-ping reply".to_vec();
    let dgram = encrypt_datagram_server(
        &payload,
        base_key,
        ServerCryptDirection::ToServer,
        &nonce(0x30, 0x0505, &[0xAA, 0xBB, 0xCC]),
    );
    // Same direction (same magic) decrypts.
    assert_eq!(
        decrypt_datagram_server(&dgram, base_key, ServerCryptDirection::ToServer),
        Some(payload),
    );
    // The opposite direction derives a different key → sync fails.
    assert!(decrypt_datagram_server(&dgram, base_key, ServerCryptDirection::FromServer).is_none(),);
    // A wrong base key also fails.
    assert!(
        decrypt_datagram_server(&dgram, base_key ^ 1, ServerCryptDirection::ToServer).is_none(),
    );
}

#[test]
fn encrypt_never_emits_a_plaintext_marker_first_byte() {
    // Both wrappers must nudge the marker clear of the bypass set, else the
    // receiver would mis-classify the datagram as plaintext and skip it.
    let uh = UserHash::from_bytes([0; 16]);
    for raw in 0u16..=255 {
        let raw = raw as u8;
        let c = encrypt_datagram_client(
            b"x",
            &ClientEncryptKey::Ed2k {
                user_hash: &uh,
                sender: DatagramSenderAddress::V4([0; 4]),
            },
            &nonce(raw, 0, &[]),
        );
        assert!(!is_udp_plaintext_marker(c[0]), "client marker {raw:#04x}");
        let s =
            encrypt_datagram_server(b"x", 1, ServerCryptDirection::ToServer, &nonce(raw, 0, &[]));
        assert!(!is_udp_plaintext_marker(s[0]), "server marker {raw:#04x}");
    }
}

#[test]
fn pad_length_byte_stays_in_lockstep_with_the_encrypted_padding() {
    // The pad-length is one wire byte; the framer must emit a count that
    // matches the padding it writes, or decode mis-slices `body_start` and
    // recovers the wrong payload. Round-trip up to the one-byte max, then
    // past it — an over-long nonce is clamped, so the frame stays coherent
    // instead of desyncing (a bare `len() as u8` would wrap 300 → 44 here).
    let uh = UserHash::from_bytes([0x77; 16]);
    let sender_ip = DatagramSenderAddress::V4([10u8, 20, 30, 40]);
    let payload = b"body that must survive the padding".to_vec();
    let keys = ClientDecryptKeys {
        user_hash: Some(&uh),
        sender: sender_ip,
        ..Default::default()
    };
    let seal = |pad_len: usize| {
        encrypt_datagram_client(
            &payload,
            &ClientEncryptKey::Ed2k {
                user_hash: &uh,
                sender: sender_ip,
            },
            &nonce(0x40, 0x1357, &vec![0x5A; pad_len]),
        )
    };
    // Across the boundary the length byte is a lossless `as u8`, so decode
    // reads back the exact pad length and the payload comes out intact.
    for pad_len in [0usize, 1, 128, 254, 255] {
        let got = decrypt_datagram_client(&seal(pad_len), &keys).expect("decrypts");
        assert_eq!(got.payload, payload, "payload survives pad_len={pad_len}");
    }
    // Past the one-byte max the padding is clamped to 255, so the over-long
    // datagram is byte-for-byte the size of a max-padding one (not the
    // 45-bytes-longer frame an unclamped 300 would emit) and still decrypts
    // to the same payload — the length byte and the body never desynced.
    let capped = seal(300);
    assert_eq!(
        capped.len(),
        seal(255).len(),
        "padding clamped to the one-byte wire maximum",
    );
    assert_eq!(
        decrypt_datagram_client(&capped, &keys)
            .expect("decrypts")
            .payload,
        payload,
    );
}

/// The two ed2k key layouts, byte for byte (ADR-0087). The magic sits *after*
/// the address, so it moves with the width: offset 20 at 23 bytes, offset 32
/// at 35. eMuleAI writes it at 20 and then copies sixteen address bytes over
/// 16..31, overwriting it and leaving offset 32 uninitialised — that end
/// cannot reproduce its own key, let alone agree with a conforming one.
#[test]
fn the_ed2k_key_layout_follows_the_senders_family() {
    let uh = UserHash::from_bytes([0x11; 16]);
    let rk = 0xBEEFu16;

    let v4 = ed2k_key_material(&uh, DatagramSenderAddress::V4([10, 0, 0, 7]), rk);
    assert_eq!(v4.len(), 23);
    assert_eq!(&v4[..16], uh.as_bytes());
    assert_eq!(&v4[16..20], &[10, 0, 0, 7]);
    assert_eq!(v4[20], MAGICVALUE_UDP);
    assert_eq!(&v4[21..], &rk.to_le_bytes());

    let address: std::net::Ipv6Addr = "2a01:4f8::1".parse().unwrap();
    let v6 = ed2k_key_material(&uh, DatagramSenderAddress::V6(address.octets()), rk);
    assert_eq!(v6.len(), 35);
    assert_eq!(&v6[..16], uh.as_bytes());
    assert_eq!(
        &v6[16..32],
        &address.octets(),
        "the sixteen bytes in network order, not a projection"
    );
    assert_eq!(v6[32], MAGICVALUE_UDP, "the magic moved with the width");
    assert_eq!(&v6[33..], &rk.to_le_bytes());
}

/// `from_ip` is how a socket hands its reported source family over — the
/// layout is selected, never probed.
#[test]
fn the_sender_address_carries_the_family_the_socket_reported() {
    let v4 = DatagramSenderAddress::from_ip("198.51.100.7".parse().unwrap());
    let v6 = DatagramSenderAddress::from_ip("2001:db8::7".parse().unwrap());
    assert_eq!(v4.as_key_bytes().len(), 4);
    assert_eq!(v6.as_key_bytes().len(), 16);

    // Guessing wrong is silent, which is exactly why it must not be guessed:
    // both widths are valid key material, so a mis-selected layout yields a
    // key that decrypts to garbage rather than an error.
    let uh = UserHash::from_bytes([0x22; 16]);
    let payload = b"reask".to_vec();
    let datagram = encrypt_datagram_client(
        &payload,
        &ClientEncryptKey::Ed2k {
            user_hash: &uh,
            sender: v6,
        },
        &nonce(0x40, 0x1234, &[]),
    );
    assert!(
        decrypt_datagram_client(
            &datagram,
            &ClientDecryptKeys {
                user_hash: Some(&uh),
                sender: DatagramSenderAddress::V4([0x20, 0x01, 0x0d, 0xb8]),
                ..Default::default()
            }
        )
        .is_none(),
        "the v4 layout over a v6 sender must not open it"
    );
    let opened = decrypt_datagram_client(
        &datagram,
        &ClientDecryptKeys {
            user_hash: Some(&uh),
            sender: v6,
            ..Default::default()
        },
    )
    .expect("the sender's own family opens it");
    assert_eq!(opened.payload, payload);
}
