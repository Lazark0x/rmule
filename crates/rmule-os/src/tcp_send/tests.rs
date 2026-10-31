//! A real loopback pair with a receiver that has not read: CI runs this on
//! Linux and macOS.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use super::{SendProgress, send_progress};

/// Fill `sender` until the kernel takes no more.
fn fill(sender: &mut TcpStream) {
    sender.set_nonblocking(true).unwrap();
    let block = [0u8; 64 * 1024];
    loop {
        match sender.write(&block) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => return,
            Err(error) => panic!("{error}"),
        }
    }
}

#[test]
fn the_count_stands_on_an_unread_socket_and_falls_as_the_receiver_reads() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut receiver, _) = listener.accept().unwrap();
    assert_eq!(send_progress(&sender), Some(SendProgress::Held(0)));

    fill(&mut sender);
    // What the receiver's window took acks away at once; wait for it to end.
    let settle = Instant::now() + Duration::from_secs(5);
    let full = loop {
        let before = send_progress(&sender);
        std::thread::sleep(Duration::from_millis(50));
        if send_progress(&sender) == before {
            break before.expect("a TCP stream answers");
        }
        assert!(Instant::now() < settle, "the count never settled");
    };
    assert!(
        matches!(full, SendProgress::Held(held) if held > 0),
        "{full:?}"
    );

    let mut chunk = [0u8; 64 * 1024];
    let give_up = Instant::now() + Duration::from_secs(5);
    loop {
        receiver.read_exact(&mut chunk).unwrap();
        if send_progress(&sender).is_some_and(|now| now.is_past(full)) {
            return;
        }
        assert!(Instant::now() < give_up, "the count never fell");
    }
}
