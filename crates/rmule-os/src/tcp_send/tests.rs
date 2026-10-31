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

    // The receiver's kernel acks what its window takes, and autotuning grows
    // that window, so the count only stands once the window is full too.
    let settle = Instant::now() + Duration::from_secs(10);
    let full = loop {
        fill(&mut sender);
        let before = send_progress(&sender).expect("a TCP stream answers");
        std::thread::sleep(Duration::from_millis(50));
        let after = send_progress(&sender).expect("a TCP stream answers");
        if after == before && !matches!(after, SendProgress::Held(0)) {
            break after;
        }
        assert!(Instant::now() < settle, "the count never settled");
    };

    let mut chunk = [0u8; 64 * 1024];
    receiver
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let give_up = Instant::now() + Duration::from_secs(10);
    loop {
        // What the receiver holds can end short of a chunk while the sender
        // waits on a window update, so no read here may insist on a whole one.
        match receiver.read(&mut chunk) {
            Ok(_) => {}
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(error) => panic!("{error}"),
        }
        if send_progress(&sender).is_some_and(|now| now.is_past(full)) {
            return;
        }
        assert!(Instant::now() < give_up, "the count never fell");
    }
}
