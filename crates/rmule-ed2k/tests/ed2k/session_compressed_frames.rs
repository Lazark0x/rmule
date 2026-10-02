//! An unusable compressed frame is skipped with an event, not treated as a
//! protocol violation that closes the session.

use rmule_ed2k::{CompressedFrameSkipReason, Ed2kEvent, Output};
use rmule_primitives::session::drain;

#[test]
fn invalid_compressed_frame_is_skipped_without_closing_session() {
    let mut session = crate::fixture::session(0);
    session.start();
    drain(|| session.poll_output());

    // 0xD4 + length=3 + opcode=OP_SERVERMESSAGE + invalid zlib payload [0, 1]
    session.handle_bytes(&[0xD4, 0x03, 0, 0, 0, 0x38, 0, 1]);

    let Some(Output::Event(Ed2kEvent::CompressedFrameSkipped {
        opcode,
        compressed_len,
        reason,
    })) = session.poll_output()
    else {
        panic!("expected CompressedFrameSkipped");
    };

    assert_eq!(opcode, 0x38);
    assert_eq!(compressed_len, 2);
    assert_eq!(reason, CompressedFrameSkipReason::InflateFailed);
    assert!(session.poll_output().is_none(), "no Close output");
}
