//! The **peer-UDP** surface, sans-I/O: the client-UDP codec, the two halves of
//! the source reask (ADR-0057) and the pure rules of its obfuscation
//! (ADR-0046).
//!
//! - The [`responder`] is the **Reask Responder**, the uploader half: it reads
//!   an `OP_REASKFILEPING` and, once the runtime has resolved the pinger
//!   against its upload queue, answers it as aMule does.
//! - The [`requester`] is the **Reask Requester**, the downloader half: it
//!   frames the ping and reads the reply, negotiating the two UDP versions.
//! - [`crypt`] holds the rules that decide whether a datagram may leave
//!   obfuscated and which of our addresses keys it, the connect-options
//!   byte's crypt bits, and the plaintext `0x95` direct callback.
//!
//! Both reask halves are stateless. The runtime owns the shared socket and its
//! demux, the upload queue and the remote-queued pool the halves read through
//! their seams, and the I/O half of crypt: the per-packet nonce, our own
//! identity and public address, and the key calls into `rmule-primitives`.

mod codec;
pub mod crypt;
pub mod requester;
pub mod responder;

pub use codec::{
    BUDDY_ID_LEN, ClientUdpOpcode, DirectCallbackReq, ReaskAck, ReaskCallbackUdp, ReaskDecodeError,
    ReaskFilePing, file_not_found_datagram, queue_full_datagram,
};
