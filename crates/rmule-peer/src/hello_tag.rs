//! The tag ids the hello and the emule info both carry, written once: the
//! client's name, its protocol version, its mule version and its mod.
//!
//! The hello projection always emits these: a tag of `ClientIdentity::extra_tags`
//! whose id collides with one is dropped before forwarding, so the wire never
//! carries one twice — `ClientIdentity` is a permissive config struct, and this
//! is the defensive boundary.

/// `CT_NAME`: the client's name.
pub(crate) const CT_NAME: u8 = 0x01;
/// `CT_VERSION`: the eDonkey protocol version the client speaks.
pub(crate) const CT_VERSION: u8 = 0x11;
/// `CT_EMULE_VERSION` (`0xFB`). Load-bearing beyond version display: eMule's
/// `ProcessHelloTypePacket` sets `bIsMule` only when this tag is present
/// (`dwEmuleTags & 0x04`), and without `bIsMule` it never reaches
/// `InfoPacketsReceived` — which is where it initiates Secure User
/// Identification. A hello without 0xFB gets no SUI challenge from a real
/// aMule (observed in the 2026-07-06 direct-SUI capture).
pub(crate) const CT_EMULE_VERSION: u8 = 0xFB;
/// `CT_MOD_VERSION` (`0x55`), aMule's `ET_MOD_VERSION` in the emule info.
pub(crate) const CT_MOD_VERSION: u8 = 0x55;
