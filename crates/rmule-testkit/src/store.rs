//! The Durable Store a test runs on: the same `rmule-store` database
//! production opens, on the engine's in-memory backend instead of a file
//! (ADR-0083). There is no in-memory twin of any seam, so this is what a test
//! hands [`Core::builder`](rmule_core::Core::builder) or a seam constructor —
//! and, for a test whose core reads its settings from a store, the scratch
//! ports that keep it off every port another client holds.

use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::sync::Arc;

use rmule_core::{CoreSettingsHandle, DurableStore, Setting, open_durable_store_in_memory};

/// One open Durable Store on the engine's in-memory backend, isolated to the
/// caller and dying with it.
///
/// Hand **one** of these to everything that shares state in the test — the
/// core builder, and any seam the test also holds — so the seams see each
/// other's writes exactly as a front-end's do. Two calls are two unrelated
/// databases.
///
/// # Panics
/// When the store refuses to open, which for a fresh in-memory backend against
/// core's own schema means core's schema is broken — not something a test can
/// handle.
#[must_use]
pub fn memory_store() -> Arc<DurableStore> {
    open_durable_store_in_memory().expect("the in-memory Durable Store opens")
}

/// Set the operator's two ports through `settings` to ports the OS has just
/// found free, as an operator's edit would — so a core built on that store
/// binds no port a client on this host holds, and two tests never share one.
///
/// The store never holds `0` (Core Settings refuses it, since no peer could
/// be told an OS-chosen port), so a test that builds its core from a store
/// takes these instead. A freed port could be taken again before the core
/// binds it; the core reports that as a failed bind, never a wrong answer.
///
/// # Panics
/// When the host has no free port, or the store refuses the write.
pub fn scratch_ports(settings: &CoreSettingsHandle) {
    let tcp = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
        .and_then(|listener| listener.local_addr())
        .expect("the OS finds a free TCP port")
        .port();
    let udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .and_then(|socket| socket.local_addr())
        .expect("the OS finds a free UDP port")
        .port();
    for setting in [Setting::TcpPort(tcp), Setting::UdpPort(udp)] {
        settings
            .set(setting)
            .expect("the store keeps a scratch port");
    }
}
