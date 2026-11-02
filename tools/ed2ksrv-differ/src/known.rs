//! The deviation registry: disagreements that are already understood.
//!
//! A divergence is only attributed when a `(case, field)` pair appears here
//! verbatim. That is deliberately rigid — the registry is a *claim*, and a claim
//! should not quietly stretch to cover a new fact. If a case starts diverging on
//! a second field, the second field comes out UNATTRIBUTED even though its
//! neighbour is explained.
//!
//! Three classes of entry, distinguishable by `id`:
//!
//! * `ed2k-server#N` — filed upstream, 2026-08-02. Fixing these is the maintainer's
//!   call; ADR-0045's amendment forbids patching them locally, because a patched
//!   surface stops being independent evidence.
//! * `audit §N` — recorded in the project's audit of ed2k-server and judged not
//!   worth filing (usually because the misread is inert in their own code).
//! * `ambiguity:*` — nobody's bug. The wire form genuinely underdetermines the
//!   reading and every implementation picks a rule.

use crate::report::Deviation;

pub static REGISTRY: &[Deviation] = &[
    Deviation {
        id: "ambiguity:crypt-ping-marker",
        title: "the raw crypt-ping's first wire byte is the challenge's low byte, \
                which collides with the 0xE3 plain-frame marker",
        cite: "udp.rs dispatches on data[0]==0xE3 before any obfuscation is \
               considered — as every eD2k server must. Unresolvable on the wire; \
               rmule keeps the minted challenge off 0xE3 \
               (rmule_ed2k::server_udp::crypt_ping_challenge). audit §3(b)",
        case: "crypt-ping/challenge-low-byte-e3",
        field: "answered",
    },
    Deviation {
        id: "ed2k-server#7",
        title: "LoginRequest::parse panics on a 22..=25 byte payload — the length \
                its own tag-count branch exists to tolerate",
        cite: "login.rs:26-40 guards len < 22 and computes tag_count only at \
               len >= 26, then slices &payload[26..] unconditionally; reachable \
               unauthenticated from connection.rs:345 on a client's first frame. \
               Contained to one spawned task (no panic = abort). Found by this \
               differ, not the audit; https://github.com/andrey23127/ed2k-server/issues/7",
        case: "login/22-byte-body-no-tag-count",
        field: "<outcome>",
    },
];
