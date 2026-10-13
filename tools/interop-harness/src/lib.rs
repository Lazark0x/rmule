//! The opt-in local interoperability harness: it stands real, unmodified
//! eMule-compatible processes up in containers, drives one exchange between them
//! and rmule, and writes down what actually happened. Evidence flows one way —
//! a counterparty's own bytes prove things and rmule's stimulus never does — so
//! a flow that cannot draw the bytes it wanted records a documented absence
//! instead. See `CONTEXT.md` for the vocabulary.
#![warn(missing_docs)]

pub mod artifacts;
pub mod bench_doctor;
pub mod docker;
pub mod fake_public;
pub mod fake_public_v6;
pub mod flow;
pub mod kad_distance_design;
pub mod kad_seed;
pub mod nat;
pub mod readiness;
pub mod rmule;
pub mod run_record;
