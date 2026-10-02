//! The harness's one integration binary: every leg is a module, so `cargo test`
//! links once and runs the legs' tests in parallel. The live legs (`acceptance`,
//! `real_container_smoke`) stay `#[ignore]`d and gated on a runtime being
//! present; every other leg runs against the **Fake Docker** or no runtime at
//! all, so a plain `cargo test` never reaches for a container.
//!
//! Unix only: the bench is Linux containers, and the Fake Docker and the stub
//! hash commands the legs share are `/bin/sh` scripts made executable by mode
//! bits.

#![cfg(unix)]

mod acceptance;
mod artifacts;
mod cli;
mod docker_commands;
mod fake_docker;
mod fixture;
mod image_labels;
mod natgw_ruleset;
mod readiness;
mod real_container_smoke;
mod rmule_container;
mod rmule_output;
