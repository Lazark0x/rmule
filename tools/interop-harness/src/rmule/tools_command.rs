//! The host-side `rmule-tools` invocation a flow drives its stimulus with: a
//! program plus a fixed argv prefix, and one builder per rmule-tools run a
//! flow needs (download start, search, SUI capture, user-hash probe). It
//! only composes argv — running, container placement and output judging belong
//! to the sibling modules.

use std::ffi::OsString;
use std::process::Command;

use crate::artifacts::RunLayout;

use super::RMULE_SERVE_TCP_PORT;

/// A host-run `rmule-tools`: the program and the argv prefix every run starts with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RmuleToolsCommand {
    program: OsString,
    args: Vec<OsString>,
}

impl RmuleToolsCommand {
    /// Run `program` as rmule-tools (the test hook substitutes a stub).
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
        }
    }

    /// `cargo run -p rmule-tools --`.
    pub fn cargo_rmule_tools() -> Self {
        Self::new("cargo")
            .arg("run")
            .arg("-p")
            .arg("rmule-tools")
            .arg("--")
    }

    /// An extra prefix argument.
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub(super) fn download_start_command(
        &self,
        layout: &RunLayout,
        server_endpoint: &str,
        ed2k_link: &str,
        serve: bool,
    ) -> Command {
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .args(["ed2k", "download", "start", "--data-dir"]);
        command
            .arg(layout.rmule_dir())
            .args(["--server", server_endpoint, "--file", ed2k_link, "--out"])
            .arg(layout.rmule_output_file())
            .args(["--tcp-port", &RMULE_SERVE_TCP_PORT.to_string()]);
        // Serve while downloading so rmule is High-ID and callback-capable
        // (ADR-0039) — required to adopt a Low-ID source.
        if serve {
            command.arg("--serve");
        }
        command
    }

    pub(super) fn search_command(&self, server_endpoint: &str, query: &str) -> Command {
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .args([
                "ed2k",
                "search",
                "--server",
                server_endpoint,
                "--query",
                query,
            ])
            .args(["--tcp-port", &RMULE_SERVE_TCP_PORT.to_string()]);
        command
    }

    pub(super) fn sui_capture_command(
        &self,
        layout: &RunLayout,
        peer_endpoint: &str,
        ed2k_link: &str,
        max_seconds: u64,
        obfuscation: Option<(&str, &str)>,
    ) -> Command {
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .args([
                "ed2k",
                "peer",
                "transfer",
                "capture",
                "--peer",
                peer_endpoint,
            ])
            .args(["--file", ed2k_link])
            .arg("--output-dir")
            .arg(layout.rmule_dir())
            // Full capture: the SUI opcodes are the golden-vector
            // source, and OP_SENDINGPART payloads make the run self-checking.
            .args(["--mode", "full"])
            .args(["--max-seconds", &max_seconds.to_string()])
            .arg("--secure-ident");
        // Obfuscation: dial obfuscated, keyed on the aMule's User Hash
        // (learned from a plaintext hello by the caller). With `required` there is
        // no plaintext fallback, so a completing SUI exchange *is* the proof
        // rmule's 34/203 derivation is aMule-compatible.
        if let Some((policy, target_hash)) = obfuscation {
            command.args(["--obfuscation", policy]);
            command.args(["--obfuscation-target-hash", target_hash]);
        }
        command
    }

    /// A short plaintext hello — no SUI, no obfuscation — that surfaces the
    /// peer's advertised User Hash. aMule ignores a pre-set
    /// `amule.conf` UserHash and generates its own, so the obfuscation target
    /// hash cannot be pinned; it is learned here, then obfuscate-dialed. Runs
    /// without `--secure-ident` so it binds no key that would trip aMule's SUI
    /// anti-theft on the real obfuscated dial that follows.
    pub(super) fn probe_user_hash_command(
        &self,
        layout: &RunLayout,
        peer_endpoint: &str,
        ed2k_link: &str,
    ) -> Command {
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .args([
                "ed2k",
                "peer",
                "transfer",
                "capture",
                "--peer",
                peer_endpoint,
            ])
            .args(["--file", ed2k_link])
            .arg("--output-dir")
            .arg(layout.rmule_dir().join("probe"))
            .args(["--mode", "protocol-only"])
            .args(["--max-seconds", "10"]);
        command
    }
}
