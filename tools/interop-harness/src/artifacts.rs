//! The **Run Dir** and what a flow writes into it: the layout every artifact
//! path is derived from, the **Synthetic File** the counterparties share, and
//! the ED2K hash command that turns it into the link they are handed. Paths are
//! resolved through `RunLayout` rather than joined ad hoc so a container's
//! output lands where the collectors and the verdict later look for it. Nothing
//! written here is ever auto-promoted into `tests/fixtures/`.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

/// The **Run Dir**: every artifact path a flow reads or writes, derived from
/// one root so containers and collectors agree on where things land.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunLayout {
    root: PathBuf,
}

impl RunLayout {
    /// Create the run dir and every directory a flow may write into.
    ///
    /// The root is made absolute first, and that is not cosmetic: every
    /// container mount a flow makes (`-v <host_dir>:/capture`, `/proof`,
    /// `/out`) names a path from this layout, and a Docker CLI given a
    /// *relative* source silently creates an anonymous volume instead of a bind
    /// mount. The flow then succeeds, the container writes happily, and the run
    /// dir is empty — an artifact loss that looks exactly like a counterparty
    /// that produced nothing.
    pub fn create(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        let root = if root.is_absolute() {
            root
        } else {
            std::env::current_dir()
                .context("resolve the run dir against the working directory")?
                .join(root)
        };
        let layout = Self { root };
        for dir in [
            layout.synthetic_dir(),
            layout.rmule_dir(),
            layout.amule_dir(),
            layout.docker_dir(),
            layout.server_logs_dir(),
            layout.amule_logs_dir(),
            layout.rmule_logs_dir(),
            layout.kad_dir(),
            layout.kad_capture_dir(),
            layout.kad_logs_dir(),
        ] {
            fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        }
        Ok(layout)
    }

    /// The run dir itself.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `synthetic/` under the run dir.
    pub fn synthetic_dir(&self) -> PathBuf {
        self.root.join("synthetic")
    }

    /// `<synthetic_dir>/shared.bin`.
    pub fn synthetic_shared_file(&self) -> PathBuf {
        self.synthetic_dir().join("shared.bin")
    }

    /// `<synthetic_dir>/shared.ed2k.txt`.
    pub fn synthetic_ed2k_file(&self) -> PathBuf {
        self.synthetic_dir().join("shared.ed2k.txt")
    }

    /// `rmule/` under the run dir.
    pub fn rmule_dir(&self) -> PathBuf {
        self.root.join("rmule")
    }

    /// `<rmule_dir>/output.bin`.
    pub fn rmule_output_file(&self) -> PathBuf {
        self.rmule_dir().join("output.bin")
    }

    /// `amule/` under the run dir.
    pub fn amule_dir(&self) -> PathBuf {
        self.root.join("amule")
    }

    /// `<amule_dir>/shared.bin`.
    pub fn amule_output_file(&self) -> PathBuf {
        self.amule_dir().join("shared.bin")
    }

    /// `<rmule_dir>/stdout.log`.
    pub fn rmule_stdout_log(&self) -> PathBuf {
        self.rmule_dir().join("stdout.log")
    }

    /// `<rmule_dir>/stderr.log`.
    pub fn rmule_stderr_log(&self) -> PathBuf {
        self.rmule_dir().join("stderr.log")
    }

    /// `docker/` under the run dir.
    pub fn docker_dir(&self) -> PathBuf {
        self.root.join("docker")
    }

    /// Directory the `bench-smoke` probe writes into (`stdout.log`,
    /// `stderr.log`, and the probe's own `probe.txt`).
    /// `probe/` under the run dir.
    pub fn probe_dir(&self) -> PathBuf {
        self.root.join("probe")
    }

    /// `<probe_dir>/stdout.log`.
    pub fn probe_stdout_log(&self) -> PathBuf {
        self.probe_dir().join("stdout.log")
    }

    /// `<probe_dir>/stderr.log`.
    pub fn probe_stderr_log(&self) -> PathBuf {
        self.probe_dir().join("stderr.log")
    }

    /// The distilled `bench-smoke` verdict (compression + crypt advert), the
    /// decision input that resolves whether an obfuscation-capable eNode is
    /// ever needed.
    /// `bench-smoke-summary.toml/` under the run dir.
    pub fn bench_smoke_summary_file(&self) -> PathBuf {
        self.root.join("bench-smoke-summary.toml")
    }

    /// `<docker_dir>/network-id.txt`.
    pub fn network_id_file(&self) -> PathBuf {
        self.docker_dir().join("network-id.txt")
    }

    /// `<docker_dir>/server-container-id.txt`.
    pub fn server_container_id_file(&self) -> PathBuf {
        self.docker_dir().join("server-container-id.txt")
    }

    /// `<docker_dir>/amule-container-id.txt`.
    pub fn amule_container_id_file(&self) -> PathBuf {
        self.docker_dir().join("amule-container-id.txt")
    }

    /// `logs/server/` under the run dir.
    pub fn server_logs_dir(&self) -> PathBuf {
        self.root.join("logs/server")
    }

    /// `<server_logs_dir>/stdout.log`.
    pub fn server_stdout_log(&self) -> PathBuf {
        self.server_logs_dir().join("stdout.log")
    }

    /// `<server_logs_dir>/stderr.log`.
    pub fn server_stderr_log(&self) -> PathBuf {
        self.server_logs_dir().join("stderr.log")
    }

    /// `logs/amule/` under the run dir.
    pub fn amule_logs_dir(&self) -> PathBuf {
        self.root.join("logs/amule")
    }

    /// `<amule_logs_dir>/stdout.log`.
    pub fn amule_stdout_log(&self) -> PathBuf {
        self.amule_logs_dir().join("stdout.log")
    }

    /// `<amule_logs_dir>/stderr.log`.
    pub fn amule_stderr_log(&self) -> PathBuf {
        self.amule_logs_dir().join("stderr.log")
    }

    /// `<amule_logs_dir>/diagnostics.stdout.log`.
    pub fn amule_diagnostics_stdout_log(&self) -> PathBuf {
        self.amule_logs_dir().join("diagnostics.stdout.log")
    }

    /// `<amule_logs_dir>/diagnostics.stderr.log`.
    pub fn amule_diagnostics_stderr_log(&self) -> PathBuf {
        self.amule_logs_dir().join("diagnostics.stderr.log")
    }

    /// `logs/rmule/` under the run dir.
    pub fn rmule_logs_dir(&self) -> PathBuf {
        self.root.join("logs/rmule")
    }

    /// `kad/` under the run dir.
    pub fn kad_dir(&self) -> PathBuf {
        self.root.join("kad")
    }

    /// `capture/kad/` under the run dir.
    pub fn kad_capture_dir(&self) -> PathBuf {
        self.root.join("capture/kad")
    }

    /// `<kad_capture_dir>/kad.pcap`.
    pub fn kad_pcap_file(&self) -> PathBuf {
        self.kad_capture_dir().join("kad.pcap")
    }

    /// `<kad_dir>/nodes.toml`.
    pub fn kad_nodes_file(&self) -> PathBuf {
        self.kad_dir().join("nodes.toml")
    }

    /// `<kad_dir>/endpoints.toml`.
    pub fn kad_endpoint_map_file(&self) -> PathBuf {
        self.kad_dir().join("endpoints.toml")
    }

    /// `<kad_dir>/candidate-summary.toml`.
    pub fn kad_candidate_summary_file(&self) -> PathBuf {
        self.kad_dir().join("candidate-summary.toml")
    }

    /// `logs/kad/` under the run dir.
    pub fn kad_logs_dir(&self) -> PathBuf {
        self.root.join("logs/kad")
    }

    /// `nat/` under the run dir — the **NAT Type Proof**'s home, one
    /// subdirectory per gateway type.
    pub fn nat_dir(&self) -> PathBuf {
        self.root.join("nat")
    }

    /// `nat/<nat_type>/` — one gateway leg's whole record: the `nft` ruleset and
    /// `conntrack` dumps the gateway wrote, the reflector probe's row, the
    /// per-attachment pcaps, and the `nat-type.toml` that judges them.
    pub fn nat_type_dir(&self, nat_type: &str) -> PathBuf {
        self.nat_dir().join(nat_type)
    }

    /// `ipv6/` under the run dir — where `ipv6-net-accept` records what each
    /// counterparty body did with a **Fake-Public v6 Plan** address.
    pub fn ipv6_dir(&self) -> PathBuf {
        self.root.join("ipv6")
    }

    /// `logs/kad/<role>/`.
    pub fn kad_node_logs_dir(&self, role: &str) -> PathBuf {
        self.kad_logs_dir().join(role)
    }

    /// Per-node directory holding the binary identity seed files
    /// (`preferencesKad.dat`, `nodes.dat`) the harness mounts at `/seed`.
    pub fn kad_node_seed_dir(&self, role: &str) -> PathBuf {
        self.kad_dir().join("seed").join(role)
    }

    /// Artifacts directory the rmule join-node container mounts at
    /// `/artifacts`: its datagram capture tap and events log land here.
    /// `<kad_dir>/rmule`.
    pub fn kad_rmule_dir(&self) -> PathBuf {
        self.kad_dir().join("rmule")
    }

    /// `logs/kad/<role>/stdout.log`.
    pub fn kad_node_stdout_log(&self, role: &str) -> PathBuf {
        self.kad_node_logs_dir(role).join("stdout.log")
    }

    /// `logs/kad/<role>/stderr.log`.
    pub fn kad_node_stderr_log(&self, role: &str) -> PathBuf {
        self.kad_node_logs_dir(role).join("stderr.log")
    }
}

/// The host-run command that ED2K-hashes the synthetic file and prints its
/// `canonical_link:`; a stub in tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed2kHashCommand {
    program: OsString,
    args: Vec<OsString>,
}

impl Ed2kHashCommand {
    /// Hash with `program` (the file path is appended as the last argument).
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
        }
    }

    /// `cargo run -p rmule-tools -- ed2k hash-file`.
    pub fn cargo_rmule_tools() -> Self {
        Self::new("cargo")
            .arg("run")
            .arg("-p")
            .arg("rmule-tools")
            .arg("--")
            .arg("ed2k")
            .arg("hash-file")
    }

    /// An extra argument before the file path.
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    fn to_command(&self, file: &Path) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.args).arg(file);
        command
    }
}

/// Write the deterministic **Synthetic File** (`byte = offset % 251`) of `size`
/// bytes.
pub fn write_synthetic_file(layout: &RunLayout, size: u64) -> Result<()> {
    let path = layout.synthetic_shared_file();
    let file = File::create(&path).with_context(|| format!("create {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    let mut offset = 0_u64;
    let mut remaining = size;
    let mut buffer = [0_u8; 8192];

    while remaining > 0 {
        let count = remaining.min(buffer.len() as u64) as usize;
        for (index, byte) in buffer[..count].iter_mut().enumerate() {
            *byte = ((offset + index as u64) % 251) as u8;
        }
        writer
            .write_all(&buffer[..count])
            .with_context(|| format!("write {}", path.display()))?;
        offset += count as u64;
        remaining -= count as u64;
    }
    writer
        .flush()
        .with_context(|| format!("flush {}", path.display()))
}

/// Write `size` zero bytes to `path` as one hole: the length is set and no
/// block is written, so a file past 4 GiB is staged without the disk holding
/// it, and a reader sees zeros.
pub fn write_sparse_file(path: &Path, size: u64) -> Result<()> {
    let file = File::create(path).with_context(|| format!("create {}", path.display()))?;
    file.set_len(size)
        .with_context(|| format!("set the length of {}", path.display()))
}

/// Write `size` bytes to `path` that no compressor shrinks: a xorshift
/// stream from `seed`. A peer compresses a part it sends when that saves
/// bytes, so a patterned file crosses a throttled link at many times its cap.
pub fn write_incompressible_file(path: &Path, size: u64, seed: u64) -> Result<()> {
    let file = File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    let mut state = seed | 1;
    let mut remaining = size;
    let mut buffer = [0_u8; 8192];
    while remaining > 0 {
        let count = remaining.min(buffer.len() as u64) as usize;
        for chunk in buffer[..count].chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
        }
        writer
            .write_all(&buffer[..count])
            .with_context(|| format!("write {}", path.display()))?;
        remaining -= count as u64;
    }
    writer
        .flush()
        .with_context(|| format!("flush {}", path.display()))
}

/// Hash the synthetic file with `command` and retain its canonical ed2k link.
pub fn write_synthetic_ed2k_link(layout: &RunLayout, command: &Ed2kHashCommand) -> Result<String> {
    write_ed2k_link(
        command,
        &layout.synthetic_shared_file(),
        &layout.synthetic_ed2k_file(),
    )
}

/// Hash `file` with `command` and retain its canonical ed2k link in `out`.
pub fn write_ed2k_link(command: &Ed2kHashCommand, file: &Path, out: &Path) -> Result<String> {
    let output = command
        .to_command(file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("run ed2k hash command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("ed2k hash command exited unsuccessfully: {stderr}");
    }

    let stdout = String::from_utf8(output.stdout).context("ed2k hash command emitted non-utf8")?;
    let link = parse_canonical_link(&stdout)?;
    fs::write(out, format!("{link}\n")).with_context(|| format!("write {}", out.display()))?;
    Ok(link)
}

fn parse_canonical_link(stdout: &str) -> Result<String> {
    for line in stdout.lines() {
        if let Some(link) = line.strip_prefix("canonical_link: ") {
            if link.is_empty() {
                bail!("ed2k hash command printed an empty canonical_link");
            }
            return Ok(link.to_owned());
        }
    }
    bail!("ed2k hash command did not print a canonical_link line")
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::write_incompressible_file;

    /// zlib gains nothing on the staged bytes, so a peer that compresses a
    /// part when that saves bytes sends them whole, at its cap.
    #[test]
    fn an_incompressible_file_does_not_shrink_under_zlib() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("staged.bin");
        write_incompressible_file(&path, 1 << 20, 0x5EED_0001).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 1 << 20);
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        zlib.write_all(&bytes).unwrap();
        let packed = zlib.finish().unwrap();
        assert!(
            packed.len() >= bytes.len(),
            "{} -> {}",
            bytes.len(),
            packed.len()
        );
    }
}
