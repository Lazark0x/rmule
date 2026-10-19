//! rmule's side of the flow: one `rmule-tools` container that runs
//! `ed2k download start --serve` and, for a restart, `ed2k download reopen`
//! after it over the same Durable Store. One container, not two, so rmule's
//! address, its ports and the tap that shares its namespace all outlive the
//! restart: a peer that knew rmule before it finds the same node after.
//!
//! The container holds until the harness writes its start gate, so the tap
//! is listening before rmule's first login and dial. Every path below is
//! the container's view of the run dir, mounted at [`RUN_MOUNT`].

use rmule_primitives::ED2K_PART_SIZE;

use crate::flow::bench::AMULE_PEER_TCP_PORT;
use crate::rmule::RMULE_SERVE_TCP_PORT;

/// Where the rmule and stimulus containers mount the run dir.
pub(crate) const RUN_MOUNT: &str = "/w";
/// The `rmule-tools` image's own entrypoint
/// (`images/rmule-tools/entrypoint.sh`), so its env knobs still apply.
const IMAGE_ENTRYPOINT: &str = "/entrypoint.sh";
/// rmule's one client-UDP port, the same in both legs: a queued peer's
/// reask after the restart must reach the port rmule advertised before it.
pub(crate) const RMULE_UDP_PORT: u16 = 4672;
/// rmule's User Hash, the same in both legs. The stimulus takes another
/// (`STIMULUS_USER_HASH`): one hash on both ends reads as a self-connection.
const RMULE_USER_HASH: &str = "5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A";
/// The stimulus peer's User Hash.
pub(crate) const STIMULUS_USER_HASH: &str = "3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C";

/// Under the flow's root dir: rmule's store, Temp Directory, download
/// directory, the whole file it shares beside, and the gates.
pub(crate) const DATA_DIR: &str = "rmule/data";
pub(crate) const TEMP_DIR: &str = "rmule/temp";
pub(crate) const INCOMING_DIR: &str = "rmule/incoming";
pub(crate) const SHARE_DIR: &str = "share";
pub(crate) const START_GATE: &str = "gates/start";
pub(crate) const PAUSE_GATE: &str = "gates/pause";
pub(crate) const STOP_GATE: &str = "gates/stop";

/// What rmule's legs are asked to do.
pub(crate) struct Legs<'a> {
    /// The flow's root, as the container sees it (`/w/partial-share`).
    pub(crate) root: &'a str,
    /// The eserver as `host:port`.
    pub(crate) server: &'a str,
    /// The stream file's link, its seeds named as sources.
    pub(crate) link: &'a str,
    /// The stream file's name in the download directory.
    pub(crate) file_name: &'a str,
    /// The whole file shared beside the download, by its name under
    /// [`SHARE_DIR`]; `None` shares none.
    pub(crate) whole: Option<&'a str>,
    /// Share the whole file only once the pause lands, so its trigger
    /// re-announces while the download is paused.
    pub(crate) whole_after_pause: bool,
    /// rmule's upload slots; `None` keeps the core's.
    pub(crate) upload_slots: Option<usize>,
    /// rmule's Connection Ceiling (ADR-0116); `None` keeps the core's.
    pub(crate) max_connections: Option<usize>,
    /// Watch the pause gate.
    pub(crate) pause: bool,
    /// Run a second leg, `download reopen`, once the first ends.
    pub(crate) restart: bool,
    /// Leg one's bound, in seconds; its stop gate usually ends it first.
    pub(crate) hold_secs: u64,
    /// Leg two's length, in seconds.
    pub(crate) reopen_secs: u64,
    /// Shape rmule's egress to this address at this many kbit/s, so a
    /// downloader on the bench network fetches a part over minutes: aMule's
    /// own download cap reacts only after a burst, and a part crosses the
    /// bridge in half a second.
    pub(crate) shaped: Option<(std::net::Ipv4Addr, u32)>,
    /// Drop rmule's dials to these addresses' peer port, so rmule never
    /// opens a link to a downloader: stock aMule closes a client's first
    /// link when a second says the same hello (`ClientList.cpp:395-401`).
    pub(crate) undialled: Vec<std::net::Ipv4Addr>,
    /// Drop rmule's client-UDP datagrams to this address, so its UDP reask
    /// goes unanswered and it reasks over a new TCP link at
    /// `FILEREASKTIME` (`PartFile.cpp:1449-1481`).
    pub(crate) unacked: Option<std::net::Ipv4Addr>,
}

impl Legs<'_> {
    fn at(&self, path: &str) -> String {
        format!("{}/{path}", self.root)
    }

    /// The arguments both legs pass alike.
    fn common(&self) -> Vec<String> {
        let mut args = vec![
            "--data-dir".to_owned(),
            self.at(DATA_DIR),
            "--server".to_owned(),
            self.server.to_owned(),
            "--tcp-port".to_owned(),
            RMULE_SERVE_TCP_PORT.to_string(),
            "--udp-port".to_owned(),
            RMULE_UDP_PORT.to_string(),
            "--user-hash".to_owned(),
            RMULE_USER_HASH.to_owned(),
            "--temp-dir".to_owned(),
            self.at(TEMP_DIR),
            "--share-download-dir".to_owned(),
            "--stamp-events".to_owned(),
            "--report-parts-every-ms".to_owned(),
            "1000".to_owned(),
        ];
        if let Some(slots) = self.upload_slots {
            args.extend(["--upload-slots".to_owned(), slots.to_string()]);
        }
        args
    }

    fn whole_path(&self) -> Option<String> {
        self.whole
            .map(|name| self.at(&format!("{SHARE_DIR}/{name}")))
    }

    /// Leg one: the download, served from its first verified part.
    pub(crate) fn first(&self) -> Vec<String> {
        let mut args: Vec<String> = ["ed2k", "download", "start"].map(str::to_owned).into();
        args.extend(self.common());
        args.extend([
            "--file".to_owned(),
            self.link.to_owned(),
            "--out".to_owned(),
            self.at(&format!("{INCOMING_DIR}/{}", self.file_name)),
            "--serve".to_owned(),
            "--linger".to_owned(),
            "--max-seconds".to_owned(),
            self.hold_secs.to_string(),
            "--stop-gate".to_owned(),
            self.at(STOP_GATE),
        ]);
        if self.pause {
            args.extend(["--pause-gate".to_owned(), self.at(PAUSE_GATE)]);
        }
        if let Some(workers) = self.max_connections {
            args.extend(["--max-connections".to_owned(), workers.to_string()]);
        }
        if let Some(whole) = self.whole_path() {
            let flag = if self.pause && self.whole_after_pause {
                "--share-after-pause"
            } else {
                "--share"
            };
            args.extend([flag.to_owned(), whole]);
        }
        args
    }

    /// Leg two: the same store reopened, nothing resumed.
    pub(crate) fn second(&self) -> Vec<String> {
        let mut args: Vec<String> = ["ed2k", "download", "reopen"].map(str::to_owned).into();
        args.extend(self.common());
        args.extend([
            "--download-dir".to_owned(),
            self.at(INCOMING_DIR),
            "--max-seconds".to_owned(),
            self.reopen_secs.to_string(),
        ]);
        // The whole file is not shared again: leg one's row for it stands in
        // the store, and a second copy of one content is refused.
        args
    }

    /// The container's `sh -c` script: wait for the start gate, run leg
    /// one, then — for a restart — leg two in its place.
    pub(crate) fn script(&self) -> String {
        let mut legs = vec![self.first()];
        if self.restart {
            legs.push(self.second());
        }
        let mut text = link_conditions(self.shaped, &self.undialled, self.unacked);
        text.push_str(&script(&self.at(START_GATE), &legs));
        text
    }
}

/// `legs` run one after the other behind `gate`, the last in the shell's
/// place, with a line between them saying how the one before ended.
pub(crate) fn script(gate: &str, legs: &[Vec<String>]) -> String {
    let mut text = format!("while [ ! -e {} ]; do sleep 0.1; done\n", quote(gate));
    for (index, leg) in legs.iter().enumerate() {
        let command = std::iter::once(IMAGE_ENTRYPOINT.to_owned())
            .chain(leg.iter().cloned())
            .map(|arg| quote(&arg))
            .collect::<Vec<_>>()
            .join(" ");
        if index + 1 == legs.len() {
            text.push_str(&format!("exec {command}\n"));
        } else {
            text.push_str(&format!(
                "{command}\necho \"rmule-leg-ended leg={} status=$?\"\n",
                index + 1
            ));
        }
    }
    text
}

/// The `tc` lines that set rmule's own link: a `prio` root; a drop filter
/// for each of `undialled`'s peer port (a dial there dies unanswered); one
/// for every UDP datagram to `unacked`; and, for `shaped`, a token bucket
/// draining the third band and a filter sending that one address there,
/// every other destination keeping its pace. A network condition on rmule's
/// own link, not a change to either body.
pub(crate) fn link_conditions(
    shaped: Option<(std::net::Ipv4Addr, u32)>,
    undialled: &[std::net::Ipv4Addr],
    unacked: Option<std::net::Ipv4Addr>,
) -> String {
    if shaped.is_none() && undialled.is_empty() && unacked.is_none() {
        return String::new();
    }
    let mut lines = vec!["tc qdisc add dev eth0 root handle 1: prio".to_owned()];
    for address in undialled {
        lines.push(format!(
            "tc filter add dev eth0 parent 1: protocol ip prio 1 u32 match ip dst {address}/32 \
             match ip dport {AMULE_PEER_TCP_PORT} 0xffff action drop"
        ));
    }
    if let Some(address) = unacked {
        lines.push(format!(
            "tc filter add dev eth0 parent 1: protocol ip prio 1 u32 match ip dst {address}/32 \
             match ip protocol 17 0xff action drop"
        ));
    }
    if let Some((address, kbit)) = shaped {
        lines.push(format!(
            "tc qdisc add dev eth0 parent 1:3 handle 30: tbf rate {kbit}kbit burst 16kb latency 1s"
        ));
        lines.push(format!(
            "tc filter add dev eth0 parent 1: protocol ip prio 2 u32 match ip dst {address}/32 flowid 1:3"
        ));
    }
    let listed: Vec<String> = undialled.iter().map(ToString::to_string).collect();
    lines.push(format!(
        "echo \"rmule-link-conditions shaped={} undialled={} unacked={}\"",
        shaped.map_or_else(
            || "none".to_owned(),
            |(address, kbit)| format!("{address}@{kbit}kbit")
        ),
        listed.join(","),
        unacked.map_or_else(|| "none".to_owned(), |address| address.to_string())
    ));
    format!(
        "{} || {{ echo \"rmule-link-conditions-failed\" >&2; exit 1; }}\n",
        lines.join(" && ")
    )
}

/// `arg` single-quoted for `sh`: an ed2k link's `|` and every other byte
/// pass as they are.
fn quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', r"'\''"))
}

/// A request that straddles a verified part's edge into a part rmule lacks,
/// for a part map (`V` verified, `I` in flight, `M` missing): 4 KiB either
/// side of the end of a verified part whose next part is missing, else of
/// the start of one whose previous part is; and a request inside that
/// verified part, at its start, that a slot still held would be served.
/// A missing neighbour, not one in flight, so it cannot verify between the
/// look and the ask.
pub(crate) fn straddle(parts: &str, size: u64) -> Option<((u64, u64), (u64, u64))> {
    const EDGE: u64 = 4_096;
    let letters: Vec<char> = parts.chars().collect();
    let start = |index: usize| index as u64 * ED2K_PART_SIZE;
    let end = |index: usize| (start(index) + ED2K_PART_SIZE).min(size);
    let inside = |index: usize| (start(index), (start(index) + EDGE).min(end(index)));
    for (index, letter) in letters.iter().enumerate() {
        if *letter != 'V' {
            continue;
        }
        if letters.get(index + 1) == Some(&'M') {
            let edge = end(index);
            return Some(((edge - EDGE, edge + EDGE), inside(index)));
        }
        if index > 0 && letters[index - 1] == 'M' {
            let edge = start(index);
            return Some(((edge - EDGE, edge + EDGE), inside(index)));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{script, straddle};
    use rmule_primitives::ED2K_PART_SIZE;

    /// A link's `|` and a quote inside an argument reach the command as
    /// they are; every leg but the last reports how it ended.
    #[test]
    fn the_script_quotes_each_argument_and_runs_the_legs_in_order() {
        let text = script(
            "/w/gates/start",
            &[
                vec!["ed2k://|file|a.bin|1|AB|/".to_owned()],
                vec!["it's".to_owned()],
            ],
        );
        assert_eq!(
            text,
            "while [ ! -e '/w/gates/start' ]; do sleep 0.1; done\n\
             '/entrypoint.sh' 'ed2k://|file|a.bin|1|AB|/'\n\
             echo \"rmule-leg-ended leg=1 status=$?\"\n\
             exec '/entrypoint.sh' 'it'\\''s'\n"
        );
    }

    /// The straddle crosses a verified part's edge into a missing part;
    /// one in flight beside it is not taken, and the inside ask stays in
    /// the verified part.
    #[test]
    fn the_straddle_crosses_into_a_missing_part_only() {
        let size = 6 * ED2K_PART_SIZE - 1_000;
        assert_eq!(
            straddle("VIMVMM", size),
            Some((
                (4 * ED2K_PART_SIZE - 4_096, 4 * ED2K_PART_SIZE + 4_096),
                (3 * ED2K_PART_SIZE, 3 * ED2K_PART_SIZE + 4_096)
            ))
        );
        assert_eq!(
            straddle("VMMMMM", size),
            Some(((ED2K_PART_SIZE - 4_096, ED2K_PART_SIZE + 4_096), (0, 4_096)))
        );
        assert_eq!(straddle("VIIIII", size), None);
    }
}
