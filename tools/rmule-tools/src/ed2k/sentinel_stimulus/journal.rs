//! The stimulus's own written record: every frame it emitted, every frame the
//! counterparty sent it, and every dial that landed on a **Source Sink**.
//!
//! Two kinds of row live here and they are not equal evidence. `emitted` rows
//! are rmule's own bytes — **Stimulus**, retained for context and never proof
//! of anything (ADR-0045). `received` and `sink_dial` rows are the
//! counterparty's own bytes, which is what a verdict may read. The renderer
//! keeps them in separate tables so a reader cannot conflate them.
//!
//! Rendered as TOML by hand: `rmule-tools` carries no serialiser, and the
//! harness parses the file back with its own `toml` dependency.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};

/// One thing that happened, in the order it happened.
pub(crate) enum Entry {
    /// A counterparty completed `OP_LOGINREQUEST` and was answered.
    Login {
        /// Its source endpoint on this bench.
        peer: String,
        /// The TCP port it advertised in the login.
        client_tcp_port: u16,
        /// The User Hash it advertised.
        user_hash: String,
        /// The id the stimulus assigned it.
        assigned_id: String,
    },
    /// A frame the counterparty sent — its own bytes.
    Received {
        /// `tcp` or `udp`.
        transport: &'static str,
        /// Where it came from.
        peer: String,
        /// The opcode byte after the protocol byte.
        opcode: u8,
        /// How many payload bytes followed.
        payload_len: usize,
    },
    /// A frame the stimulus emitted — rmule's own bytes, never evidence.
    Emitted {
        /// `tcp` or `udp`.
        transport: &'static str,
        /// Where it was sent.
        peer: String,
        /// What the flow calls this emission.
        label: String,
        /// What made it fire (`get-sources`, `timer`, `glob-get-sources`).
        trigger: String,
        /// The whole frame, hex.
        bytes: String,
    },
    /// A counterparty dialled one of the **Source Sink** endpoints — the
    /// address and port it decoded out of a source record, in its own TCP SYN,
    /// followed by whatever it said first.
    SinkDial {
        /// The sink address the dial landed on: the record's decoded endpoint.
        local: String,
        /// The dialling counterparty.
        peer: String,
        /// Its first bytes, hex (an `OP_HELLO`, normally).
        bytes: String,
    },
}

/// The stimulus's append-only record.
pub(crate) struct Journal {
    listen: String,
    udp_listen: String,
    sinks: Vec<String>,
    entries: Mutex<Vec<Entry>>,
}

impl Journal {
    /// A record for a stimulus bound to `listen` / `udp_listen`, holding the
    /// sink endpoints so an unused sink is visible as a zero rather than as an
    /// absent row.
    pub(crate) fn new(listen: String, udp_listen: String, sinks: Vec<String>) -> Self {
        Self {
            listen,
            udp_listen,
            sinks,
            entries: Mutex::new(Vec::new()),
        }
    }

    /// Append one entry.
    pub(crate) fn push(&self, entry: Entry) {
        self.entries
            .lock()
            .expect("sentinel stimulus journal")
            .push(entry);
    }

    /// Render the whole record as TOML.
    pub(crate) fn render(&self) -> String {
        let entries = self.entries.lock().expect("sentinel stimulus journal");
        let mut out = String::new();
        let _ = writeln!(out, "stimulus = \"sentinel-stimulus\"");
        let _ = writeln!(out, "listen = \"{}\"", self.listen);
        let _ = writeln!(out, "udp_listen = \"{}\"", self.udp_listen);
        let _ = writeln!(out, "sinks = {}", toml_string_array(&self.sinks));
        let _ = writeln!(
            out,
            "logins = {}",
            count(&entries, |e| matches!(e, Entry::Login { .. }))
        );
        let _ = writeln!(
            out,
            "sink_dials = {}",
            count(&entries, |e| matches!(e, Entry::SinkDial { .. }))
        );
        for entry in entries.iter() {
            render_entry(&mut out, entry);
        }
        out
    }

    /// Write the record to `dir/stimulus.toml` and print it.
    ///
    /// # Errors
    /// If the directory cannot be created or the file cannot be written.
    pub(crate) fn write(&self, dir: &Path) -> Result<()> {
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        let path = dir.join("stimulus.toml");
        let text = self.render();
        println!("{text}");
        fs::write(&path, text).with_context(|| format!("write {}", path.display()))
    }
}

fn count(entries: &[Entry], predicate: impl Fn(&Entry) -> bool) -> usize {
    entries.iter().filter(|entry| predicate(entry)).count()
}

fn render_entry(out: &mut String, entry: &Entry) {
    match entry {
        Entry::Login {
            peer,
            client_tcp_port,
            user_hash,
            assigned_id,
        } => {
            let _ = write!(
                out,
                "\n[[login]]\npeer = \"{peer}\"\nclient_tcp_port = {client_tcp_port}\n\
                 user_hash = \"{user_hash}\"\nassigned_id = \"{assigned_id}\"\n"
            );
        }
        Entry::Received {
            transport,
            peer,
            opcode,
            payload_len,
        } => {
            let _ = write!(
                out,
                "\n[[received]]\ntransport = \"{transport}\"\npeer = \"{peer}\"\n\
                 opcode = {opcode}\npayload_len = {payload_len}\n"
            );
        }
        Entry::Emitted {
            transport,
            peer,
            label,
            trigger,
            bytes,
        } => {
            let _ = write!(
                out,
                "\n[[emitted]]\ntransport = \"{transport}\"\npeer = \"{peer}\"\n\
                 label = \"{label}\"\ntrigger = \"{trigger}\"\nbytes = \"{bytes}\"\n"
            );
        }
        Entry::SinkDial { local, peer, bytes } => {
            let _ = write!(
                out,
                "\n[[sink_dial]]\nlocal = \"{local}\"\npeer = \"{peer}\"\nbytes = \"{bytes}\"\n"
            );
        }
    }
}

fn toml_string_array(values: &[String]) -> String {
    let inner: Vec<String> = values.iter().map(|value| format!("\"{value}\"")).collect();
    format!("[{}]", inner.join(", "))
}

/// Lowercase hex, the spelling every frame in this record is written in.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_record_separates_counterparty_bytes_from_rmules_own() {
        let journal = Journal::new(
            "0.0.0.0:4661".to_owned(),
            "0.0.0.0:4665".to_owned(),
            vec!["5001".to_owned()],
        );
        journal.push(Entry::Emitted {
            transport: "tcp",
            peer: "203.0.113.3:1".to_owned(),
            label: "found-sources".to_owned(),
            trigger: "timer".to_owned(),
            bytes: hex(&[0xE3, 0x42]),
        });
        journal.push(Entry::SinkDial {
            local: "203.0.113.50:5001".to_owned(),
            peer: "203.0.113.3:2".to_owned(),
            bytes: hex(&[0xE3, 0x01]),
        });
        let rendered = journal.render();
        assert!(rendered.contains("sink_dials = 1"), "{rendered}");
        assert!(rendered.contains("[[emitted]]"), "{rendered}");
        assert!(rendered.contains("[[sink_dial]]"), "{rendered}");
        assert!(rendered.contains("bytes = \"e342\""), "{rendered}");
        // The renderer's whole job is being readable back by the harness.
        let parsed: toml::Value = toml::from_str(&rendered).expect("journal renders valid TOML");
        assert_eq!(parsed["sink_dials"].as_integer(), Some(1));
    }
}
