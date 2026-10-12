//! The `natt-server-punch-one-symmetric` half of the driver (ADR-0091's port-prediction
//! amendment): the knob, a Kad node seeded with the flow's open observers, and
//! the **Readiness Gate** that holds the identity back until the node knows its
//! own mapping.
//!
//! The gate is why Kad runs at all. **Port Prediction** starts only from an
//! Own Mapping, and the only things that report our UDP port back to us are
//! Kad contacts answering the Extern Port Round (one ping every 15 s, three
//! observers). A peer introduced before its round settles reads Unknown and
//! keeps the baseline. That would be a correct run of the product and a
//! useless run of the row, so the driver publishes its identity, which is what
//! lets the harness introduce it, only after the mapping reads known.

use std::net::SocketAddrV4;
use std::time::Duration;

use anyhow::{Result, bail};
use clap::{Args, ValueEnum};
use rmule_core::run_log::Level;
use rmule_core::{Core, CoreCommand, CoreEvent, KadEnableConfig, OwnMapping, PortPrediction};
use rmule_kad::KadId;

use crate::operand::{parse_hex16, parse_seeded_kad_contacts};

/// How often the gate re-reads the snapshot. The round adds an observer every
/// 15 s, so a finer poll buys nothing.
const OWN_MAPPING_POLL: Duration = Duration::from_secs(2);

/// `--port-prediction`, the CLI face of `natt.port_prediction`. It defaults to
/// `off` even though the product defaults to `birthday`: a bench row names the
/// knob it measures, so the existing server-punch rows keep measuring the baseline they always did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum PredictionKnob {
    /// The baseline alone.
    #[default]
    Off,
    /// The one-symmetric birthday policy.
    Birthday,
}

impl From<PredictionKnob> for PortPrediction {
    fn from(knob: PredictionKnob) -> Self {
        match knob {
            PredictionKnob::Off => Self::Off,
            PredictionKnob::Birthday => Self::Birthday,
        }
    }
}

/// The prediction row's operands.
#[derive(Debug, Args)]
pub(crate) struct PredictionArgs {
    /// `natt.port_prediction`.
    #[arg(long, value_enum, default_value_t = PredictionKnob::Off)]
    pub(crate) port_prediction: PredictionKnob,
    /// Our Kad ID as hex (32 chars). With it the node runs Kad, which is the
    /// only thing that can tell it its own mapping.
    #[arg(long)]
    kad_id: Option<String>,
    /// One **Seeded Bootstrap** contact, `<kad-id-hex>@<ipv4>:<udp-port>`,
    /// repeatable: the flow's open Kad observers.
    #[arg(long = "kad-contact")]
    kad_contacts: Vec<String>,
    /// A Kad node to bootstrap from, `<ipv4>:<udp-port>`, repeatable.
    #[arg(long = "kad-bootstrap")]
    kad_bootstrap: Vec<SocketAddrV4>,
    /// Seconds to wait, after the login, for the Own Mapping to read known
    /// before the identity is published. `0` publishes at once.
    #[arg(long, default_value_t = 0)]
    own_mapping_timeout: u64,
}

impl PredictionArgs {
    /// Refuse the operand set the module doc calls a useless run: `birthday`
    /// with no Kad ID never learns an Own Mapping at all, and `birthday` with
    /// no gate timeout publishes before it can, so either reads Unknown and
    /// keeps the baseline while the row claims the knob was measured.
    ///
    /// # Errors
    /// On either combination.
    pub(super) fn validate(&self) -> Result<()> {
        if self.port_prediction != PredictionKnob::Birthday {
            return Ok(());
        }
        if self.kad_id.is_none() {
            bail!("--port-prediction birthday needs --kad-id: only Kad reports the Own Mapping");
        }
        if self.own_mapping_timeout == 0 {
            bail!(
                "--port-prediction birthday needs --own-mapping-timeout > 0: a publish that does \
                 not wait for the Own Mapping introduces a peer that reads Unknown"
            );
        }
        Ok(())
    }
}

/// The Kad ID `--kad-id` names, which the core is built under.
pub(super) fn kad_id(args: &PredictionArgs) -> Result<Option<KadId>> {
    args.kad_id
        .as_deref()
        .map(|hex| parse_hex16("--kad-id", hex).map(KadId::from_bytes))
        .transpose()
}

/// Start Kad when a Kad ID was given; the core was built under it.
pub(super) async fn enable_kad(core: &mut Core, args: &PredictionArgs) -> Result<bool> {
    if args.kad_id.is_none() {
        return Ok(false);
    }
    core.send(CoreCommand::EnableKad(KadEnableConfig {
        bootstrap: args.kad_bootstrap.clone(),
        contacts: parse_seeded_kad_contacts(&args.kad_contacts)?,
        nodes_dat_path: None,
        assume_open_reachability: false,
        kad_capture_dir: None,
        kad_shutdown: None,
    }))
    .await?;
    Ok(true)
}

/// The Readiness Gate: poll the snapshot until the Own Mapping reads known or
/// the budget runs out. Returns what it last read, `Unknown` included. A gate
/// that timed out is a row, not an error.
pub(super) async fn await_own_mapping(
    core: &mut Core,
    args: &PredictionArgs,
) -> Result<OwnMapping> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.own_mapping_timeout);
    loop {
        core.send(CoreCommand::DumpDiagnostics).await?;
        let mapping = read_own_mapping(core).await?;
        if mapping != OwnMapping::Unknown || tokio::time::Instant::now() >= deadline {
            return Ok(mapping);
        }
        tokio::time::sleep(OWN_MAPPING_POLL).await;
    }
}

/// The next snapshot's Own Mapping. Other events are printed and passed over,
/// so the log still carries them.
async fn read_own_mapping(core: &mut Core) -> Result<OwnMapping> {
    loop {
        let Some(event) = core.next_event().await else {
            return Ok(OwnMapping::Unknown);
        };
        if let CoreEvent::DiagnosticsSnapshot { snapshot } = event {
            return Ok(snapshot.natt_own_mapping.unwrap_or(OwnMapping::Unknown));
        }
        println!("{}", event.record().render(Level::Full));
    }
}

/// The row's spelling of a mapping.
pub(super) const fn mapping_name(mapping: OwnMapping) -> &'static str {
    match mapping {
        OwnMapping::EndpointDependent => "endpoint-dependent",
        OwnMapping::EndpointIndependent => "endpoint-independent",
        OwnMapping::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::{PredictionArgs, PredictionKnob};

    fn args(port_prediction: PredictionKnob, kad_id: bool, timeout: u64) -> PredictionArgs {
        PredictionArgs {
            port_prediction,
            kad_id: kad_id.then(|| "00".repeat(16)),
            kad_contacts: Vec::new(),
            kad_bootstrap: Vec::new(),
            own_mapping_timeout: timeout,
        }
    }

    /// The two birthday operand sets that cannot learn an Own Mapping before
    /// the publish used to run silently; they are refused.
    #[test]
    fn a_birthday_run_that_cannot_learn_its_mapping_is_refused() {
        assert!(
            args(PredictionKnob::Birthday, false, 150)
                .validate()
                .is_err()
        );
        assert!(args(PredictionKnob::Birthday, true, 0).validate().is_err());
        assert!(args(PredictionKnob::Birthday, true, 150).validate().is_ok());
        assert!(args(PredictionKnob::Off, false, 0).validate().is_ok());
    }
}
