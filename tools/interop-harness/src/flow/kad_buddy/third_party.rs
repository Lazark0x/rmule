//! Flow M's **third party** as one unit: when it runs, what it
//! is handed, and how its legs are judged — the High-ID downloader
//! ([`callback`](super::callback)) and the ID-only walk fold-in
//! ([`callback_walk`](super::callback_walk)), or instead a stock aMule
//! requester ([`amule_requester`](super::amule_requester)), whose
//! row may be ID-only ([`id_only_row`]), or the buddy reask leg
//! ([`buddy_reask`](super::buddy_reask)). Flow M
//! hands this module its bench, taps and addresses and replaces its fixed tap
//! window with [`drive`].

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;

use crate::artifacts::RunLayout;
use crate::docker::Docker;
use crate::flow::bench::{KadMeshNames, KadResources};
use crate::flow::gate::wait_for_host_file;
use crate::flow::identity::{hex_lower, parse_ed2k_file_hash};
use crate::flow::kad_buddy::amule_requester::{AmuleRequesterLeg, AmuleRequesterPlan};
use crate::flow::kad_buddy::buddy_reask::{ReaskLeg, ReaskPlan};
use crate::flow::kad_buddy::callback::{CallbackLeg, DownloaderPlan, Judged, await_indexed};
use crate::flow::kad_buddy::callback_walk::{WalkLeg, WalkPlan, WalkTaps};
use crate::flow::kad_buddy::id_only_row::{self, IdOnlyRowPlan};
use crate::flow::logs::collect_kad_logs;

/// What flow M hands its third party.
pub(crate) struct ThirdParty<'a> {
    pub(crate) docker: &'a Docker,
    pub(crate) layout: &'a RunLayout,
    pub(crate) names: &'a KadMeshNames,
    pub(crate) rmule_tools_image: &'a str,
    pub(crate) capture_image: &'a str,
    /// The downloader's fake-public address; the walker takes the next one.
    pub(crate) downloader_v4: String,
    pub(crate) walker_v4: String,
    /// The placed storer's event log, whose `SourceIndexed` is the gate.
    pub(crate) storer_events: PathBuf,
    /// How long the gate may stay shut: flow M's tap window.
    pub(crate) window: Duration,
    /// The downloader's `--kad-contact` operands.
    pub(crate) seed: Vec<String>,
    /// aMule's Kad endpoint, `ip:port`, and its and the stimulus's addresses.
    pub(crate) amule_kad: String,
    pub(crate) amule_ip: String,
    pub(crate) rmule_ip: String,
    /// The walk's target, wire order: `~stimulusKadID`, aMule's own ID.
    pub(crate) walk_buddy_id: Option<[u8; 16]>,
    /// `Some` runs a stock aMule requester at `downloader_v4` in place of the
    /// rmule downloader; the walk does not run with it.
    pub(crate) amule_requester: Option<AmuleRequesterPlan<'a>>,
    /// `Some` publishes the requester's row ID-only from rmule;
    /// the publisher takes `walker_v4`.
    pub(crate) id_only_row: Option<IdOnlyRowPlan<'a>>,
    /// `Some` runs the buddy reask leg in place of either asker.
    pub(crate) buddy_reask: Option<ReaskPlan<'a>>,
}

/// Who asked for the relay.
enum Asker {
    /// The rmule downloader (`kad-core-buddy --callback-downloader`), started or not.
    Rmule(CallbackLeg),
    /// The stock aMule requester (`kad-core-buddy --amule-requester`); `None`
    /// when no row was indexed.
    Amule(Option<AmuleRequesterLeg>),
    /// The buddy reask leg (`kad-core-buddy --buddy-reask`); `None` when no
    /// row was indexed.
    Reask(Option<ReaskLeg>),
}

/// The legs that ran.
pub(crate) struct Legs {
    asker: Asker,
    walk: Option<WalkLeg>,
}

/// A tap flow M runs: its sidecar, its pcap inside it, its host directory.
pub(crate) type Tap<'a> = (&'a str, &'a str, &'a Path);

/// Wait for aMule's row, then run the downloader and (if asked) the walker.
///
/// # Errors
/// If a container cannot be started or the host cannot be polled.
pub(crate) fn drive(party: &ThirdParty<'_>, resources: &mut KadResources<'_>) -> Result<Legs> {
    let id_only = party
        .id_only_row
        .as_ref()
        .map(|plan| {
            id_only_row::publish(
                party.docker,
                party.layout,
                party.names,
                resources,
                plan,
                &party.storer_events,
                party.window,
            )
        })
        .transpose()?;
    // Under the `--findsource-transfer` leg the requester must read both rows — the
    // ID-only one newest — or it could adopt aMule's own endpoint row.
    let indexed = if party
        .id_only_row
        .as_ref()
        .is_some_and(|plan| plan.after_firewalled_row)
    {
        wait_for_host_file(&party.storer_events, "rows_for_key: 2", party.window)?
    } else {
        await_indexed(&party.storer_events, party.window)?
    };
    if let Some(plan) = &party.buddy_reask {
        let leg = indexed
            .then(|| ReaskLeg::run(party.docker, party.layout, party.names, resources, plan))
            .transpose()?;
        return Ok(Legs {
            asker: Asker::Reask(leg),
            walk: None,
        });
    }
    if let Some(plan) = &party.amule_requester {
        let leg = indexed
            .then(|| {
                AmuleRequesterLeg::run(
                    party.docker,
                    party.names,
                    resources,
                    plan,
                    &party.downloader_v4,
                    id_only,
                )
            })
            .transpose()?;
        return Ok(Legs {
            asker: Asker::Amule(leg),
            walk: None,
        });
    }
    if !indexed {
        return Ok(Legs {
            asker: Asker::Rmule(CallbackLeg::never_started(party.layout, party.names)),
            walk: None,
        });
    }
    let link = std::fs::read_to_string(party.layout.synthetic_ed2k_file())?;
    let callback = CallbackLeg::start(
        party.docker,
        party.layout,
        party.names,
        resources,
        DownloaderPlan {
            image: party.rmule_tools_image,
            capture_image: party.capture_image,
            address_v4: party.downloader_v4.clone(),
            seed: party.seed.clone(),
            link: link.trim().to_owned(),
        },
    )?;
    callback.run()?;
    let walk = party
        .walk_buddy_id
        .map(|buddy_id| -> Result<WalkLeg> {
            WalkLeg::run(
                party.docker,
                party.layout,
                party.names,
                resources,
                WalkPlan {
                    image: party.rmule_tools_image,
                    address_v4: party.walker_v4.clone(),
                    amule_kad: party.amule_kad.clone(),
                    buddy_id,
                    file_hash_hex: hex_lower(&parse_ed2k_file_hash(link.trim())?),
                },
            )
        })
        .transpose()?;
    Ok(Legs {
        asker: Asker::Rmule(callback),
        walk,
    })
}

impl Legs {
    /// Collect the legs' logs and write both verdicts; the first failing leg
    /// is the error, after both files exist.
    ///
    /// # Errors
    /// If a tap or log cannot be read, or a leg's claims do not hold.
    pub(crate) fn judge(
        &self,
        party: &ThirdParty<'_>,
        buddy: Tap<'_>,
        amule: Tap<'_>,
    ) -> Result<()> {
        let judged = Judged {
            docker: party.docker,
            layout: party.layout,
            buddy_tap: buddy.0,
            buddy_pcap: buddy.1,
            buddy_host_dir: buddy.2,
            amule_tap: amule.0,
            amule_pcap: amule.1,
            amule_host_dir: amule.2,
            amule_ip: &party.amule_ip,
            rmule_ip: &party.rmule_ip,
        };
        let callback = match &self.asker {
            Asker::Rmule(callback) => {
                if callback.started() {
                    collect_kad_logs(
                        party.docker,
                        party.layout,
                        "downloader",
                        callback.container(),
                    )?;
                }
                callback.judge(&judged)
            }
            Asker::Amule(Some(requester)) => {
                if party.id_only_row.is_some() {
                    collect_kad_logs(
                        party.docker,
                        party.layout,
                        "publisher",
                        &party.names.publisher,
                    )?;
                }
                requester.judge(&judged)
            }
            Asker::Reask(Some(leg)) => leg.judge(&judged),
            Asker::Reask(None) => Err(anyhow::anyhow!(
                "kad-buddy-reask: the placed storer indexed no source, so no body ran"
            )),
            Asker::Amule(None) => Err(anyhow::anyhow!(
                "kad-amule-requester: the placed storer indexed no source, so no requester ran"
            )),
        };
        let walked = self
            .walk
            .as_ref()
            .map(|walk| {
                collect_kad_logs(party.docker, party.layout, "walker", &party.names.publisher)?;
                walk.judge(&WalkTaps {
                    docker: party.docker,
                    layout: party.layout,
                    buddy,
                    amule,
                    amule_ip: &party.amule_ip,
                    rmule_ip: &party.rmule_ip,
                })
            })
            .transpose();
        callback?;
        walked.map(|_| ())
    }
}
