//! The **Kad Mesh with a Seeded Bootstrap** the buddy rendezvous is staged on,
//! built once here so a second flow can reuse it.
//!
//! # Why a mesh at all
//!
//! ADR-0091's second Rendezvous coordinator is a buddy relation that the
//! relay admits *only* while it is **held** (ADR-0091 correction 7), and
//! rmule's firewalled-node front wires that
//! relation to a live `0x51`/`0x5A` FINDBUDDY recruit run over Kad: the
//! firewalled node walks toward `~ourKadID` and asks the single closest
//! **responded** contact to be its buddy. So the flow cannot fabricate the
//! relation — it has to stand up a keyspace for the walk to converge in.
//!
//! # How the seed makes the walk converge
//!
//! The mesh's identities are chosen, not drawn: the buddy's Kad ID is the
//! target's **inverted**, which is exactly the walk's target, so the buddy sits
//! at distance zero from `~targetID` and no other member can be closer. The
//! two routing-only members are placed far from it on purpose — `0x22…`/`0x88…`
//! against the buddy's `0xEE…` — so the walk has real alternatives and still
//! picks the buddy, which is what makes "the recruit landed on the intended
//! buddy" a measurement rather than a tautology of a one-node table.
//!
//! The transfer rows add a third member at the file's own Kad key: a storer
//! refuses a publish from a non-LAN sender outside `SEARCHTOLERANCE` of its
//! ID, the same gate flow M had to place a member for, so the
//! buddy row needs a node at distance zero to land on.
//!
//! The seed itself is the ADR-0065 v1/v2-merge: each contact is handed to the
//! target as an **already-placed** routing contact (`MergeContacts`), not as a
//! bootstrap dial candidate. A walk needs contacts *in the keyspace*, and a
//! bootstrap round trip would only re-earn what the harness already knows —
//! while costing the 15 s/2 s dial cadence before the first walk could run.
//!
//! Every member takes its own fake-public `/24` address (one Kad client per
//! IP — aMule's `MAX_CONTACTS_IP 1`).

use std::path::Path;
use std::time::Duration;

use anyhow::Result;

use crate::flow::bench::Bench;
use crate::flow::nat::natt::BODY_CLIENT_UDP_PORT;
use crate::flow::nat::natt::bench::NattOptions;

/// The target's Kad ID. Fixed and non-secret so a verdict can name the
/// keyspace position the walk started from.
pub(super) const TARGET_KAD_ID: [u8; 16] = [0x11; 16];

/// The buddy's Kad ID — the target's inverted, which is the FINDBUDDY walk's
/// target (`~ourKadID`). At distance zero from it, so the walk converges on
/// the buddy whatever else is in the table.
pub(super) const BUDDY_KAD_ID: [u8; 16] = [0xEE; 16];

/// The routing-only members. Chosen far from `0xEE…` so they are genuine
/// alternatives the walk rejects rather than decoration.
pub(super) const MESH_KAD_IDS: [[u8; 16]; 2] = [[0x22; 16], [0x88; 16]];

/// The transfer requester's Kad ID — it walks for sources, so it
/// needs a place in the keyspace; far from the buddy's `0xEE…` so it never
/// competes for the target's recruit.
pub(super) const REQUESTER_KAD_ID: [u8; 16] = [0x44; 16];

/// One routing-only member, as the flow stands it up and as the target's seed
/// names it.
pub(super) struct MeshNode {
    /// The container name.
    pub(super) container: String,
    /// Its fake-public address.
    pub(super) address_v4: String,
    /// Its Kad ID, lower-case hex.
    pub(super) kad_id: String,
}

impl MeshNode {
    /// The `--kad-contact` operand the target is seeded with.
    pub(super) fn seed_operand(&self) -> String {
        seed_operand(&self.kad_id, &self.address_v4)
    }
}

/// The `<kad-id-hex>@<ipv4>:<udp-port>` operand form the driver parses.
pub(super) fn seed_operand(kad_id: &str, address_v4: &str) -> String {
    crate::flow::kad_member::seed_operand(kad_id, address_v4, BODY_CLIENT_UDP_PORT)
}

/// Sixteen bytes as lower-case hex — the form every Kad-ID operand takes.
pub(super) fn hex(id: &[u8; 16]) -> String {
    crate::flow::kad_member::hex(id)
}

/// Where the mesh goes and how long it lives — the fields that would
/// otherwise make [`start`] a seven-operand call nobody can read.
pub(super) struct MeshPlan<'a> {
    /// The fake-public WAN network.
    pub(super) wan: &'a str,
    /// The run suffix every container name carries.
    pub(super) suffix: &'a str,
    /// One fake-public address per member (one Kad client per IP).
    pub(super) addresses: &'a [String],
    /// Each member's Kad ID, paired with `addresses` by index.
    pub(super) kad_ids: &'a [[u8; 16]],
    /// The buddy each member bootstraps to — the one member already up.
    pub(super) buddy_v4: &'a str,
    /// Where each member's capture and log land.
    pub(super) leg_dir: &'a Path,
    /// How long a member runs before finalizing its capture. It must outlive
    /// the whole flow, buddy wait included.
    pub(super) run_secs: u64,
}

/// Start the mesh's routing-only members on the fake-public WAN.
///
/// Each is a standalone `rmule-tools kad join-node` — the **Kad Stimulus
/// Node** of ADR-0043 — bootstrapped to the buddy, which is the one member
/// that is up before them. They are not drivers: nothing reads a row from
/// them, and their whole job is to be contacts the walk can reject.
///
/// # Errors
/// If a member cannot be started.
pub(super) fn start(
    bench: &mut Bench,
    options: &NattOptions<'_>,
    plan: &MeshPlan<'_>,
) -> Result<Vec<MeshNode>> {
    let MeshPlan {
        wan,
        suffix,
        addresses,
        kad_ids,
        buddy_v4,
        leg_dir,
        run_secs,
    } = plan;
    let mut nodes = Vec::new();
    for (index, (address, kad_id)) in addresses.iter().zip(kad_ids.iter()).enumerate() {
        let kad_id = hex(kad_id);
        let container = format!("rmule-interop-nattmesh{index}-{suffix}");
        let dir = leg_dir.join(format!("mesh-{index}"));
        std::fs::create_dir_all(&dir)?;
        let bootstrap = format!("{buddy_v4}:{BODY_CLIENT_UDP_PORT}");
        bench.start_extra(
            &container,
            crate::flow::kad_member::PlacedMember {
                image: options.rmule_tools_image,
                container: &container,
                network: wan,
                address_v4: address,
                udp_port: BODY_CLIENT_UDP_PORT,
                tcp_port: crate::flow::nat::natt::BODY_PEER_TCP_PORT,
                kad_id: &kad_id,
                bootstrap: Some(&bootstrap),
                host_dir: &dir,
                run_secs: *run_secs,
            }
            .container_spec(),
            "run a Kad mesh member",
        )?;
        nodes.push(MeshNode {
            container,
            address_v4: address.clone(),
            kad_id,
        });
    }
    Ok(nodes)
}

/// Lift each member's own output beside its capture, before the bench tears
/// the containers down.
///
/// # Errors
/// If a member's log cannot be written.
pub(super) fn collect(bench: &Bench, nodes: &[MeshNode], leg_dir: &Path) -> Result<()> {
    for (index, node) in nodes.iter().enumerate() {
        let output = bench
            .docker
            .logs(node.container.clone())
            .to_command()
            .output()?;
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        std::fs::write(leg_dir.join(format!("mesh-{index}")).join("node.log"), text)?;
    }
    Ok(())
}

/// How long a member is given to bind before the target is seeded with it. The
/// seed is a placed contact rather than a dial, so the only thing that must be
/// true is that the socket is up when the walk queries it.
pub(super) const MESH_SETTLE: Duration = Duration::from_secs(5);
