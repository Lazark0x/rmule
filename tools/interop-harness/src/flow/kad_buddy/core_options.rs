//! Flow M's options and the pinned Kad IDs its two sides take: what a
//! `kad-core-buddy` run was asked to do, and the one derived fact (whether
//! the counterparty's Kad UDP port is really dropped) both the container env
//! and the verdict read.

use crate::flow::mesh::KadCaptureOptions;
use crate::rmule::RmuleServeContainer;

/// The firewalled aMule's pinned Kad ID for flow M; rmule takes the bitwise
/// inverse so it sits at distance 0 from the FindBuddy target (`~ownID`) and
/// clears `SEARCHTOLERANCE` outright.
///
/// **Asymmetric per 32-bit word, on purpose**. The old
/// pin was `0x33` repeated, so the buddy relationship ID `~ownID` came out
/// `0xCC` repeated — a value that reads the same whichever way its words are
/// ordered. `TAG_BUDDYHASH` is the one tag whose byte order the reference
/// families disagree on (aMule's `CUInt128::ToByteArray`, big-endian; eMule's
/// and eMuleAI's `GetData()`, word-ordered), and a palindromic ID cannot tell
/// the two apart. Run `1790095682`'s `0x44` proved every other field and left
/// exactly that one open; these bytes are what closes it.
pub(crate) const KAD_CORE_BUDDY_AMULE_KAD_ID: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
];
/// The bitwise inverse of [`KAD_CORE_BUDDY_AMULE_KAD_ID`]: rmule IS the
/// FindBuddy target. Complement commutes with any byte permutation, so this
/// holds in whichever order the two sides write their 128-bit IDs.
pub(crate) const KAD_CORE_BUDDY_RMULE_KAD_ID: [u8; 16] = [
    0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
];

/// Options for [`run_kad_core_buddy`](crate::flow::kad_buddy::core::run_kad_core_buddy) (flow M).
pub struct KadCoreBuddyOptions<'a> {
    /// The shared Kad bench options.
    pub base: KadCaptureOptions<'a>,
    /// The rust image the stimulus container compiles and runs `rmule-tools` in.
    pub rmule_client_container: &'a RmuleServeContainer,
    /// How long the tap runs once both sides are up. Must outlast aMule's
    /// ~6–7 min buddy convergence with room for the TCP dial and a ping.
    pub window_secs: u64,
    /// Open stock aMule nodes that serve as the firewalled node's **UDP
    /// firewall helpers** (`OP_FWCHECKUDPREQ` over peer TCP, `0x62` back).
    ///
    /// They are never in its seed: `QueryNextClient` refuses a candidate its
    /// routing zone already holds, so each helper is seeded with rmule and
    /// reaches the aMule only as a row of rmule's answer to its helper lookup
    /// (`core_swarm`). That needs
    /// [`mesh_members`](Self::mesh_members) `>= 1` — rmule and a member fill
    /// the one-`/24` routing bin's two slots first — and the members, not the
    /// helpers, are the extern-port reporters (`CPrefs::SetExternKadPort`,
    /// `Prefs.cpp:291-316` kno `ab483654`, stops at the second agreeing report).
    ///
    /// Helpers force [`block_udp`](Self::block_udp): with helpers reachable the
    /// UDP firewall test runs for real, and an open UDP port would come back
    /// verified-open — which withdraws the buddy recruitment entirely.
    pub helper_count: usize,
    /// Also drop the aMule's Kad **UDP** port. With no helpers the UDP verdict
    /// comes from the six-minute timeout and a dropped port would swallow the
    /// `0x51`; with helpers it is required, and the two-helper test is expected
    /// to settle the verdict before the timeout (not yet measured).
    pub block_udp: bool,
    /// Pass `--kad-assume-open` to the stimulus. On by default; `false` records
    /// what rmule's live (unconverged) self-check verdicts do to the recruit gate.
    pub assume_open: bool,
    /// Give the firewalled aMule the staged synthetic file to **share**, so its
    /// `CSharedFileList::Publish` has something to publish a source for.
    ///
    /// `CSharedFileList::Publish` (`SharedFileList.cpp:1729`) runs the
    /// `STOREFILE` branch only while Kad is connected, `GetCount()` is
    /// non-zero, `CKademlia::GetPublish()` holds and — for a firewalled node —
    /// `GetBuddyStatus() == Connected`; run `1790084715` cleared all four and
    /// still drew no `0x44`, because a **fifth, silent** gate sits one level
    /// deeper. `CSearch::StorePacket` (`Search.cpp:456`) returns with no debug
    /// line when `fromDistance.Get32BitChunk(0) > SEARCHTOLERANCE`
    /// (`0x01000000`) and the candidate is not a LAN IP, so the publish never
    /// leaves unless *some* contact sits within that tolerance of the **file's
    /// own Kad location**.
    ///
    /// Which is why this knob now also **places a member there**: it obliges
    /// [`mesh_members`](Self::mesh_members) `>= 1` and pins the last member's
    /// Kad ID to `kad_seed::storer_kad_id_for_file_hash(<synthetic file hash>)`
    /// — distance 0, the same placement flow F's storer uses. rmule keeps the
    /// buddy-target placement (`~aMuleKadID`), because the buddy link is
    /// peer-TCP onto rmule's serve listener and a `join-node` member binds
    /// none; the two targets are different points in the keyspace and need two
    /// different nodes.
    pub publish_source: bool,
    /// Placed `rmule-tools kad join-node` members added to the swarm as extra
    /// **routing contacts** for the counterparty.
    ///
    /// Not decoration, and not helpers: what they fix is the two-node swarm's
    /// own arithmetic. `CKademlia::Process` pings a *random* contact every 15 s
    /// while `CPrefs::FindExternKadPort()` holds, so with rmule as the only
    /// contact every ping lands on rmule — 4/min against the 2/min
    /// `KADEMLIA2_PING` budget **both** clients enforce identically
    /// (aMule `PacketTracking.cpp`, rmule `FloodTable`). Past 5× that budget
    /// each side bans the IP, and a banned IP's inbound connection is refused,
    /// which closes the very peer-TCP surface the buddy link needs. The first
    /// run of this leg measured **53 pings** and exactly that outcome: the dial
    /// landed, rmule FIN'd 1.4 ms later, and `GetBuddyStatus()` never reached
    /// `Connected`, so no source was ever published.
    ///
    /// Two members end it twice over: the pings spread three ways (~1.3/min
    /// each), and `CPrefs::SetExternKadPort` stops the probe outright once two
    /// distinct reporters agree on a port. They cannot disturb the verdicts
    /// this flow depends on — a `join-node` binds no peer-TCP listener, so it
    /// can never answer the `OP_FWCHECKUDPREQ` that would complete aMule's UDP
    /// firewall check and withdraw the buddy recruitment.
    ///
    /// Their Kad IDs are placed far from `~aMuleKadID`, so the FINDBUDDY walk
    /// still converges on rmule at distance 0 — except the **last** one under
    /// [`publish_source`](Self::publish_source), which is pinned to the
    /// synthetic file's own Kad location so the publish clears
    /// `SEARCHTOLERANCE`. A random file key beating rmule's distance-0 on the
    /// buddy target is not possible, so that pin cannot move the walk.
    pub mesh_members: usize,
    /// The image the placed members run `rmule-tools` from.
    pub rmule_tools_image: &'a str,
    /// Arm Kad-UDP crypt on both sides of the Core-pumped exchange
    /// `--peer-crypt requested` on the stimulus (the Core
    /// leg — ADR-0046's one setting arms Kad-UDP crypt and verify keys
    /// together) and `AMULE_KAD_CRYPT=1` on the firewalled aMule. Off by
    /// default, matching every other Kad flow's plain-`0xE4` evidence.
    pub kad_crypt: bool,
    /// `--peer-crypt-flip <secs>:<policy>` for the stimulus, one per entry:
    /// its obfuscation policy changes mid-run, live (ADR-0046), and the
    /// verdict lists each change the stimulus marked. With
    /// [`kad_crypt`](Self::kad_crypt) the run starts `requested` and the
    /// firewalled aMule's Kad crypt is up throughout, so a flip off and back
    /// is the leg that shows the running node re-armed both ways.
    pub peer_crypt_flip: &'a [String],
    /// Add the **third party**: a High-ID rmule downloader handed
    /// only the ed2k link, whose download reaches the firewalled aMule through
    /// ADR-0061 route 4 — the `0x52` to the buddy, the relayed `0x99`, aMule's
    /// dial-back. Requires [`publish_source`](Self::publish_source): the row
    /// the download finds is the one that publish stores. The fixed tap window
    /// becomes a gate on the placed storer's `SourceIndexed`, bounded by it.
    pub callback_downloader: bool,
    /// Add the ID-only fold-in: once the downloader's
    /// window has run, a `kad join-node` walker runs one **Callback Walk**
    /// toward `~stimulusKadID` — aMule's own ID — so its `0x52` lands on the
    /// firewalled aMule, which relays `OP_CALLBACK` over its held link.
    /// Requires [`callback_downloader`](Self::callback_downloader) (its gate
    /// is the proof the link is held).
    pub callback_walk: bool,
    /// Run the third party as a **stock aMule requester** instead of the rmule
    /// downloader: aMule's own `0x52` to the rmule buddy, and the
    /// buddy's relay of it. Requires [`publish_source`](Self::publish_source);
    /// excludes [`callback_downloader`](Self::callback_downloader).
    pub amule_requester: bool,
    /// Make the requester's row **ID-only**: an rmule publisher
    /// writes it with `TAG_BUDDYHASH` and no buddy endpoint, the firewalled
    /// aMule shares nothing, and the requester walks aMule's `FINDSOURCE`
    /// road (`kad_buddy::id_only_row`). Requires
    /// [`amule_requester`](Self::amule_requester).
    pub omit_buddy_endpoint: bool,
    /// Arm the requester's crypt layer: `AMULE_KAD_CRYPT=1` on
    /// the requester alone, so its `0x52` leaves keyed on the buddy's Kad ID
    /// while every other body keeps flow M's plaintext posture. Requires
    /// [`amule_requester`](Self::amule_requester).
    pub requester_kad_crypt: bool,
    /// Carry the `FINDSOURCE` road through to a transfer: the
    /// firewalled aMule shares the file under a pinned user hash
    /// (`id_only_row::FIREWALLED_USER_HASH`), and the ID-only row goes out under the same hash once aMule's own row
    /// is indexed — the storer serves newest first, and aMule's requester
    /// keeps the first row per user hash (`DownloadQueue.cpp:702-724`), so it
    /// takes the `FINDSOURCE` road to a body that shares the file. Requires
    /// [`omit_buddy_endpoint`](Self::omit_buddy_endpoint).
    pub findsource_transfer: bool,
}

impl KadCoreBuddyOptions<'_> {
    /// Whether the counterparty's Kad **UDP** port actually gets dropped. Helpers
    /// force it (see [`helper_count`](Self::helper_count)), so the requested flag
    /// is not what ran — both the container env and the verdict read this.
    pub(crate) fn block_udp_effective(&self) -> bool {
        self.block_udp || self.helper_count > 0
    }

    /// Whether a third party asks for a relay — either asker.
    pub(crate) fn third_party(&self) -> bool {
        self.callback_downloader || self.amule_requester
    }
}
