//! `natt-udp-selfcheck-amule`'s **Low-ID Buddy Recipe**: the sequence that satisfies
//! stock aMule 2.3.3's type-6 publish gate as aMule's own source names it.
//!
//! aMule publishes a firewalled source only while it holds a buddy
//! (`SharedFileList.cpp:773`, `KnownFile.cpp:1308-1318`), searches for one
//! only while its TCP *and* UDP verdicts read firewalled
//! (`ClientList.cpp:686-687`), and releases a buddy whose hello did not read
//! Low-ID once they do not (`:706-712`). So the flow:
//!
//! 1. **Holds the helpers back at the gateway.** aMule's UDP tester asks a
//!    helper only once it knows its extern Kad port (`QueryNextClient` returns
//!    while `FindExternKadPort`), and it learns that port only from the
//!    `KADEMLIA2_PONG`s to its own `KADEMLIA2_PING`s
//!    (`KademliaUDPListener.cpp:1548-1557`). The gateway drops aMule's
//!    plaintext `0x60` on its way out, so no `0xA7` leaves and the tester times
//!    out firewalled after six minutes (`UDPFirewallTester.cpp:62`). The
//!    helpers run from the start and are never touched.
//! 2. **Gives the root a real Low ID.** The rmule root logs in to an `ed2ksrv`
//!    on the WAN whose High-ID back-connect is dropped in the server's own
//!    netns, so the id it assigns — the one the root's `OP_HELLOANSWER` stamps
//!    — is Low, and aMule's `HasLowID()` keeps it (`BaseClient.cpp:678`).
//! 3. **Waits for the recruit.** Both verdicts firewalled, aMule's
//!    `BuddySearch` finds the root at `~KadID` and dials it; the root holds the
//!    link.
//! 4. **Releases.** The drop goes; aMule's next ping learns the port, a
//!    helper's `0x62` flips the verdict open, and the Low-ID buddy is kept.
//! 5. **Shares.** The Synthetic File moves into aMule's shared directory and
//!    `amulecmd Reload shared` hashes it: a new file's `PublishSrc` fires on a
//!    buddy it has never published with, and with UDP open and verified
//!    `StorePacket` writes type 6 (`Search.cpp:595-605`).

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};

use super::evidence::wait_for_log_line;
use super::{AMULE_EC_PASSWORD, HASH_TARGET, UDP_OPEN_LINE, parse_hash};
use crate::docker::RunContainer;
use crate::flow::bench::{Bench, run_checked};
use crate::flow::gate::wait_for_container_log;
use crate::flow::nat::claims::{Claim, Evidence};
use crate::flow::nat::natt::BODY_PEER_TCP_PORT;
use crate::flow::nat::natt::bench::NattOptions;
use crate::flow::nat::natt::punch::start_server;

/// The `ed2ksrv`'s WAN host index: gateway A's slot, which this topology
/// leaves empty.
pub(super) const HOST_SERVER: usize = 1;

/// aMule's six-minute UDP timeout runs from its Kad start; this is that plus
/// the ticks around it.
const TIMEOUT_BUDGET_SECS: u64 = 480;
/// From the timeout to a held link: the next buddy tick, one FINDBUDDY
/// lookup, one TCP handshake.
const RECRUIT_BUDGET_SECS: u64 = 300;
/// From the release to the open verdict: a ping every 15 s until two
/// contacts agree on the port (`Prefs.cpp:280-307`), then one `0xA7`.
const OPEN_BUDGET_SECS: u64 = 240;
/// From the reload to the `StoreFile` search: the hash, then the 2 s source
/// publish loop.
const PUBLISH_BUDGET_SECS: u64 = 300;
/// Held after the `StoreFile` line so the `0x44` and its answer land.
const PUBLISH_LINGER_SECS: u64 = 30;

/// How long the WAN bodies must outlive the recipe's start.
pub(super) const RECIPE_SECS: u64 = TIMEOUT_BUDGET_SECS
    + RECRUIT_BUDGET_SECS
    + OPEN_BUDGET_SECS
    + PUBLISH_BUDGET_SECS
    + PUBLISH_LINGER_SECS;

/// The nft table the hold lives in on aMule's gateway.
const HOLD_TABLE: &str = "rmule_udp_verdict_hold";
/// The nft table the refused High-ID probe lives in, in the server's netns.
const PROBE_TABLE: &str = "rmule_high_id_probe_refused";

/// aMule's lines the recipe reads, each written by the step it names.
const TIMEOUT_LINE: &str = "Timeout: Setting UDP status to firewalled";
const BUDDY_SEARCH_LINE: &str = "Starting BuddySearch";
const STORE_FILE_LINE: &str = "Search request type: StoreFile";
/// The root's own line when the recruit's inbound connection is held.
const BUDDY_ATTACHED_LINE: &str = "buddy link attached";

/// What the recipe's run did, read back for its claims.
#[derive(Default)]
pub(super) struct Recipe {
    /// The id the `ed2ksrv` assigned the root, off its `server.connected`
    /// line.
    pub(super) root_client_id: Option<u32>,
    /// High-ID back-connect packets the server's netns dropped.
    pub(super) probes_refused: u64,
    /// aMule's six-minute timeout line.
    timed_out: Option<String>,
    /// aMule `0x60`s the gateway held.
    pings_held: u64,
    /// The root's `buddy link attached` line.
    buddy_attached: Option<String>,
    /// aMule's open verdict after the release.
    opened: Option<String>,
    /// `amulecmd Reload shared`'s answer.
    reload: String,
    /// aMule's first `StoreFile` line after the reload.
    store_file: Option<String>,
}

/// Stand the `ed2ksrv` up and refuse its High-ID back-connect to the root's
/// listen port, so the id it assigns the root is Low. The drop is in the
/// server's own netns: the root's listener stays open to everything else,
/// aMule's buddy dial included.
pub(super) fn start_low_id_server(
    bench: &mut Bench,
    options: &NattOptions<'_>,
    suffix: &str,
    wan: &str,
    (server_v4, root_v4): (&str, &str),
    leg_dir: &Path,
) -> Result<String> {
    let timeout = Duration::from_secs(options.timeout_secs);
    let server = start_server(bench, options, suffix, wan, server_v4, leg_dir, timeout)?;
    server_nft(
        bench,
        options,
        &server,
        &format!(
            "add table ip {PROBE_TABLE} ; add chain ip {PROBE_TABLE} out {{ type filter hook \
             output priority 0 ; }} ; add rule ip {PROBE_TABLE} out ip daddr {root_v4} tcp \
             dport {BODY_PEER_TCP_PORT} counter drop"
        ),
        "refuse the server's High-ID probe",
    )?;
    Ok(server)
}

/// The id the server assigned the root, off the root's own `server.connected`
/// line; `None` when no login landed in the budget.
pub(super) fn await_root_login(bench: &Bench, root: &str, timeout: Duration) -> Option<u32> {
    let logs = wait_for_container_log(&bench.docker, root, "server.connected", timeout).ok()?;
    logs.lines()
        .find(|line| line.contains("server.connected"))?
        .split("client_id=")
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Drop aMule's plaintext `KADEMLIA2_PING` on the gateway's forward path, so
/// its UDP tester never learns the extern port it asks helpers with.
pub(super) fn hold(bench: &Bench, gateway: &str) -> Result<()> {
    gateway_nft(
        bench,
        gateway,
        &format!(
            "add table inet {HOLD_TABLE} ; add chain inet {HOLD_TABLE} hold {{ type filter hook \
             forward priority -10 ; }} ; add rule inet {HOLD_TABLE} hold iifname \"eth1\" meta \
             l4proto udp @th,64,16 0xe460 counter drop"
        ),
        "hold aMule's extern-port pings at its gateway",
    )
    .map(drop)
}

/// Run steps 3–5 against a ready aMule, waiting on each step's own line, and
/// hand back its open verdict line; a step that never lands ends the waiting,
/// never the run — the release and the share still happen, so the claims read
/// how far the chain got.
pub(super) fn run(
    bench: &Bench,
    driver: &str,
    gateway: &str,
    root: &str,
    (staged, incoming): (&Path, &Path),
    recipe: &mut Recipe,
) -> Result<Option<String>> {
    let budget = Duration::from_secs;
    recipe.timed_out = wait_for_log_line(
        bench,
        driver,
        &[TIMEOUT_LINE, UDP_OPEN_LINE],
        budget(TIMEOUT_BUDGET_SECS),
    );
    println!(
        "natt amule low-id recipe: verdict held -> {:?}",
        recipe.timed_out
    );
    if recipe.timed_out.is_some() {
        recipe.buddy_attached = wait_for_container_log(
            &bench.docker,
            root,
            BUDDY_ATTACHED_LINE,
            budget(RECRUIT_BUDGET_SECS),
        )
        .ok()
        .and_then(|logs| {
            logs.lines()
                .find(|line| line.contains(BUDDY_ATTACHED_LINE))
                .map(|line| line.trim().to_owned())
        });
        println!(
            "natt amule low-id recipe: buddy -> {:?}",
            recipe.buddy_attached
        );
    }

    let listing = gateway_nft(
        bench,
        gateway,
        &format!("list table inet {HOLD_TABLE}"),
        "read the hold's counter",
    )?;
    recipe.pings_held = counter_packets(&listing);
    gateway_nft(
        bench,
        gateway,
        &format!("delete table inet {HOLD_TABLE}"),
        "release aMule's extern-port pings",
    )?;
    println!(
        "natt amule low-id recipe: released after holding {} pings",
        recipe.pings_held
    );
    if recipe.buddy_attached.is_some() {
        recipe.opened =
            wait_for_log_line(bench, driver, &[UDP_OPEN_LINE], budget(OPEN_BUDGET_SECS));
        println!("natt amule low-id recipe: verdict -> {:?}", recipe.opened);
    }

    let name = staged.file_name().context("the staged file has a name")?;
    fs::rename(staged, incoming.join(name))
        .with_context(|| format!("move {} into aMule's share", staged.display()))?;
    recipe.reload = run_checked(
        bench.docker.exec(
            driver.to_owned(),
            [
                OsString::from("amulecmd"),
                OsString::from("-P"),
                OsString::from(AMULE_EC_PASSWORD),
                OsString::from("-c"),
                OsString::from("Reload shared"),
            ],
        ),
        "reload aMule's shared files",
    )
    .unwrap_or_else(|error| format!("amulecmd Reload shared failed: {error:#}"));
    recipe.store_file = wait_for_log_line(
        bench,
        driver,
        &[STORE_FILE_LINE],
        budget(PUBLISH_BUDGET_SECS),
    );
    println!(
        "natt amule low-id recipe: publish -> {:?}",
        recipe.store_file
    );
    if recipe.store_file.is_some() {
        std::thread::sleep(budget(PUBLISH_LINGER_SECS));
    }
    Ok(recipe.opened.clone())
}

/// High-ID back-connect packets the server's netns dropped over the run.
pub(super) fn probes_refused(bench: &Bench, options: &NattOptions<'_>, server: &str) -> u64 {
    server_nft(
        bench,
        options,
        server,
        &format!("list table ip {PROBE_TABLE}"),
        "read the refused probes",
    )
    .map_or(0, |listing| counter_packets(&listing))
}

/// [`HASH_TARGET`] as aMule's own `OP_HELLO` carries it: `CPreferences::
/// CPreferences()` stamps two identity bytes unconditionally after loading
/// whatever `preferences.dat` pins (`Preferences.cpp:1081-1082`, kno
/// `ab483654`) — byte 5 -> `0x0E`, byte 14 -> `0x6F`, "mark hash as an
/// eMule-type hash" — so the hello this root reads never carries the pin
/// verbatim.
fn expected_hello_hash() -> String {
    let mut bytes = parse_hash(HASH_TARGET).expect("HASH_TARGET is a 32-hex-char hash");
    bytes[5] = 0x0e;
    bytes[14] = 0x6f;
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

/// The recipe's own claims, from its steps and aMule's logfile.
pub(super) fn claims(recipe: &Recipe, log: &str) -> Vec<Claim> {
    let buddy_searches = log
        .lines()
        .filter(|line| line.contains(BUDDY_SEARCH_LINE))
        .count();
    let low_id = recipe
        .root_client_id
        .is_some_and(|id| id != 0 && id < 0x0100_0000);
    let hello_hash = recipe.buddy_attached.as_deref().and_then(|line| {
        line.split("hello_user_hash=")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
    });
    let expected = expected_hello_hash();
    vec![
        Claim::about(
            "the-root-logged-in-with-a-server-assigned-low-id",
            low_id,
            // Read off the rmule root's own `server.connected` line; no
            // capture of the server's id assignment backs it.
            Evidence::RmuleOnly,
            format!(
                "the ed2ksrv assigned the root client_id {:?}; its High-ID back-connect \
                 dropped {} times in its own netns",
                recipe.root_client_id, recipe.probes_refused
            ),
        ),
        Claim::about(
            "the-held-amule-udp-verdict-timed-out-firewalled",
            recipe
                .timed_out
                .as_deref()
                .is_some_and(|line| line.contains(TIMEOUT_LINE)),
            Evidence::Captured,
            format!(
                "aMule's line: {:?}; its 0x60s the gateway held: {}",
                recipe.timed_out, recipe.pings_held
            ),
        ),
        Claim::about(
            "amule-recruited-the-low-id-root-as-its-buddy",
            buddy_searches > 0 && recipe.buddy_attached.is_some(),
            Evidence::Captured,
            format!(
                "aMule `{BUDDY_SEARCH_LINE}` x{buddy_searches}; the root: {:?}",
                recipe.buddy_attached
            ),
        ),
        Claim::about(
            "amules-hello-carried-the-pinned-user-hash",
            hello_hash.is_some_and(|hex| hex.eq_ignore_ascii_case(&expected)),
            Evidence::Captured,
            format!(
                "the root's buddy-attach line carried hello_user_hash={hello_hash:?}; expected \
                 {expected} (`AMULE_USER_HASH` {HASH_TARGET} pinned via `preferences.dat`, \
                 stamped eMule-type by aMule itself: byte 5 -> 0x0E, byte 14 -> 0x6F, \
                 `Preferences.cpp:1081-1082`)"
            ),
        ),
    ]
}

/// On this recipe the type-6 row is what the run exists to capture, so a
/// publish claim that did not hold is settled on the recipe's own steps.
///
/// It stays `absent` — the row fails — when a publish arrived at all
/// (`publish_seen`: a wrong-type `0x44` is the regression, not a bench gap) or
/// when every step landed and still no `0x44` reached the storer. Only a
/// chain that broke before the publish could be asked for is `blocked`, on
/// the first step that did not land, quoting aMule's own lines.
pub(super) fn settle_publish(claims: &mut [Claim], recipe: &Recipe, log: &str, publish_seen: bool) {
    let Some(claim) = claims
        .iter_mut()
        .find(|claim| claim.name == super::PUBLISH_CLAIM && claim.outcome != "held")
    else {
        return;
    };
    let count = |needle: &str| log.lines().filter(|line| line.contains(needle)).count();
    let every_step_landed = recipe.timed_out.is_some()
        && recipe.buddy_attached.is_some()
        && recipe.opened.is_some()
        && recipe.store_file.is_some();
    if publish_seen || every_step_landed {
        if claim.outcome != "absent" {
            *claim = Claim::about(
                super::PUBLISH_CLAIM,
                false,
                Evidence::Captured,
                format!(
                    "every recipe step landed and aMule's StoreFile search sent no 0x44 the \
                     storer saw. {}",
                    claim.note
                ),
            );
        }
        return;
    }
    let broke_at = if recipe.timed_out.is_none() {
        "aMule's UDP verdict never timed out firewalled"
    } else if recipe.buddy_attached.is_none() {
        "aMule never held the Low-ID root as its buddy"
    } else if recipe.opened.is_none() {
        "aMule's UDP verdict never read open after the release"
    } else {
        "aMule never started a StoreFile search for the new file"
    };
    *claim = Claim::blocked(
        super::PUBLISH_CLAIM,
        format!(
            "{broke_at}. {}; aMule: timeout {:?}, `{BUDDY_SEARCH_LINE}` x{}, root {:?}, open \
             {:?}, reload {:?}, `{STORE_FILE_LINE}` x{}",
            claim.note,
            recipe.timed_out,
            count(BUDDY_SEARCH_LINE),
            recipe.buddy_attached,
            recipe.opened,
            recipe.reload.trim(),
            count(STORE_FILE_LINE),
        ),
    );
}

/// `nft <script>` inside aMule's gateway, which carries nft itself.
fn gateway_nft(bench: &Bench, gateway: &str, script: &str, phase: &str) -> Result<String> {
    run_checked(
        bench.docker.exec(
            gateway.to_owned(),
            [OsString::from("nft"), OsString::from(script)],
        ),
        phase,
    )
}

/// `nft <script>` in the server's netns, from a throwaway `natgw` container:
/// the server image carries no nft.
fn server_nft(
    bench: &Bench,
    options: &NattOptions<'_>,
    server: &str,
    script: &str,
    phase: &str,
) -> Result<String> {
    run_checked(
        bench.docker.run_container(
            RunContainer::new(options.natgw_image)
                .remove_after_exit()
                .network(format!("container:{server}"))
                .cap_add("NET_ADMIN")
                .entrypoint("nft")
                .arg(script),
        ),
        phase,
    )
}

/// The packet count of the one counter in an `nft list table` listing.
fn counter_packets(listing: &str) -> u64 {
    listing
        .split("counter packets ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|count| count.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{Recipe, settle_publish};
    use crate::flow::nat::claims::{Claim, Evidence};

    fn recipe(opened: bool, store_file: bool) -> Recipe {
        Recipe {
            root_client_id: Some(5),
            probes_refused: 1,
            timed_out: Some("timed out".to_owned()),
            pings_held: 3,
            buddy_attached: Some("buddy link attached".to_owned()),
            opened: opened.then(|| "open".to_owned()),
            reload: String::new(),
            store_file: store_file.then(|| "StoreFile".to_owned()),
        }
    }

    fn settled(claim: Claim, recipe: &Recipe, publish_seen: bool) -> &'static str {
        let mut claims = vec![claim];
        settle_publish(&mut claims, recipe, "", publish_seen);
        claims[0].outcome
    }

    fn absent() -> Claim {
        Claim::about(super::super::PUBLISH_CLAIM, false, Evidence::Captured, "")
    }

    fn blocked() -> Claim {
        Claim::blocked(super::super::PUBLISH_CLAIM, "")
    }

    /// A `0x44` of the wrong source type is the regression the row exists to
    /// catch; it used to be rewritten to `blocked`, which the leg's `PASS ||
    /// OBSERVED` wrapper accepted.
    #[test]
    fn a_wrong_type_publish_stays_absent() {
        assert_eq!(settled(absent(), &recipe(true, true), true), "absent");
        assert_eq!(settled(absent(), &recipe(false, false), true), "absent");
    }

    /// Every step of the recipe landed and no `0x44` arrived: aMule was
    /// asked and did not publish, which is a failed row, not a bench gap.
    #[test]
    fn a_missing_publish_after_every_step_landed_is_absent() {
        assert_eq!(settled(absent(), &recipe(true, true), false), "absent");
        assert_eq!(settled(blocked(), &recipe(true, true), false), "absent");
    }

    /// A chain that broke before the publish could be asked for is the one
    /// case the bench cannot drive, and stays `blocked`.
    #[test]
    fn a_chain_that_broke_before_the_publish_is_blocked() {
        assert_eq!(settled(absent(), &recipe(false, false), false), "blocked");
        assert_eq!(settled(absent(), &recipe(true, false), false), "blocked");
    }
}
