//! `rmule` — the product front door (ADR-0069): the terminal UI app with the
//! embedded core, bound behind the `CoreClient` seam.
//!
//! Startup (ADR-0076 §Arguments): read the command line and answer `--help`,
//! `--version` or a refusal before anything touches the data directory; refuse
//! a run with no terminal just as early. Then resolve the data dir by core's
//! rule (`--data-dir` > `RMULE_DATA` > `$XDG_DATA_HOME/rmule` >
//! `~/.local/share/rmule`; `%LOCALAPPDATA%\rmule` in place of the last two on
//! Windows), install the Run Log there, attach the core
//! ([`rmule::attach`]: the one Durable Store, the identities, the core
//! over that store's seams), spawn the bridge, arm the Kad join
//! ([`rmule::kad`]), run the UI. A
//! failure to stand the core up falls back to a UI-only run with the reason in
//! the status bar — honest degrade, never a broken UI.
//! v1 semantics are stock-aMule monolith: quitting the UI stops transfers —
//! gracefully (`App::graceful_quit`): the core's own quit
//! stops every activity in order and flushes the credit checkpoint,
//! bounded so a stuck core cannot hang the terminal.

#![warn(missing_docs)]

use std::io::IsTerminal;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rmule::action::Action;
use rmule::app::App;
use rmule::args::{self, BUILD, Invocation, MissingTerminal, RunArgs};
use rmule::attach::{Attachment, Live, attach};
use rmule::bridge::{self, BridgeConfig};
use rmule::input::spawn_input_pump;
use rmule::theme::Theme;
use rmule::tui::Tui;
use rmule::words::front_door;
use rmule_core::{CoreCommand, ScanCommand};

/// A refused command line.
const EXIT_USAGE: u8 = 2;
/// A run that could not start: no terminal, or the runtime or the terminal
/// failed.
const EXIT_FAILURE: u8 = 1;

fn main() -> ExitCode {
    // Nothing above the terminal check may touch the data directory.
    let run_args = match args::parse(std::env::args_os().skip(1)) {
        Ok(Invocation::Run(run_args)) => run_args,
        Ok(Invocation::Help(run_args)) => {
            print!("{}", front_door::help(BUILD, data_dir(&run_args).as_ref()));
            return ExitCode::SUCCESS;
        }
        Ok(Invocation::Version) => {
            println!("{}", front_door::version_line(BUILD));
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("{}", front_door::args_error(&error));
            return ExitCode::from(EXIT_USAGE);
        }
    };
    if let Some(missing) = MissingTerminal::from_streams(
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
    ) {
        eprintln!("{}", front_door::no_terminal(missing));
        return ExitCode::from(EXIT_FAILURE);
    }
    // One multi-thread runtime for UI loop, bridge, and core tasks.
    let result = tokio::runtime::Runtime::new().and_then(|runtime| runtime.block_on(run(run_args)));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "{}",
                front_door::run_failed(error.kind(), error.raw_os_error())
            );
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

/// The data directory this invocation names, and the rule that picked it.
fn data_dir(run_args: &RunArgs) -> Option<args::DataDir> {
    args::resolve_data_dir(run_args.data_dir.as_deref(), |name| std::env::var_os(name))
}

async fn run(run_args: RunArgs) -> std::io::Result<()> {
    let (actions_tx, actions_rx) = tokio::sync::mpsc::channel(256);
    let shutdown = Arc::new(AtomicBool::new(false));

    // Theme detection (spec §5): RMULE_THEME override beats the COLORTERM
    // truecolor convention; no truecolor ⇒ the hand-tuned 256-safe fallback.
    // This is what the Settings tab's `auto` choice means; a stored
    // choice of dark/light/256 replaces it in `App::with_config`.
    let theme = Theme::select(
        std::env::var("RMULE_THEME").ok().as_deref(),
        std::env::var("COLORTERM").ok().as_deref(),
    );

    // Attach the core before entering the alternate screen so failures print
    // normally; the UI-only fallback still runs with the reason visible.
    // The Run Log first, so the attachment's own events are in it.
    let data_dir = data_dir(&run_args);
    let (log_tell, log_told) = std::sync::mpsc::channel();
    let run_log = data_dir
        .as_ref()
        .ok_or(rmule::run_log::RunLogFailure::NoDataDir)
        .and_then(|data_dir| {
            rmule::run_log::install(
                &data_dir.path,
                log_tell,
                run_args.log_level.unwrap_or_default(),
            )
        });
    if run_log.is_ok() {
        // The log names the build that wrote it, so two runs' logs tell
        // their builds apart.
        rmule::run_log::write(
            &rmule::run_log::Record::new("run_start")
                .code("version", BUILD.version)
                .code("commit", front_door::build_fact(BUILD.commit))
                .flag("dirty", BUILD.dirty)
                .code("committed", front_door::build_fact(BUILD.committed)),
            rmule::run_log::Level::Lean,
        );
    }
    // Without a log the handle still exists, held by nobody who writes.
    let (run_log_level, run_log) = match run_log {
        Ok(level) => (level, Ok(())),
        Err(failure) => (rmule::run_log::LevelHandle::default(), Err(failure)),
    };
    {
        // The log's first failed write is a fact the operator is owed; the
        // thread ends with the run, or at once when there is no log.
        let actions_tx = actions_tx.clone();
        std::thread::spawn(move || {
            if let Ok(failure) = log_told.recv() {
                let _ =
                    actions_tx.blocking_send(Action::Note(rmule::words::app::no_run_log(failure)));
            }
        });
    }
    let attachment = attach(data_dir.clone(), &Live).await;

    let mut tui = Tui::enter()?;
    let pump = spawn_input_pump(actions_tx.clone(), Arc::clone(&shutdown));

    let mut app = App::new(theme);
    match attachment {
        Ok(Attachment {
            core,
            session,
            config,
            mut preferences,
            kad,
            at_start,
        }) => {
            // `--log-level` holds for this run and is never stored; the
            // Settings tab shows the level in force.
            if let Some(level) = run_args.log_level {
                preferences.run_log_full = level == rmule::run_log::Level::Full;
            }
            run_log_level.set(rmule::run_log::Level::from_full(preferences.run_log_full));
            let handle = bridge::spawn(
                core,
                actions_tx.clone(),
                BridgeConfig {
                    run_log: run_log_level.clone(),
                    ..BridgeConfig::default()
                },
            );
            // The operator's connect, given ahead of time — or nothing
            // (ADR-0095): no other road in the app dials a server.
            match at_start {
                rmule::connect::AtStart::Nothing => {}
                rmule::connect::AtStart::Connect(server) => {
                    let command = CoreCommand::ConnectToServer {
                        server,
                        credentials: session.credentials.clone(),
                    };
                    if let Err(error) = rmule::client::CoreClient::send(&handle, command).await {
                        tracing::warn!(%error, "connect at start could not be sent");
                    }
                }
                rmule::connect::AtStart::CannotConnect(why) => {
                    let _ = actions_tx.send(Action::Note(why)).await;
                }
            }
            // The download directory is a shared directory (ADR-0101): its
            // scan starts with the core, and asks before it shares anything
            // the first time it finds files there.
            if let Some(dir) = session.download_dir.clone() {
                let command = CoreCommand::Scan(ScanCommand::Start { dir });
                if let Err(error) = rmule::client::CoreClient::send(&handle, command).await {
                    tracing::warn!(%error, "download directory scan could not be started");
                }
            }
            // The Kad join, parked behind the run's first eD2k login
            // or the operator's `K`: nothing of Kad's reaches the
            // network — not the seed acquisition, not the UDP socket — until
            // the operator has asked to be on one. Off the first-frame path
            // either way, since a cold-start acquisition can mean an HTTP
            // round trip. Each outcome reaches the same status bar every other
            // command's does, including the honest "no contacts, waiting for
            // an eD2k peer" degrade.
            let (kad_start, mut kad_starts) = rmule::kad::start_lane();
            // …and the panel's bare "Kad: off" says nothing about *why* until
            // then, so the app does.
            let _ = actions_tx
                .send(Action::Note(rmule::words::kad::WAITING_FOR_CONNECT))
                .await;
            let kad_client = handle.clone();
            tokio::spawn(async move {
                while let Some(joined) = rmule::kad::join_on_next_start(
                    &mut kad_starts,
                    &kad_client,
                    &kad.config,
                    &kad.bootstrap,
                    &kad.fetcher,
                )
                .await
                {
                    match joined {
                        Ok(outcome) => {
                            let _ = actions_tx
                                .send(Action::Note(rmule::words::kad::seed_outcome_words(
                                    &outcome,
                                )))
                                .await;
                        }
                        // The core stopped; the bus already carries `CoreClosed`.
                        Err(error) => {
                            tracing::warn!(%error, "kad join could not be sent");
                            break;
                        }
                    }
                }
            });
            app = app
                .with_client(handle)
                .with_session(session)
                .with_run_log(run_log_level)
                .with_config(config, preferences)
                .with_kad_start(kad_start);
            if let Err(failure) = run_log {
                app.state.notable = Some(rmule::words::app::no_run_log(failure));
            }
        }
        Err(failure) => {
            // Surface the degrade in the status bar's info feed.
            app.state.notable = Some(rmule::words::app::ui_only(failure));
            // Where the data directory is stays true without a core, and
            // the Settings tab says it.
            app.state.preferences.data_dir = data_dir;
            app.state.ui_only = Some(failure);
        }
    }
    let result = app.run(&mut tui, actions_rx).await;

    shutdown.store(true, Ordering::Relaxed);
    drop(tui); // restore the terminal before waiting on the pump's poll tick
    let _ = pump.join();
    result
}
