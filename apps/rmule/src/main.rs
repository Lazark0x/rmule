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
//! bounded so a stuck core cannot hang the terminal. A stop signal is the
//! same Quit, and the panic hook decides what a panic costs (ADR-0118).

#![warn(missing_docs)]

use std::io::IsTerminal;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rmule::action::Action;
use rmule::app::App;
use rmule::args::{self, BUILD, Invocation, MissingTerminal, RunArgs};
use rmule::attach::{Attachment, Live, attach};
use rmule::bridge::{self, BridgeConfig};
use rmule::input::spawn_input_pump;
use rmule::theme::{Colours, Theme};
use rmule::tui::Tui;
use rmule::words::front_door;
use rmule_core::run_log::{self, Level, RunLog, RunLogFailure};
use rmule_core::{CoreCommand, StopRequest};

/// A refused command line.
const EXIT_USAGE: u8 = 2;
/// A run that could not start: no terminal, or the runtime or the terminal
/// failed.
const EXIT_FAILURE: u8 = 1;
/// How long the blocking pool is given once the run is over: past the core's
/// own grace a walk still on it has no one left to answer, and must not keep
/// the process alive behind a restored terminal.
const RUNTIME_SHUTDOWN_BOUND: Duration = Duration::from_secs(2);

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
    let result = tokio::runtime::Runtime::new().and_then(|runtime| {
        let result = runtime.block_on(run(run_args));
        runtime.shutdown_timeout(RUNTIME_SHUTDOWN_BOUND);
        result
    });
    rmule_core::run_log::drain();
    match result {
        Ok(code) => code,
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

async fn run(run_args: RunArgs) -> std::io::Result<ExitCode> {
    let (actions_tx, actions_rx) = tokio::sync::mpsc::channel(256);
    let shutdown = Arc::new(AtomicBool::new(false));

    // Theme detection (spec §5, `Theme::select`). This is what the Settings
    // tab's `auto` choice means; a stored choice replaces it in
    // `App::with_config`.
    let colorterm = std::env::var("COLORTERM").ok();
    let term = std::env::var("TERM").ok();
    let theme = Theme::select(
        std::env::var("RMULE_THEME").ok().as_deref(),
        Colours {
            colorterm: colorterm.as_deref(),
            term: term.as_deref(),
            no_color: std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()),
        },
    );

    // Attach the core before entering the alternate screen, so a run with no
    // core ends with its reason on the normal screen and a failing status,
    // not in tabs that can do nothing (ADR-0083).
    // The Run Log first, so the attachment's own events are in it.
    let data_dir = data_dir(&run_args);
    let opened = data_dir
        .as_ref()
        .ok_or(RunLogFailure::NoDataDir)
        .and_then(|data_dir| RunLog::open(&data_dir.path, run_args.log_level.unwrap_or_default()));
    // Without a log the handle still exists, held by nobody who writes.
    let run_log_level = opened.as_ref().map(RunLog::level).unwrap_or_default();
    // Ahead of everything that can panic. This future runs on the main
    // thread, which is the UI's.
    rmule::fault::install_hook(
        std::thread::current().id(),
        run_log_level.clone(),
        actions_tx.downgrade(),
        data_dir
            .as_ref()
            .filter(|_| opened.is_ok())
            .map(|data_dir| data_dir.path.join(run_log::FILE_NAME)),
    );
    let run_log = match opened.and_then(RunLog::install) {
        Ok(failures) => {
            // The log names the build that wrote it, so two runs' logs tell
            // their builds apart.
            run_log::write(
                &run_log::run_start(BUILD.version, BUILD.commit, BUILD.committed, BUILD.dirty),
                Level::Lean,
            );
            // The log's first failed write is a fact the operator is owed;
            // the thread ends with the run.
            let actions_tx = actions_tx.clone();
            std::thread::spawn(move || {
                if let Ok(failure) = failures.recv() {
                    let _ = actions_tx
                        .blocking_send(Action::Note(rmule::words::app::no_run_log(failure)));
                }
            });
            Ok(())
        }
        Err(failure) => Err(failure),
    };
    let attachment = match attach(data_dir, &Live, run_log_level.clone()).await {
        Ok(attachment) => attachment,
        Err(failure) => {
            eprintln!(
                "rmule: {}",
                rmule::words::app::attach_failure_words(failure)
            );
            return Ok(ExitCode::from(EXIT_FAILURE));
        }
    };

    // Every stop the OS can ask for is the operator's `q`; held on the bus
    // until the UI reads it, however early it comes.
    let stop_signals_refused = match StopRequest::install() {
        Ok(mut stop) => {
            let actions_tx = actions_tx.clone();
            tokio::spawn(async move {
                stop.recv().await;
                let _ = actions_tx.send(Action::Quit).await;
            });
            false
        }
        Err(_) => true,
    };

    let mut tui = Tui::enter()?;
    let pump = spawn_input_pump(actions_tx.clone(), Arc::clone(&shutdown));

    let mut app = App::new(theme);
    let Attachment {
        core,
        session,
        config,
        mut preferences,
        kad,
        at_start,
        ceiling_lowered,
    } = attachment;
    // `--log-level` holds for this run and is never stored; the
    // Settings tab shows the level in force.
    if let Some(level) = run_args.log_level {
        preferences.run_log_full = level == Level::Full;
    }
    run_log_level.set(Level::from_full(preferences.run_log_full));
    let handle = bridge::spawn(core, actions_tx.clone(), BridgeConfig::default());
    // The operator's connect, given ahead of time — or nothing
    // (ADR-0095): no other road in the app dials a server.
    let cannot_connect = match at_start {
        rmule::connect::AtStart::Nothing => None,
        rmule::connect::AtStart::Connect(server) => {
            let command = CoreCommand::ConnectToServer { server };
            if let Err(error) = rmule::client::CoreClient::send(&handle, command) {
                tracing::warn!(%error, "connect at start could not be sent");
            }
            None
        }
        rmule::connect::AtStart::CannotConnect(why) => Some(why),
    };
    // The Kad join, parked behind the run's first eD2k login
    // or the operator's `K`: nothing of Kad's reaches the
    // network — not the seed acquisition, not the UDP socket — until
    // the operator has asked to be on one. Off the first-frame path
    // either way, since a cold-start acquisition can mean an HTTP
    // round trip. Each outcome reaches the same status bar every other
    // command's does, including the honest "no contacts, waiting for
    // an eD2k peer" degrade.
    // The player lane (ADR-0114): each Preview's player is started
    // and awaited on a task of its own, and how it ended is noted.
    let (player, launches) = rmule::player::lane();
    tokio::spawn(rmule::player::play_each(launches, actions_tx.clone()));
    let (kad_start, mut kad_starts) = rmule::kad::start_lane();
    // …and the panel's bare "Kad: off" says nothing about *why* until
    // then, so the app does, among what else a start has to say.
    let notes = rmule::start_notes::start_notes(rmule::start_notes::StartFacts {
        no_run_log: run_log.err().map(rmule::words::app::no_run_log),
        stop_signals_refused,
        ceiling_lowered: ceiling_lowered.map(rmule::words::download::ceiling_lowered),
        cannot_connect,
        download_dir_set: session.download_dir.is_some(),
    });
    for note in notes {
        let _ = actions_tx.send(Action::Note(note)).await;
    }
    let kad_client = handle.clone();
    tokio::spawn(async move {
        while let Some(joined) = rmule::kad::join_on_next_start(
            &mut kad_starts,
            &kad_client,
            &kad.config,
            kad.own_id,
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
        .with_kad_start(kad_start)
        .with_player(player);
    let result = app.run(&mut tui, actions_rx).await;

    shutdown.store(true, Ordering::Relaxed);
    drop(tui); // restore the terminal before waiting on the pump's poll tick
    let _ = pump.join();
    result.map(|()| ExitCode::SUCCESS)
}
