//! One bounded `rmule-tools` run inside the bench network: the container
//! started from the image built at the tip under test at a static address a
//! tap can filter on after it has gone, `root` mounted at `/w`, waited for
//! until it exits on its own bound, and its log kept.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::docker::RunContainer;
use crate::flow::bench::{Bench, run_checked};

/// Run `rmule-tools <args>` as `name` at `ip` and wait for it; the log lands in
/// `root/<name>.log` and is returned. `args` must bound the run
/// (`--max-seconds`, a search's end).
///
/// # Errors
/// If the container cannot be started or waited for, or its log read.
pub(crate) fn run_to_exit(
    bench: &mut Bench,
    image: &str,
    name: &str,
    ip: &str,
    root: &Path,
    args: &[&str],
) -> Result<String> {
    let container = args.iter().fold(
        RunContainer::new(image.to_owned())
            .detach()
            .name(name)
            .network(bench.names.network_name.clone())
            .ip(ip)
            .env("RMULE_LOG", "info")
            .volume(root, "/w"),
        |container, arg| container.arg(*arg),
    );
    bench.start_extra(name, container, "run rmule-tools")?;
    run_checked(bench.docker.wait(name.to_owned()), "wait for rmule-tools")?;
    let logs = run_checked(bench.docker.logs(name.to_owned()), "rmule-tools logs")?;
    let log = root.join(format!("{name}.log"));
    fs::write(&log, format!("{logs}\n")).with_context(|| format!("write {}", log.display()))?;
    Ok(logs)
}
