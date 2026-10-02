#!/bin/sh
# Run the folder watch past inotify's watch limit, on Linux, in one container.
#
#   scripts/inotify-limit-run.sh [limit]
#
#   limit  the watch limit the run lowers to (default 64)
#
# The test (`download_directory_scan::past_the_inotify_limit_…`, ignored and
# gated on RMULE_INOTIFY_LIMIT=1) needs a limit it can reach. Docker refuses
# `--sysctl fs.inotify.max_user_watches`: that sysctl belongs to no namespace
# a container has. The limit a watch is charged against first is its user
# namespace's (`/proc/sys/user/max_inotify_watches`), and the owner of a user
# namespace may lower it there. So the run enters a user namespace of its own
# and lowers the limit inside it: nothing else in the VM, the bench's
# containers included, loses a watch. `--privileged` is what lets the
# container create that namespace (the default seccomp profile and Ubuntu's
# AppArmor userns restriction both refuse it otherwise).
#
# The build lands in the named volume `rmule-inotify-target`, never in the
# worktree's own `target/`, whose artifacts are the host's. The volumes are
# this run's own; remove them with
#   docker volume rm rmule-inotify-target rmule-inotify-cargo
set -eu

limit="${1:-64}"
repo="$(cd "$(dirname "$0")/.." && pwd)"
test_name='download_directory_scan::past_the_inotify_limit_the_operator_is_told_once_and_a_fresh_pass_still_shares'

exec docker run --rm --privileged \
	-v "$repo":/src:ro -w /src \
	-v rmule-inotify-target:/target -e CARGO_TARGET_DIR=/target \
	-v rmule-inotify-cargo:/usr/local/cargo/registry \
	-e RMULE_INOTIFY_LIMIT=1 \
	rust:1.94.0-bookworm \
	sh -c "cargo fetch --locked && unshare --user --map-root-user sh -c '
		echo $limit > /proc/sys/user/max_inotify_watches &&
		echo \"watch limit in this namespace: \$(cat /proc/sys/user/max_inotify_watches)\" &&
		cargo test --locked --offline -p rmule-core --test core -- --ignored --exact $test_name --nocapture'"
