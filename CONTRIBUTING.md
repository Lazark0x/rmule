# Contributing to rmule

Thank you for being here. rmule is a small project with one maintainer, so this
page is plain about how contributing works. Please read the short version, then
the parts you need.

## The short version

- **Issues are open to everyone.** Bug reports, interop mismatches and feature
  requests are all welcome, and so are questions in
  [Discussions](https://github.com/Lazark0x/rmule/discussions).
- **Pull requests are by invitation.** Send one once the issue it belongs to
  carries the `accepted` label. A pull request without that is closed
  automatically, politely, and without being read.
- **Sign off every commit** (`git commit -s`); a check enforces it. See
  [Sign your commits](#sign-your-commits).
- **Run the checks** before you open a pull request. See [Build and check](#build-and-check).
- Be kind. See the [Code of Conduct](CODE_OF_CONDUCT.md). Security problems go
  through the [security policy](SECURITY.md), never a public issue.

## Why pull requests are by invitation

rmule is a protocol implementation. A change to what it sends or accepts on the
network usually needs a design discussion first, evidence from other clients, and
a decision about how it fits the rest. One maintainer can review only so much. If
the discussion happens before the code, nobody's evening is wasted on a change
that cannot be merged, and the review is about the work instead of about whether
the work should exist.

It is not a judgement on you or on your code. It is also not meant to stop a good
idea: a well-described issue is the best contribution there is.

## Ways to help without a pull request

- **Interop mismatches.** If rmule and aMule, eMule, an eMule-based client or a
  server disagree about the protocol, the
  [Interop mismatch form](https://github.com/Lazark0x/rmule/issues/new?template=interop-mismatch.yml)
  is the most useful thing you can send. Name the other side exactly (client
  and version), say what each side did, and attach what you have: a log, a hex
  dump, a capture.
- **Bug reports** with steps that reproduce the problem.
- **Feature requests** that start from the problem you are trying to solve.
- **Testing** rmule against a client or a network setup you have and we do not,
  and telling us what happened.
- **Reading the docs** and telling us where they are wrong or unclear.

## Sending a pull request

1. **Find or open an issue.** Search first. Use one of the
   [issue forms](https://github.com/Lazark0x/rmule/issues/new/choose); blank
   issues are turned off so that each report arrives with what we need.
2. **Say you would like to work on it,** and talk the approach through in the
   issue. For anything that changes wire behaviour, or the structure of the code,
   this is where the design is settled.
3. **Wait for `accepted`.** The maintainer adds the label when the change is
   wanted and the approach is agreed. That label is the invitation. It is not a
   promise to merge, and it does not reserve the issue for you on its own: say in
   the thread that you are taking it, so two people do not build the same thing.
4. **Branch from `main`** and keep the change small and about one thing.
5. **Check it and sign it off.** Run the [checks](#build-and-check) and sign every
   commit.
6. **Open the pull request** and fill in the template. Link the accepted issue in
   the description; the automatic check looks for it there.
7. **Review.** Expect questions and requests for changes. CI repeats the checks,
   and a red CI means the change is not finished yet. Reviews happen when time
   allows; a polite nudge after a couple of weeks is fine.

There is no exemption for documentation. A fix to the README, a comment or a
single typo follows the same rule as a code change: it starts as an issue. It
costs two minutes and keeps the rule simple.

### If your pull request was closed automatically

That means it did not link an open issue carrying the `accepted` label. Nothing
was wrong with your work. Open or find the issue, wait for the label, and open a
new pull request that links it.

### Commit messages

Write the subject in the imperative and keep it short (about 70 characters). Use
the body to say why, not what; the diff already says what. One logical change per
commit makes review easier.

Pull requests are squash-merged: your commits become one commit on `main`, with
the sign-offs of all of them kept. For a one-commit pull request that commit's
subject is used, otherwise the pull request title, so write the title the way you
would write a commit subject.

## Sign your commits

rmule uses the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a contributor agreement. You keep your copyright. By signing off, you
certify that you wrote the change or have the right to submit it, and that it
may be distributed under the project's license, GPL-3.0-or-later.

Add the sign-off with `-s`:

```bash
git commit -s -m "Fix the thing"
```

That appends a `Signed-off-by: Your Name <you@example.com>` line, using your
`user.name` and `user.email`. The name and address become part of the public
history.

A check named `dco` runs on every pull request and enforces this. It fails when
a commit has no `Signed-off-by` line, or when the line does not match the
commit's author (the same name and email). It lists each commit it objects to.
Merge commits are skipped. If it fails, fix the last commit with
`git commit --amend -s`, or every commit on your branch with
`git rebase --signoff origin/main`, then update the pull request with
`git push --force-with-lease`.

The certificate you are agreeing to:

```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

### No porting from aMule or eMule

aMule and eMule are behavioural references only. Do not copy, translate or
mechanically port their source code into rmule, however small the piece. Describe
what they do from captures, documentation and observation, and write the code
yourself. The reasoning is in
[ADR-0004](docs/adr/0004-gpl-3-or-later-and-no-ported-source.md)
and
[ADR-0013](docs/adr/0013-pinned-local-reference-cache.md). The sign-off above is
a promise that you kept to this.

## Build and check

You need Rust 1.94 or newer (2024 edition). The repository's `rust-toolchain.toml`
pins 1.94.0 with `clippy` and `rustfmt`, so `rustup` installs the right toolchain
the first time you run `cargo` here.

```bash
cargo build --release          # binaries land in target/release/{rmule,rmule-cli}
```

Before you open a pull request, all five of these pass. CI runs the same ones.

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
scripts/guards.sh
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items
```

What they cover:

- **`cargo test --workspace`** is hermetic. Tests that need Docker, the public
  networks or a long time are switched off unless you opt in with an environment
  variable, so a plain run never touches either.
- **`scripts/guards.sh`** is a pure shell script that checks the shape rules
  below: file sizes, module layout, documentation, glossaries and the docs tree.
  A violation names the file and the rule.
- **`cargo doc`** fails on a broken link or a missing doc, so documentation stays
  part of the build.

`tools/ed2ksrv-differ` is its own workspace and is not covered by `--workspace`;
if you touch it, build and test it from its own directory.

While you develop, point the binaries at a scratch data directory: `--data-dir`
on `rmule-cli`, or `RMULE_DATA` for `rmule`. A work-in-progress build should
never touch your real downloads or identity.

## The interop bench

Wire behaviour is proven against real software: stock aMule and real eD2k
servers, running in containers. If your change touches what rmule sends or
accepts, run the bench flows that cover it and say which ones in the pull request.

You need a Docker-compatible runtime (`--container-runtime <BIN>` selects another
CLI than `docker`). The images are built on your machine from the recipes under
[`tools/interop-harness/images/`](tools/interop-harness/images/), which fetch
pinned upstream inputs (versions, commits and checksums are in the recipes).
Nothing prebuilt is downloaded and no built image is committed. If your container
runtime runs in a VM, keep the checkout and the run directory under your home
directory, which is what such VMs usually mount.

Run one flow end to end. aMule shares a synthetic file, rmule finds it through a
real eD2k server and downloads it, and the harness compares the bytes:

```bash
cargo run -p rmule-interop-harness -- \
  amule-serves-rmule-downloads \
  --build-images \
  --timeout 300
```

Run the whole acceptance suite, one test at a time:

```bash
RMULE_BENCH=1 cargo test -p rmule-interop-harness --test harness \
  -- --ignored --test-threads=1 acceptance::
```

Each run keeps its logs and artifacts under `.scratch/interop-runs/`, which is
never committed. The harness's own README,
[`tools/interop-harness/README.md`](tools/interop-harness/README.md), lists every
flow, what it proves, and the image and run options.

## Code shape

These rules keep the code easy to navigate. `scripts/guards.sh` enforces the
mechanical ones; review enforces the rest.

- **File size.** Aim for 500 lines or fewer per `.rs` file; 1000 is a hard limit
  that the guard enforces. Exemptions live in `scripts/guards-allow.txt`. They
  are rare, and adding one needs a reason in the pull request.
- **Modules.** Use the named-file style: `foo.rs` next to a `foo/` directory. No
  `mod.rs` anywhere, tests included.
- **Splitting a big file.** Keep the interface: the parent module keeps its public
  surface through re-exports, and the implementation moves into private
  submodules along real responsibilities. Do not make `util`, `helpers`,
  `common`, `misc`, `manager` or `handler` modules; name a module for what it does.
- **Where things live.** `apps/` holds user-facing binaries, `crates/` holds
  libraries, `tools/` holds developer tools. Protocol crates are sans-I/O: bytes
  in, events out, no sockets and no clock.
- **Docs on code.** Every `.rs` file opens with a one-paragraph `//!` comment
  saying what the file is for. Every item reachable from a crate root has a `///`
  doc comment. Internals are at your judgement.
- **Comments.** Say what the code cannot: a constraint, an invariant, the reason
  for a surprising choice. No narration of what the next line does, no history,
  no notes to the reviewer.
- **Tests.** Unit tests sit inline under `#[cfg(test)]`; when they push a file
  toward the limit, move them to a sibling `foo/tests.rs`. Integration tests
  live in `tests/<crate>/main.rs` with one module per area
  (`tests/<crate>/<area>.rs`), so each crate has a single integration binary.
  Helpers shared by two or more crates belong in `rmule-testkit`; a helper used
  inside one crate lives in exactly one `tests/<crate>/fixture.rs`. Never keep
  two copies. Write tests that can fail for a real reason. Tests that only echo a
  field back, restate the code, or only prove that something compiles will be
  asked to go.
- **Fixtures are evidence.** Captured fixtures and golden vectors are recorded
  from live systems. Never edit them by hand or regenerate them from the code
  under test. New behaviour needs a new capture. If you cannot capture it, say
  so in the issue before you write the code.
- **Naming.** Use the vocabulary in each crate's `CONTEXT.md` glossary. Only
  domain-standard abbreviations (`ed2k`, `kad`, and similar).
- **Text people read.** Anything printed for a user, front-end output and error
  messages alike, is written in words, never with `{:?}` Debug formatting. The
  guard checks this.
- **`unsafe`** is forbidden across the workspace.

## Docs

- **Delete over archive.** A document that has been superseded or acted on is
  deleted; git history is the archive. There are no `archive/` folders and no
  dated one-off plan files.
- **A small docs tree.** `docs/` holds `adr`, `architecture`, `protocol` and
  `reference`, and nothing else at the top level.
- **Decisions are ADRs.** Each file in `docs/adr/` is a decision in force: a
  changed decision is edited in place and a dropped one is deleted, so no ADR
  carries a status line. Adding or changing an ADR updates its row in the index,
  `docs/adr/README.md`, in the same change.
- **Glossaries.** Each crate has a `CONTEXT.md`, indexed from the repository
  root. A new crate arrives with its glossary and its index row in the same pull
  request.
- **Generated files** such as caches and build output stay untracked.

## License

rmule is GPL-3.0-or-later. Your contributions are licensed the same way. See
[`LICENSE`](LICENSE).
