## Accepted issue

<!--
Pull requests are taken by invitation. Link the issue this change belongs to, by
URL or by writing # followed by its number. That issue must carry the `accepted`
label. A pull request without one is closed automatically; see CONTRIBUTING.md.
-->

Issue:

## What changed and why

<!-- A few sentences. The issue holds the background; say what this change does and any choice a reviewer should look at first. -->

## How it was checked

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `scripts/guards.sh`
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items`
- [ ] Interop bench, if wire behaviour changed (which flows, against which counterparty versions):

## Sign-off

- [ ] Every commit carries a `Signed-off-by` line (`git commit -s`), certifying the Developer Certificate of Origin in CONTRIBUTING.md.
- [ ] No code from aMule, eMule or another GPL-2-only project is copied, translated or mechanically ported into this change.
- [ ] Captured fixtures and golden vectors, if touched, were recorded from a live system and not edited by hand.
