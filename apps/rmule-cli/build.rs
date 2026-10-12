//! Captures the build facts the Run Log's `run_start` record names, by the
//! one script `rmule` runs (ADR-0076 §Arguments), so both front ends write
//! the same facts the same way.

#[path = "../rmule/build.rs"]
mod capture;

fn main() {
    capture::main();
}
