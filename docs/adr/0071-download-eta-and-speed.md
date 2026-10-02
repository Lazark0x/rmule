# Download ETA divides by a 60-second average; speed is a 4-second meter

## Context

The TUI derives rates at the edge from the core's monotonic byte counters (ADR-0077,
ADR-0069). An estimate of hours and a speed meter answer different questions: aMule
filters each source's speed (`DownloadClient.cpp:1162`) and divides a file's remaining
bytes by its current speed (`PartFile.cpp:3786-3789`), so its estimate swings with one
slow second.

## Decision

- **ETA** divides the bytes still to verify by the speed averaged over the last 60 s
  (`ETA_WINDOW`), or over the whole run while it is younger. **Speed** is a meter: an
  exponential average with a 4 s time constant, close to aMule's per-source filter
  (`DownloadClient.cpp:1162`). An estimate of hours must not swing on one slow second,
  so ETA does not divide by the meter, as aMule does (`PartFile.cpp:3786-3789`).
- An average under 1 KiB/s or an estimate over 30 days reads *slow*. A download with
  nothing left to verify or with no run keeps the dash. ETA sorts by seconds; *slow*
  and the dash are missing values. There is no global ETA.
- **The status is the fact, not the meter.** A download not in Downloading reads Speed 0
  and an ETA dash from the first frame that knows its status. A Downloading row that
  moved no bytes for one meter window reads Speed 0 at the window's end and ETA *slow*.
  Every meter — the status bar, sources, upload peers — follows the same cut.

## Consequences

- An estimate of hours holds steady through a slow second, and the meter still reacts
  within seconds.
- Every meter in the TUI reads the same zero at the same moment.
