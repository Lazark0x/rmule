# A part file stays positional and is never pre-sized; every write that extends it punches the gap it opened, and each run measures whether its disk holds holes

## Context

A run writes each verified part at its absolute offset through the one handle it holds on its
`.part` (ADR-0094, "The run holds its part file"), which lies in the Temp Directory for a download
placed since ADR-0115 and beside its final path for an older one. It sets no length, sets no
sparse flag and punches nothing, so whether the file occupies only the bytes written is the
filesystem's accident:

- Measured on Linux 6.8: ext4, XFS, btrfs and overlayfs leave a hole at 4 KiB granularity where a
  write lands past the end of the file.
- Measured on macOS 27 disk images: HFS+, exFAT and FAT32 hold no hole; even truncating to the
  final size costs the full size.
- Documented: NTFS holds a hole only after `FSCTL_SET_SPARSE`, and `FSCTL_SET_ZERO_DATA` frees a
  range only on a file already sparse, writing zeros otherwise. ReFS and SMB 3.0 take the same
  controls; NFS needs 4.2.
- Measured on macOS 27 APFS: a gap past the end of the file below exactly 16,777,216 bytes is
  zero-filled, so a single missing 9,728,000-byte part costs its full size; twenty parts written
  in ascending order with gaps cost 184,836,096 bytes, and setting the full length first does not
  help (184,844,288). `fcntl(F_PUNCHHOLE)` over every gap brought one such file from 87,556,096 to
  40,960 bytes, exactly the bytes written; it works at 4 KiB granularity and refuses an unaligned
  range with `EINVAL`. Linux `fallocate(PUNCH_HOLE | KEEP_SIZE)` succeeds on ext4, XFS and btrfs.
- Measured on Linux XFS: an 8 MiB write reports 16,711,680 bytes allocated (speculative
  preallocation). NTFS rounds to clusters and ZFS reports late on a dirty file, so the allocated
  size can exceed the file's length.
- Measured on APFS: a rename within one filesystem keeps the holes (36,864 bytes before and after).

aMule writes each block at its offset in the part file (`PartFile.cpp:126-131`), serves an upload
from the part file at the block's offset (`PartFile.cpp:3137-3147`, `UploadClient.cpp:226-233`) and
hands the part file's path to the previewer (`DownloadListCtrl.cpp:1447-1450`). It creates the
part file sparse by default (`PartFile.cpp:289-294`; `CreateSparseFiles` on, `Preferences.cpp:1261`;
`AllocateFullFile` off, `Preferences.cpp:1097`): on Windows it sets the sparse flag, zeroes the whole
range and sets the end of the file at the final size (`PlatformSpecific.cpp:62-100`); elsewhere it
creates an empty file (`PlatformSpecific.cpp:105-109`). At completion it renames the part file,
copying it when the rename fails across partitions (`ThreadTasks.cpp:467-474`).

aMule citations are to 2.3.3; read, never ported (ADR-0082).

## Decision

**A download's `.part` is a Sparse Part File: positional, holding only verified bytes, never
pre-sized, and on a disk that can hold a hole occupying only the bytes written.**

### The Sparse Part File

- **Positional.** Byte *N* of the download is byte *N* of the `.part`, on every platform: no
  header, index or remapping. It is what lets the serve side (ADR-0113) and a player (ADR-0114)
  read the `.part` at the download's own offsets, as aMule does.
- **Verified bytes only.** A part is checked against its part hash before it is written
  (`persist_streamed_part`). The one exception is a file with no part hashes, whose parts are
  written under the file hash's authority and checked whole at finalize.
- **Never pre-sized.** No `set_len`, no reserving `fallocate`. Its length is the end of the highest
  part written so far; a reader meets the end of the file there, as on aMule's builds other than
  Windows.
- **Bounded.** Where the run's Hole Verdict is `HoldsHoles`, the file's **Allocated Bytes** are at
  most the bytes written, plus one allocation unit of the filesystem at each end of each Extension
  Gap, plus the filesystem's own slack (XFS preallocation, cluster rounding). A part a repair
  dropped (ADR-0094, "Damaged parts are repaired, not condemned") counts as written until it is
  rewritten at the same offset and length. The gaps are not stored anywhere new: they are the parts ADR-0079's positional
  vector does not show `Verified`.

### Every write that extends the file punches its Extension Gap

- **The Extension Gap** of one write at `offset` into a file whose length was `end` just before it
  is `[end, offset)` when `offset > end`, and empty otherwise. It is the only range a write can make
  a filesystem zero-fill, and it never holds a verified byte: every earlier write ended at or before
  `end`. The run already reads `end` on the held handle before each part, in the check that the
  file is still the one it holds.
- **The punch.** After the write, the run punches `[align_up(end, 4096), align_down(offset, 4096))`
  when that range is not empty: aligned inward, so the verified bytes on both sides are untouched
  and APFS never sees an unaligned range. The eD2k part size is 2,375 × 4 KiB, so every gap a
  whole-part write opens is aligned already; aligning inward keeps the rule true without that.
  Linux punches with `fallocate(PUNCH_HOLE | KEEP_SIZE)`, macOS with `fcntl(F_PUNCHHOLE)`, Windows
  with `FSCTL_SET_ZERO_DATA`. On a filesystem that left a hole by itself the punch changes nothing;
  one path on every platform keeps the bound independent of how each filesystem extends a file.
- **A failed punch costs space, never correctness.** The part is already written; the failure is
  logged at `debug` and the run goes on.
- **Windows sets the sparse flag once per run.** When the run holds its part file it sets
  `FSCTL_SET_SPARSE` on the handle, before its first write. The control is idempotent, so a part
  file an older build wrote becomes sparse too; the zeros it already holds stay allocated, and
  nothing scans for them. A volume that refuses the flag (FAT, exFAT) is not an error, but that run
  does not punch: `FSCTL_SET_ZERO_DATA` on a file that is not sparse writes zeros.
- **Nothing else is punched.** A rewrite inside the file, such as a repaired part, extends nothing.
  A dropped part's range is left allocated, since its rewrite reuses it.
- **One write is one blocking-pool call** on the held standard-library handle: the check, the
  positional write, the punch and the reading. No async file operation is ever in flight on the
  handle while a raw-handle call runs on it.

### Allocated Bytes is a level read after each write

`DownloadDiagnostics::allocated_bytes: Option<u64>` is what the filesystem reserved for the
`.part`: `st_blocks × 512` on Unix, `FILE_STANDARD_INFO.AllocationSize` on Windows, read on the
held handle after the punch. It is read when the run holds the file and after every part written,
never on a clock and never when a snapshot is taken, since the snapshot is a synchronous read of
shared state (ADR-0077). `None` means not read; a reading that fails sets `None`. It is published
as read, above the file's length included: core computes no ratio and clamps nothing, and
"over-allocated" is a consumer's word. The row keeps the last reading after the run ends
(ADR-0094); the next run's first reading replaces it. Cost: one `fstat` per 9.28 MB part.

### Each run measures whether its disk holds holes

- **The Hole Probe.** When the run first holds its part file — once per run, since a repair keeps
  the handle — it writes a probe file in the `.part`'s own directory through the same write as a
  part: created or truncated, the sparse flag set, 4 KiB at offset 0 and 4 KiB at
  `4096 + 32 MiB`, the Extension Gap punched; then `fsync`, Allocated Bytes, and the file deleted.
  The **Hole Verdict** is `HoldsHoles` when the allocated size is below half the probe's length,
  `HoleLess` otherwise, and `Unknown(io::ErrorKind)` when any step failed. The 32 MiB gap exceeds
  XFS preallocation and cluster rounding with margin. Because the probe punches, it measures
  rmule's own mechanism rather than the filesystem's default, so APFS's fill threshold does not
  enter the verdict.
- **The probe file** is `.<part file name>.holeprobe` beside the `.part`, in the Temp Directory or,
  for an older row, the download directory, where the dot prefix keeps the scan and its watch off
  it (ADR-0101). Its name is fixed per download, so a file a crash left behind is truncated and
  deleted by the next probe, and removing the `.part` (a cancel, or a Restart that starts over)
  removes it too.
- **Per run, in the `.part`'s directory**, because a download writes to the paths placed at its
  start and kept on its row (ADR-0115): a later change of the Temp Directory does not move it, so a
  verdict on the setting's directory says nothing about it. The volume under a path can also
  change between one run and the next.
- **Cost.** On a disk that holds holes, 8 KiB and one `fsync` per run. On one that does not, the
  filesystem fills 32 MiB per run, which several runs starting together on one slow volume each pay.
- **Level and edge.** `DownloadDiagnostics::hole_verdict: Option<HoleVerdict>` is `None` from a
  run's start until its probe answers, and the row keeps it after the run. A `HoleLess` verdict also
  sends `DownloadEvent::HoleLessDestination { download_id, directory }`, once per run: the CLI
  reads events and never the snapshot, and a note the TUI shows does not outlive the next note, so a
  level alone reaches no CLI user and an edge alone is gone after a moment. `Unknown` sends no edge:
  the probe's failure is the one the run's own writes meet, and those end the run as
  `DownloadFailed`.
- **A verdict changes nothing the run does.** A `HoleLess` run proceeds; the scheduler takes no
  input from the verdict (ADR-0112); there is no second layout for a disk that holds no holes.

### What the operator reads

Core carries the verdict and the directory; the sentences live in the download words of
`rmule-words`, which the CLI and the TUI share. The edge's sentence names the download and the
directory and says that this disk holds no holes, so the file takes its full length up to its last
verified part, that the download goes on, and that a Temp Directory on another disk avoids it. The
CLI prints it; the TUI puts it in the status note and the Networks log, once per run. The
Allocated Bytes and the verdict are shown in one place only: an **On disk** row in the Transfers
details modal, the Allocated Bytes and what the verdict means; the downloads table carries
neither. A reading or verdict not yet taken shows a dash, an `Unknown` verdict says the disk was
not measured and why, and no state reads "OK".

### Completion is a rename, else the copy of ADR-0115

A rename within one filesystem keeps the file's holes; the Completion Copy across volumes writes a
finished file, which has no gap left to keep. Either way the `.part` is read at its own offsets only
before completion, and the finished file is never pre-sized either.

### The operating-system calls live in `rmule-os`

- **One crate holds every call std does not expose and every `unsafe` block:** `crates/rmule-os`,
  which takes in the former `rmule-winsock`. Module `winsock` is the ICMP-reset switch `rmule-net`
  sets on every unconnected UDP socket, unchanged. Module `sparse` holds three primitives over a
  borrowed `&std::fs::File`: `set_sparse` (a no-op off Windows), `punch_hole(offset, len)` and
  `allocated_bytes`. What to punch, the probe and the verdict are core's.
- **Safe where a safe call exists:** the Linux punch goes through `rustix`, the Unix reading through
  std. The waived functions are the macOS punch (`libc`'s `F_PUNCHHOLE` and `fpunchhole_t`), the
  three Windows calls (`DeviceIoControl` with `FSCTL_SET_SPARSE` and with `FSCTL_SET_ZERO_DATA`,
  `GetFileInformationByHandleEx` with `FileStandardInfo`) and `WSAIoctl`. `libc`, `rustix` and
  `windows-sys` are already in the dependency graph: no crate is added.
- **How the compiler and the guards hold it.** The crate's own lint table repeats
  `[workspace.lints]` but relaxes `unsafe_code` to `deny`; every other crate keeps `forbid`, which
  no inner `allow` can lift. `scripts/guards.sh` (check `unsafe`) pins the waived functions by file
  and name: each carries the one waiver, holds one `unsafe` block under a `// SAFETY:` comment, and
  nothing else in the crate, or outside it, holds either.

## Consequences

- On ext4, XFS, btrfs, APFS and NTFS a part file costs its verified bytes plus slack, in whatever
  order its parts arrive. On HFS+, exFAT and FAT32 it costs every byte up to its highest verified
  part, which the head-and-tail order of ADR-0112 reaches early, and the operator is told once per
  run. With the default Temp Directory on the data directory's volume, that happens mostly where
  the operator moved the Temp Directory to such a disk, or for an older row whose part file lies
  in the download directory.
- Tests of the punch, the reading and the probe run natively on Linux ext4, macOS APFS and Windows
  NTFS in CI's test matrix, so a change of platform behaviour fails a build.
- Not measured: whether the sparse flag fails cleanly on FAT and exFAT under Windows, what SMB and
  NFS 4.2 mounts report, whether ZFS's late reading can make a hole-holding dataset read
  `HoleLess`, and what the punch costs on the blocking pool.

## Considered options

- **Probing when the operator chooses the Temp Directory, or when a `.part` is first created.**
  Rejected: a download's paths outlive a change of the setting, a resumed download creates
  nothing, and the setting's door is synchronous and also runs with no core at all.
- **Caching one verdict per volume.** Rejected: a volume key passes to another filesystem when
  removable media are swapped and the device number is reused, and the level must never show
  another disk's verdict.
- **Setting the full length up front**, aMule's shape on Windows. Rejected: it does not stop the
  APFS fill and costs the full size at once on HFS+, exFAT and FAT32.
- **Punching only where a fill was seen, or never on Linux.** Rejected: one path keeps the bound
  whatever a filesystem does with an extending write, and a punch over a hole changes nothing.
- **A second exempt crate beside `rmule-winsock`.** Rejected: two lint tables and two waiver
  contracts, and "where may `unsafe` live" becomes a list of crates instead of one.
- **Safe wrappers only.** Rejected: `rustix` covers the Linux punch, but neither it nor
  `winapi-util`, both already in the tree, covers `F_PUNCHHOLE`, the two controls or
  `AllocationSize`.
