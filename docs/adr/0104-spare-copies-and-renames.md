# Spare copies and renames carry a stored hash only when the file's identity proves it

## Context

The same content can sit at two paths under shared directories, and a file can be renamed or
moved while rmule runs or while it is stopped. Re-hashing it costs a read of the whole file
(ADR-0102); carrying a hash to the wrong file offers content the file does not hold.

aMule citations are to 2.3.3 unless they say kno's fork; read, never ported (ADR-0082).

## Decision

- **A spare copy** is a file whose content is already shared from another path. The scan records its
  path, size, modification time and identity in `spare_copy` (keyed by path, indexed by content). A
  spare whose stamp matches is trusted unread and stays a spare. It is in no snapshot, announce or Kad
  publication, and no mark. A spare exists only beside a row of its content: every write that removes
  a row deletes its spares in the same transaction, and a share at a path deletes the spare there.
- **When a row's file vanishes or changes** and a spare of its content still holds its stamp, the row
  is relocated to the spare in one transaction, its part hash set kept and nothing read. When a spare
  vanishes or changes, its record is dropped; it never joins the Had Set.
- **A rename carries its hash when the file's identity proves it.** The identity is the device, inode
  number and birth time. A found file with no trusted record at its path is carried, unread, when a
  row or spare has the same identity, size and modification time; a carried row is relocated (or,
  when its old path still holds the file — a hard link — the new path becomes a spare). It is not
  carried, and is read, when the device differs, the filesystem is not one rmule trusts for a stable
  identity (only APFS and HFS+ on macOS, ext4, btrfs and XFS on Linux, read with `statfs`; nothing on
  other platforms), there is no birth time (ext2/3, small-inode ext4, no `statx`), the record has no
  identity yet, or the size or time differ. Inode reuse after a delete gives a new birth time; only a
  deliberate restamp on macOS could forge one, inside the blind spot already accepted. A pass counts
  carried files apart (`ScanSummary::carried`).

## Consequences

- A rename or a move within a filesystem rmule trusts for identity costs nothing.
- A shared file whose copy survives elsewhere is relocated, never re-read.

## Considered options

- **Carrying a hash across paths on size and time alone.** Rejected: two files that merely share a
  size and a time would match; the file identity answers that.
