# Patched aMule daemon image (private Kad capture only)

This image builds `amuled` from the Ubuntu aMule source package with a single
documented patch so that a **fully private, air-gapped** aMule Kad mesh can form
and emit plain, capturable datagrams. It exists only to capture interop evidence
for `rmule-kad`. **Never point it at the public Kad network.**

## Why a patch is needed

Stock aMule release binaries cannot form a Kad mesh on a private/LAN network:

- `IsGoodIPPort()` hardcodes `IsGoodIP(ip, /*filterLAN=*/true)`, so every RFC1918
  address is rejected for Kad regardless of the `FilterLanIPs` preference. Nodes
  never add each other to their routing tables, so no lookup or source search
  can run.

`disable-lan-kad-filter.patch` changes that one call to `IsGoodIP(ip, false)`.
It deliberately leaves `IsLanIP()` itself intact, because aMule's **LAN mode**
(`CKademlia::IsRunningInLANMode` + `CRoutingZone::HasOnlyLANNodes`) uses it to
detect an all-LAN routing table and switch to non-firewalled "home LAN"
behaviour — exactly what an isolated mesh needs. Patching `IsLanIP` instead would
defeat LAN mode and leave every node firewalled.

The patch relaxes a deployment guard only; no Kad protocol or wire-format logic
is changed, so captured datagrams are genuine aMule output (not invented or
ported bytes).

## Build

```bash
docker build -t rmule/interop-amule:local tools/interop-harness/images/amule
docker build -t rmule/interop-amule-kad-patched:local \
  tools/interop-harness/images/amule-kad-patched
```

## Runtime configuration the mesh needs

The standard `kad-node` entrypoint already applies the rest of the recipe
(see `tools/interop-harness/images/amule/entrypoint.sh`):

- UDP obfuscation disabled → captured Kad packets are plain `0xE4`;
- non-zero `MaxUpload` so the upload-bandwidth throttler flushes Kad control
  packets;
- publisher/routing seeds idle instead of self-terminating.

## Private bootstrap

Each node is seeded with a harness-generated **bootstrap-edition `nodes.dat`**
(version 3, edition 1; one 25-byte contact: 16-byte id, IP in reversed-octet
order, UDP port, TCP port, contact version). aMule only sends
`KADEMLIA2_BOOTSTRAP_REQ` for contacts in this bootstrap list. No public
bootstrap URL or public `nodes.dat` is ever used.

## What this reliably captures

A live private mesh of these nodes reproducibly forms (all nodes reach
`Kad: Connected (ok)` via LAN mode) and emits genuine plain `0xE4` datagrams:
`KADEMLIA2_REQ`/`RES` (`0x21`/`0x29`), `KADEMLIA2_HELLO_REQ`/`RES`
(`0x11`/`0x19`), and `KADEMLIA2_SEARCH_SOURCE_REQ` (`0x34`).

The source **result** (`KADEMLIA2_SEARCH_RES`, `0x3B`) additionally requires the
DHT publish/store/retrieve round-trip to land the publisher's source on a node
the requester queries; in a small controlled mesh the publish and search sets do
not reliably overlap, so `0x3B` is not yet captured here. See
`docs/reference/notes/kad-source-lookup.md`.
