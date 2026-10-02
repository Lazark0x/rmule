# aMule Login Fixtures

This document describes the safe process for producing aMule-generated eD2k login request fixtures. The goal is to capture aMule's first client-to-server login packet without contacting public eD2k servers or storing user-identifying data.

## Safety Rules

- Use a synthetic aMule profile and nickname.
- Share no real files while capturing fixtures.
- Point aMule at a local fake TCP listener, not a public eD2k server.
- Capture only the first client-to-server packet bytes needed for a login request fixture.
- Reject any fixture candidate that contains public IPs, real server lists, real content names, or user-identifying data.
- Do not commit pcap files unless packet-container metadata is specifically needed and the redaction rule is documented.

## Procedure

1. Start a local TCP listener on a chosen port.
2. Configure aMule with a synthetic nickname and no shared content.
3. Add a server entry pointing to `127.0.0.1` and the listener port.
4. Trigger aMule to connect to that local server entry.
5. Save only the first packet bytes sent by aMule.
6. Store the packet as a `.bin` fixture and add neighboring TOML metadata with `provenance = "amule-generated"`.
7. Verify the fixture with:

```bash
rmule-tools ed2k login inspect crates/rmule-ed2k/tests/fixtures/login/amule_loopback_login_request.bin
```

## Current Status

The offline login work started with a handwritten synthetic login request fixture. The aMule-generated loopback fixture is still an open research task until a safe local capture is produced.
