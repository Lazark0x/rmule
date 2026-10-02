# `miniupnpd` — the Port-Mapping Gateway (ADR-0092)

A **NAT Gateway** that also speaks the three protocols rmule's **Port Mapper**
races (ADR-0086): UPnP-IGD2, NAT-PMP and PCP. Used by `portmap-highid`,
`portmap-mismatch` and `portmap-ipv6-pinhole` as the `natgw` itself — it holds
the WAN and LAN attachments, translates, and answers on UDP 5351 and SSDP.

```
docker build -t rmule/interop-miniupnpd:local tools/interop-harness/images/miniupnpd
```

## Pin

`alpine:edge` + `miniupnpd-nftables=2.3.10-r0` + `miniupnpc=2.3.3-r2`, pinned by
exact package version. Alpine 3.22 carries only miniupnpd 2.3.7; 2.3.10 is the
release ADR-0092 names, and it is on `edge`. The daemon states its own build at
startup and the flow keeps the line:

```
rmule-miniupnpd-version miniupnpd 2.3.10 May 14 2026
rmule-miniupnpd-version using netfilter(nftables) backend
rmule-miniupnpd-version build options: ipv6 NAT-PMP PCP leasefile igdv2
```

That line **is** the `--ipv6 --igd2 enable_pcp_pmp=yes` gateway ADR-0092 asks
for: `ipv6` and `igdv2` are compiled in, and `-N` (this build's own help: "enables
NAT-PMP and PCP functionality") is what the entrypoint passes.

## Measured: the WAN cannot be an RFC 5737 prefix

miniupnpd applies its own `addr_is_reserved()` to the address it would report as
the external IP, and that list includes the RFC 5737 documentation ranges. On
`203.0.113.0/24` — the harness's first fake-public prefix — the daemon answers
every `GetExternalIPAddress` with an empty string and logs:

```
miniupnpd[1]: private/reserved address 203.0.113.2 is not suitable for external IP
```

A gateway with no external address grants nothing usable, so **the port-mapping flows
put their WAN on the third fake-public prefix, `45.55.200.0/24`** (fake-public
subnet index 2) — the one ADR-0092 already names for mixed topologies because it
is the only prefix both aMule and emule-qt accept. Verified on the same bench:
`ExternalIPAddress = 45.55.200.2`, and an `AddPortMapping` for `4662` lands in
the lease file as `TCP:4662:10.77.0.3:4662:<expiry>:rmule`.

rmule's own **Address Learning** store deliberately does *not* refuse the
documentation ranges (`admissible.rs`: "aMule routes them"), so this is a
miniupnpd rule the bench works around, never a rmule one.

## The gateway's own table

Two files, both written by the daemon or the kernel, never by the harness:

- `upnp.leases` (`lease_file`, copied to `gateway-table.txt` by the proof dump) —
  `proto:eport:iaddr:iport:expiry:description`, one line per granted mapping.
- `nft-ruleset.txt` — `nft list ruleset`, holding both the entrypoint's SNAT and
  every DNAT/filter rule miniupnpd added for a grant.

`clean_ruleset_interval=0`: the daemon never reaps on a timer, so a flow reading
the table is not racing a sweeper.

## PCP lifetime clamps

miniupnpd's default `min_lifetime` is 120 s, which would silently turn a flow's
deliberately short lease into a two-minute one and push the renewal it is trying
to observe outside the window. The entrypoint writes `min_lifetime=4`
(`MINIUPNPD_MIN_LIFETIME`) and copies the whole generated `miniupnpd.conf` into
the proof directory, so a row is always readable against the clamps that were in
force when it was taken.
