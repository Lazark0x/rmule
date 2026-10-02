//! What the **NAT Gateway** entrypoint actually renders, read back from the
//! shipped `entrypoint.sh` rather than from a copy of it (ADR-0092).
//!
//! The image's whole behaviour is that one rendered ruleset, and it is written
//! in shell, so this is the cheapest tier that can see it at all: no container
//! runtime, no kernel, just `sh … --print-config`. The RFC 5780 **Reflector
//! Probe** cannot stand in for it — the probe addresses the reflector's own
//! ports and never the pinned client port, which is exactly the port whose rule
//! was wrong in run `1790028867`.

use std::process::Command;

/// The gateway's LAN client and WAN address in every rendering below. Values
/// the flow itself uses, so a rule printed here is the rule a run installs.
const LAN_CLIENT: &str = "10.77.0.3";
const WAN_ADDR: &str = "45.55.200.3";

/// Render one `NAT_TYPE`'s ruleset through the shipped entrypoint.
fn render(nat_type: &str) -> String {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/images/natgw/entrypoint.sh");
    let output = Command::new("sh")
        .arg(script)
        .arg("--print-config")
        .env("NAT_TYPE", nat_type)
        .env("NAT_LAN_CLIENT", LAN_CLIENT)
        .env("NAT_WAN_ADDR", WAN_ADDR)
        .output()
        .expect("run the natgw entrypoint");
    assert!(
        output.status.success(),
        "the natgw entrypoint must render {nat_type} on any POSIX sh: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8(output.stdout).expect("the ruleset is UTF-8")
}

/// **A prerouting DNAT that is not scoped to the WAN interface swallows the
/// client's own outbound traffic.** `prerouting` sees LAN-to-WAN packets too,
/// so `udp dport <pinned> dnat to <client>` matches every datagram the client
/// sends *to* that port on any peer, rewrites the destination to the client
/// itself and routes it back down the LAN. Nothing reaches the WAN.
///
/// That is what happened in run `1790028867`: both peers' six on-target punches
/// and the requester's single uTP `ST_SYN` came back DNAT'd to their own
/// address (conntrack reply tuple `src=10.77.0.3 dst=10.77.0.3`), the WAN taps
/// counted zero `0xB2`, and the flow read as a product defect for two sessions.
/// Only the ±16 sweep — whose destination port is never the pinned one —
/// escaped, which is why the row showed 13 and 31 punches out instead of 38.
#[test]
fn every_inbound_dnat_is_scoped_to_the_wan_interface() {
    for nat_type in [
        "port-restricted",
        "restricted",
        "full-cone-pinned",
        "symmetric",
    ] {
        let ruleset = render(nat_type);
        for rule in ruleset.lines().filter(|line| line.contains("dnat to")) {
            assert!(
                rule.trim_start().starts_with("iifname \"eth0\""),
                "{nat_type}: an inbound DNAT must match only what arrives on the \
                 WAN, or it hairpins the client's own punches: {rule}",
            );
        }
    }
}

/// **Every type drops unsolicited inbound UDP before conntrack commits it.**
/// A NAT gateway hosts no UDP service: anything that reaches `filter input` is
/// a datagram no mapping claimed, and letting the local stack have it commits
/// an entry whose original tuple is `peer:4672 -> us:4672` — the exact reply
/// tuple the client's own next datagram to that peer needs.
///
/// Both halves of the rule are asserted because both are load-bearing. The WAN
/// interface scope keeps the LAN's own traffic out of it; `ct state new` keeps
/// replies to the gateway's own outbound UDP arriving, so the drop covers the
/// unsolicited half only.
///
/// Measured on the bench, at `conntrack -S`: `restricted` and
/// `full-cone-pinned` pin their SNAT to one port, so the kernel has nowhere
/// else to put the mapping and drops the datagram at confirmation
/// (`insert_failed=23`, one per send); `port-restricted` silently picks another
/// external port instead (reply tuple `dport=50982`), which breaks the
/// Endpoint-Independent Mapping that type exists to provide. Two of four broken
/// by one cause is why the rule is generic.
#[test]
fn every_type_drops_unsolicited_inbound_udp_before_it_becomes_state() {
    for nat_type in [
        "port-restricted",
        "restricted",
        "full-cone-pinned",
        "symmetric",
    ] {
        let ruleset = render(nat_type);
        let drop_rule = ruleset
            .lines()
            .map(str::trim)
            .find(|line| line.ends_with("drop"))
            .unwrap_or_else(|| {
                panic!("{nat_type} installs no drop rule at all:\n{ruleset}");
            });
        for fragment in ["iifname \"eth0\"", "meta l4proto udp", "ct state new"] {
            assert!(
                drop_rule.contains(fragment),
                "{nat_type}: the unsolicited-inbound drop must match {fragment}, \
                 or it drops the wrong traffic: {drop_rule}",
            );
        }
        assert!(
            ruleset.contains("hook input priority filter"),
            "{nat_type}: the drop must sit in filter input, which runs before \
             conntrack confirmation at LOCAL_IN — anywhere later and the entry \
             is already committed:\n{ruleset}",
        );
    }
}

/// The two types that admit an unsolicited inbound datagram are the two that
/// carry a DNAT at all; the other two leave conntrack as the whole filter, and
/// a stray DNAT there would silently turn an APDF gateway into a port-forward.
#[test]
fn only_the_two_filtering_types_install_a_dnat() {
    for (nat_type, expected) in [
        ("port-restricted", 0),
        ("restricted", 1),
        ("full-cone-pinned", 1),
        ("symmetric", 0),
    ] {
        let ruleset = render(nat_type);
        let dnats = ruleset
            .lines()
            .filter(|line| line.contains("dnat to"))
            .count();
        assert_eq!(dnats, expected, "{nat_type} rendered:\n{ruleset}");
    }
}

/// The two rules that make `symmetric` and `restricted` the types they claim,
/// and nothing else carrying them. Without `fully-random` symmetric is a
/// port-preserving SNAT (endpoint-independent mapping); without the `@seen`
/// gate restricted's DNAT is unconditional — `full-cone-pinned` under another
/// name — and the Reflector Probe of a punch row is the only other place
/// either would show.
#[test]
fn each_type_carries_exactly_its_own_mapping_and_filtering_rules() {
    for (nat_type, fully_random, seen_gate) in [
        ("port-restricted", false, false),
        ("restricted", false, true),
        ("full-cone-pinned", false, false),
        ("symmetric", true, false),
    ] {
        let ruleset = render(nat_type);
        let has = |fragment: &str| ruleset.lines().any(|line| line.contains(fragment));
        assert_eq!(
            has("fully-random"),
            fully_random,
            "{nat_type}: `fully-random` SNAT:\n{ruleset}",
        );
        assert_eq!(
            has("update @seen"),
            seen_gate,
            "{nat_type}: the LAN side's `update @seen`:\n{ruleset}",
        );
        let gated_dnat = ruleset
            .lines()
            .any(|line| line.contains("ip saddr @seen") && line.contains("dnat to"));
        assert_eq!(
            gated_dnat, seen_gate,
            "{nat_type}: a DNAT gated on `ip saddr @seen`:\n{ruleset}",
        );
        if seen_gate {
            assert!(
                ruleset
                    .lines()
                    .filter(|line| line.contains("dnat to"))
                    .all(|line| line.contains("ip saddr @seen")),
                "{nat_type}: an ungated DNAT turns it into full-cone:\n{ruleset}",
            );
        }
    }
}

/// The **Port-Mapping Gateway** claims `natgw`'s `port-restricted` recipe, so
/// it carries the same unsolicited-inbound drop: without it an
/// unsolicited WAN datagram's conntrack entry can collide with a LAN mapping's
/// reply tuple and the port-preserving SNAT silently remaps the client. Read
/// off the shipped entrypoint, whose ruleset is a heredoc with no render mode.
#[test]
fn the_port_mapping_gateway_drops_unsolicited_wan_udp_like_natgw() {
    let script = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/images/miniupnpd/entrypoint.sh"
    ))
    .expect("read the miniupnpd entrypoint");
    let lines: Vec<&str> = script.lines().map(str::trim).collect();
    let hook = lines
        .iter()
        .position(|line| line.starts_with("type filter hook input priority filter"))
        .expect("the gateway installs a filter-input chain");
    assert!(
        lines[hook..]
            .iter()
            .take(3)
            .any(|line| *line == "iifname \"$WAN_IF\" meta l4proto udp ct state new drop"),
        "the input chain must drop new UDP from the WAN, and only from the WAN",
    );
}
