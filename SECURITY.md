# Security policy

rmule is a peer-to-peer client: it parses bytes from strangers all day. A report
that a crafted packet, file name, server list or link can hurt an rmule user is
exactly the kind of report this policy exists for.

## Reporting a vulnerability

Please report privately, never in a public issue, discussion or pull request.

Use GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/Lazark0x/rmule/security/advisories/new)**
(the *Security* tab, then *Report a vulnerability*).

Include what you can of:

- the version or commit you tested, your operating system, and the front-end
  (`rmule` or `rmule-cli`);
- what an attacker needs to be able to do (send a datagram, run a server, share
  a file, hand the user a link);
- a minimal way to reproduce it: a hex dump of the offending bytes, a capture,
  a short script, or steps;
- what you think the impact is. A guess is fine.

You do not need a complete analysis or a fix. A clear reproduction is worth more
than a polished write-up.

## What to expect

This is the policy for every report, counted from the day you submit it.

| Step | Timing |
| --- | --- |
| Acknowledgement that the report was read | within 7 days |
| First assessment: accepted, needs more detail, or not a vulnerability | within 14 days |
| Fix released, for an accepted report | target of 60 days |
| Public disclosure through the advisory | at 90 days at the latest |

The 7-day and 14-day steps are commitments; the 60-day fix is a target, since
some fixes need a change other clients must follow. The 90-day date is fixed: on
that day the advisory is published, with the fix if there is one and with
whatever mitigation exists if there is not. A fix that is ready sooner ships
sooner, and the advisory goes public with it. Any other date needs both of us to
agree in the advisory thread. You are free to publish your own account on or
after day 90.

Accepted reports are published as GitHub security advisories, with a CVE
requested where one applies. You are credited by the name you choose, or not at
all if you prefer.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x (latest release) | yes |
| anything older | no |
| `main` | fixes land here first; it is not a release |

rmule is pre-1.0. Only the latest 0.1.x release receives security fixes, and
once a newer minor line exists the older one stops being supported.

## What is in scope

Anything in this repository that lets an attacker, as a remote peer, a server, a
Kad contact, a web server serving a list, or a file's author, do something the
user did not ask for. Examples:

- a crash, hang or unbounded memory or disk growth triggered by a crafted
  packet, frame, server list, node list or link;
- reading or writing outside the download, incoming or shared directories
  (path traversal through file names, tags or link fields);
- leaking the user's address, identity key or file list in a way the protocol
  does not already expose;
- flaws in how rmule stores or uses its identity key, or in the secure
  identification exchange;
- a way to make rmule take part in an amplification or reflection attack.

## What is out of scope

- Weaknesses of the eD2k and Kad protocols themselves that rmule shares with
  every compatible client: cleartext traffic, unauthenticated Kad contacts,
  Sybil and eclipse attacks on the DHT, and the fact that protocol obfuscation
  hides traffic from casual inspection but is not encryption. rmule keeps these
  behaviours so that it stays compatible. A report that rmule makes one of them
  worse than a stock client does is in scope.
- Vulnerabilities in other clients or servers. Please report those to their
  maintainers. If you found one while testing rmule's interoperability, an
  interop report is welcome once the other project has had its chance to fix it.
- Findings that need an attacker who already controls the user's account, or
  the user's machine.
- Denial of service by simply sending a high volume of valid traffic.

## Testing in good faith

Please test against your own machines, or a private network of your own. Do not
point exploits at other people's peers, servers or files, and do not touch data
that is not yours. Research that follows this policy, and reports what it finds
as described above, is welcome and will not be answered with legal action.

There is no bug bounty.
