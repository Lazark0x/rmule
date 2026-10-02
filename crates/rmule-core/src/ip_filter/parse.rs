//! The ipfilter dat **line grammar** — aMule 2.3.3's flex scanner
//! (`src/IPFilterScanner.l`) as a byte scanner, with nothing behind it: no
//! range store, no access level threshold, no verdict. One line in, one
//! [`ParsedLine`] out.
//!
//! **Two line formats, decided per line**: the PeerGuardian form
//! `<IPStart> - <IPEnd> , <AccessLevel> , <Description>` and the AntiP2P form
//! `<Description> : <IPStart> - <IPEnd>` (whose level is hardcoded 0). A
//! `#`-leading line is a comment; a whitespace-only line is blank; anything
//! else — including a shape-matched line whose octet or level exceeds 255 — is
//! one malformed line (aMule's `yyip_Bad`), counted and discarded without
//! failing the load.
//!
//! The flex rule order and longest-match resolution reduce to: PeerGuardian
//! first, then comment, then AntiP2P taken at the *rightmost* colon whose tail
//! matches the range shape (trailing bytes after the match are swallowed, and
//! a value-invalid shape match is malformed — it never retries another colon).

/// What one line of an ipfilter file contributed.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ParsedLine {
    /// A lexed range row: `start`/`end` are host-order numeric IPv4 addresses
    /// (aMule `ScanIP` builds the same), `level` the access level (0 for the
    /// AntiP2P form).
    Range { start: u32, end: u32, level: u8 },
    /// A comment or blank line — contributes nothing, counted nowhere.
    Ignored,
    /// aMule `yyip_Bad`: counted, discarded, never fails the load.
    Malformed,
}

/// `[ \t\r]*` — the lexer's `WS` class (`\r` included, so CRLF files parse).
fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while matches!(bytes.get(i), Some(b' ' | b'\t' | b'\r')) {
        i += 1;
    }
    i
}

/// The lexer's `{NO}`: 1-3 digits. `None` = shape mismatch (zero or more than
/// three digits — in this grammar the byte after `{NO}` is never a digit, so
/// consuming the whole digit run is equivalent to flex's backtracking).
/// `Some((None, _))` = shape matched but the value exceeds 255, which aMule's
/// `ScanInt` turns into a malformed line rather than a shape miss.
fn scan_no(bytes: &[u8], start: usize) -> Option<(Option<u8>, usize)> {
    let mut end = start;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    let digits = end - start;
    if digits == 0 || digits > 3 {
        return None;
    }
    let mut value: u32 = 0;
    for &b in &bytes[start..end] {
        value = value * 10 + u32::from(b - b'0');
    }
    Some((u8::try_from(value).ok(), end))
}

/// The lexer's `{IP}`: `NO.NO.NO.NO`, yielding the host-order numeric address
/// exactly as aMule's `ScanIP` composes it (`ip = (ip << 8) | octet`).
/// `Some((None, _))` = shape matched, an octet exceeded 255 (malformed line).
fn scan_ip(bytes: &[u8], start: usize) -> Option<(Option<u32>, usize)> {
    let mut ip: u32 = 0;
    let mut valid = true;
    let mut pos = start;
    for octet_index in 0..4 {
        if octet_index > 0 {
            if bytes.get(pos) != Some(&b'.') {
                return None;
            }
            pos += 1;
        }
        let (octet, next) = scan_no(bytes, pos)?;
        match octet {
            Some(octet) => ip = (ip << 8) | u32::from(octet),
            None => valid = false,
        }
        pos = next;
    }
    Some((valid.then_some(ip), pos))
}

/// The PeerGuardian rule: `^{WS}{IP}{WS}-{WS}{IP}{WS},{WS}{NO}{WS},.*` —
/// everything after the second comma is the description, which aMule keeps
/// only in debug builds and rmule discards.
fn parse_peer_guardian(bytes: &[u8]) -> Option<ParsedLine> {
    let i = skip_ws(bytes, 0);
    let (start, i) = scan_ip(bytes, i)?;
    let i = skip_ws(bytes, i);
    if bytes.get(i) != Some(&b'-') {
        return None;
    }
    let (end, i) = scan_ip(bytes, skip_ws(bytes, i + 1))?;
    let i = skip_ws(bytes, i);
    if bytes.get(i) != Some(&b',') {
        return None;
    }
    let (level, i) = scan_no(bytes, skip_ws(bytes, i + 1))?;
    let i = skip_ws(bytes, i);
    if bytes.get(i) != Some(&b',') {
        return None;
    }
    Some(match (start, end, level) {
        (Some(start), Some(end), Some(level)) => ParsedLine::Range { start, end, level },
        _ => ParsedLine::Malformed,
    })
}

/// The AntiP2P rule: `^.*:{WS}{IP}{WS}-{WS}{IP}{WS}`. Flex's longest match
/// lands on the *rightmost* colon whose tail matches the range shape (the
/// shape itself contains no colon, so a later colon's match always ends
/// later); bytes after the matched shape are swallowed silently, and a
/// shape-matched tail with an octet over 255 is malformed without retrying an
/// earlier colon (the flex action runs on the committed match). The level is
/// the lexer's hardcoded 0 — an AntiP2P row blocks at every threshold.
fn parse_anti_p2p(bytes: &[u8]) -> Option<ParsedLine> {
    for colon in (0..bytes.len()).rev().filter(|&i| bytes[i] == b':') {
        let i = skip_ws(bytes, colon + 1);
        let Some((start, i)) = scan_ip(bytes, i) else {
            continue;
        };
        let i = skip_ws(bytes, i);
        if bytes.get(i) != Some(&b'-') {
            continue;
        }
        let Some((end, _)) = scan_ip(bytes, skip_ws(bytes, i + 1)) else {
            continue;
        };
        return Some(match (start, end) {
            (Some(start), Some(end)) => ParsedLine::Range {
                start,
                end,
                level: 0,
            },
            _ => ParsedLine::Malformed,
        });
    }
    None
}

/// Classify one line exactly as the flex scanner does. Rule order matters and
/// mirrors the resolved flex precedence: PeerGuardian (listed first, and its
/// `.*` tail always spans the whole line, so it wins every tie), then comment
/// (whose whole-line `.*` outmatches any AntiP2P prefix on a `#` line), then
/// AntiP2P, then blank; anything left is the `^.` bad-line rule.
pub(super) fn parse_line(line: &[u8]) -> ParsedLine {
    if let Some(parsed) = parse_peer_guardian(line) {
        return parsed;
    }
    let after_ws = skip_ws(line, 0);
    if after_ws == line.len() {
        return ParsedLine::Ignored;
    }
    if line[after_ws] == b'#' {
        return ParsedLine::Ignored;
    }
    if let Some(parsed) = parse_anti_p2p(line) {
        return parsed;
    }
    ParsedLine::Malformed
}
