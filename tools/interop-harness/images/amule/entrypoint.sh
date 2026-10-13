#!/bin/sh
# Scenario entrypoint for a harness aMule body.
#
# Shared, not copied: the `amule-kno` image carries this same file (its build
# context is the parent `images/` directory, see that image's Dockerfile) and
# hands over to it whenever AMULE_SCENARIO_MODE is set, so a Seeded Bootstrap
# knob added here reaches both counterparties. Everything below must therefore
# stay portable across Ubuntu 24.04 (stock 2.3.3) and Debian trixie (kno's
# fork): POSIX sh, coreutils, getent, awk, perl-base, amulecmd.
set -eu

# Selected scenario mode. Default preserves the original eD2k-server behavior so
# existing interop scenarios are unchanged.
AMULE_SCENARIO_MODE="${AMULE_SCENARIO_MODE:-ed2k-server}"

CONFIG_DIR="${AMULE_CONFIG_DIR:-/root/.aMule}"
INCOMING_DIR="${AMULE_SHARED_DIR:-/incoming}"
TEMP_DIR="${AMULE_TEMP_DIR:-/tmp/amule-temp}"
EC_PASSWORD="${AMULE_EC_PASSWORD:-rmule}"
EC_PASSWORD_MD5="${AMULE_EC_PASSWORD_MD5:-6a30721f062fac4590247952165a57bc}"
TCP_PORT="${AMULE_TCP_PORT:-4662}"
UDP_PORT="${AMULE_UDP_PORT:-4672}"
EC_PORT="${AMULE_EC_PORT:-4712}"

PRINT_CONFIG=0
if [ "${1:-}" = "--print-config" ]; then
    PRINT_CONFIG=1
fi

mkdir -p "$CONFIG_DIR" "$INCOMING_DIR" "$TEMP_DIR"

# LAN default-route knob (ADR-0092). A counterparty placed on a NAT gateway's
# LAN bridge has no egress of its own — the bridge is created with
# `enable_ip_masquerade=false` — so its way out is a default route through the
# gateway. Repointing a route is a *network condition*, the same legal Bench
# Variant Env class as `AMULE_FORCE_LOW_ID`'s inbound DROP,
# and changes nothing about how the client speaks the protocol.
if [ -n "${AMULE_DEFAULT_ROUTE_VIA:-}" ]; then
    ip route replace default via "$AMULE_DEFAULT_ROUTE_VIA"
    echo "rmule-amule-default-route via=$AMULE_DEFAULT_ROUTE_VIA"
fi
if [ -n "${AMULE_DEFAULT_ROUTE_VIA6:-}" ]; then
    ip -6 route replace default via "$AMULE_DEFAULT_ROUTE_VIA6"
    echo "rmule-amule-default-route6 via=$AMULE_DEFAULT_ROUTE_VIA6"
fi

# Fresh-identity variant: wipe the binary identity + the
# credit/recheck state so the daemon mints new values on start. This clears any
# stale identity a reused config dir would carry (a no-op on the harness's
# default ephemeral config). amule.conf (config, not identity) is preserved; a
# seeded preferencesKad.dat, if any, is copied in later and still wins.
if [ "${AMULE_FRESH_IDENTITY:-0}" = "1" ]; then
    rm -f "$CONFIG_DIR/preferences.dat" "$CONFIG_DIR/cryptkey.dat" \
        "$CONFIG_DIR/preferencesKad.dat" "$CONFIG_DIR/clients.met" \
        "$CONFIG_DIR/known.met"
    echo "rmule-amule-fresh-identity-wiped"
fi

if [ ! -f "$CONFIG_DIR/amule.conf" ]; then
    timeout 10s amuled -c "$CONFIG_DIR" -o >/tmp/amule-bootstrap.log 2>&1 || true
fi

set_config() {
    key="$1"
    value="$2"
    file="$CONFIG_DIR/amule.conf"
    if grep -q "^${key}=" "$file"; then
        # Escape sed-replacement metacharacters (`\`, `&`, the `|` delimiter)
        # so an env-supplied value lands verbatim instead of corrupting the
        # substitution.
        escaped=$(printf '%s' "$value" | sed 's/[\\&|]/\\&/g')
        sed -i "s|^${key}=.*|${key}=${escaped}|" "$file"
    else
        printf '%s=%s\n' "$key" "$value" >>"$file"
    fi
}

# aMule has no `UserHash` key: it reads its identity hash from
# `preferences.dat` (1-byte `PREFFILE_VERSION` + 16 raw bytes), never from
# `amule.conf` (`CPreferences::CPreferences()`/`Save()`, `Preferences.cpp`
# kno `ab483654`). `set_config UserHash ...` used to write a key aMule never
# reads back, so the pin had no effect. This writes the file
# aMule actually loads.
#
# `CPreferences::CPreferences()` also stamps two identity bytes
# unconditionally after loading, "mark hash as an eMule-type hash"
# (`Preferences.cpp:1081-1082`): byte 5 -> `0x0E`, byte 14 -> `0x6F`. The
# hello aMule sends therefore carries this pin with those two bytes already
# overwritten, whatever value is passed here.
#
# dash's `printf` builtin has no `\xHH` escape, only octal `\NNN`, so each
# byte is converted through its decimal form (`printf '%d' "0x$byte"`) rather
# than built as a literal hex escape.
write_user_hash() {
    hash_hex="$1"
    pref_file="$CONFIG_DIR/preferences.dat"
    : >"$pref_file"
    printf '\024' >>"$pref_file" # PREFFILE_VERSION (0x14); aMule ignores it on read
    pairs=$(printf '%s' "$hash_hex" | sed 's/\(..\)/\1 /g')
    for byte in $pairs; do
        dec=$(printf '%d' "0x$byte")
        printf "$(printf '\\%03o' "$dec")" >>"$pref_file"
    done
}

# Copy one harness-written **Seeded Bootstrap** file into the config dir. An
# unset variable is a no-op; a variable naming a missing file fails the start,
# because a seed that silently did not land boots a random Kad ID or an empty
# routing table and the flow would measure that instead.
install_seed() {
    seed_var="$1"
    seed_src="$2"
    seed_dest="$3"
    if [ -z "$seed_src" ]; then
        return 0
    fi
    if [ ! -f "$seed_src" ]; then
        echo "${seed_var}=${seed_src} does not exist" >&2
        exit 1
    fi
    cp "$seed_src" "$CONFIG_DIR/$seed_dest"
}

# Unlock the Kad debug categories a DEBUG-built aMule's AMULE_KAD_VERBOSE=1
# promises. VerboseDebug alone is NOT enough: CLogger::IsEnabled
# is `cat.IsEnabled() && thePrefs::GetVerbose()` (Logger.cpp) — the AND, not
# just the global flag — and CPreferences::LoadAllItems only turns a
# category's own IsEnabled() on from a `/Debug/Cat_<Name>` config entry
# (Preferences.cpp, #ifdef __DEBUG__), a key a stock config never carries.
# The names below are `g_debugcats`' exact display strings (Logger.cpp) for
# every Kad-named category; there is no separate "logKadPublish" — the
# CSharedFileList::Publish gate is reasoned about under
# logKadSearch (the NODECOMPLETE self-lookup that flips GetPublish()) and
# logKadPrefs (the external-port / firewall verdicts feeding it).
#
# Written into a `[Debug]` section appended at the END of amule.conf, after
# every other `set_config` call in the caller — `/Debug/Cat_...` must land
# under `[Debug]`, not whatever section happens to precede it, and this is
# the only way the flat `key=value` file format keeps that grouping correct.
#
# Inert on a RELEASE build: the entire read is compiled out under
# `#ifdef __DEBUG__` (Logger.h), so writing these keys unconditionally changes
# nothing for the default (non-debug) image.
enable_kad_debug_categories() {
    file="$CONFIG_DIR/amule.conf"
    if ! grep -q '^\[Debug\]$' "$file"; then
        printf '[Debug]\n' >>"$file"
    fi
    cats="Kademlia Search|Kademlia Routing|Kademlia Indexing|Kademlia Main Thread"
    cats="$cats|Kademlia Preferences|Client Kademlia UDP|Kademlia UDP Firewall Tester"
    cats="$cats|Kademlia Packet Tracking|Kademlia Entry Tracking"
    # AMULE_DEBUG_PEER_CATEGORIES=1 adds the peer-TCP trail: the
    # `Remote Client: OP_CALLBACK from` / `Local Client: OP_CALLBACK to` lines
    # a buddy relay writes, and the `caused an error ... Disconnecting client!`
    # line a packet the session refuses writes. Off by default, so every flow
    # that does not ask keeps its Kad-only logfile.
    if [ "${AMULE_DEBUG_PEER_CATEGORIES:-0}" = "1" ]; then
        cats="$cats|ED2k Client|Local Client Protocol|Remote Client Protocol"
        cats="$cats|Packet Parsing Errors"
    fi
    # AMULE_DEBUG_SOURCE_CATEGORIES=1 adds what a source's fate is decided
    # by: the download queue and part files (a source added, attached to a
    # client already known, dropped) and the Asio socket layer, whose read
    # path is the only place a peer's close is noticed. Implies the peer
    # set above. Asio is loud (a line per read); off by default.
    if [ "${AMULE_DEBUG_SOURCE_CATEGORIES:-0}" = "1" ]; then
        cats="$cats|ED2k Client|Local Client Protocol|Remote Client Protocol"
        cats="$cats|Packet Parsing Errors|DownloadQueue|PartFiles|Asio Sockets"
    fi
    old_ifs=$IFS
    IFS='|'
    for cat in $cats; do
        IFS=$old_ifs
        # wxFileConfig escapes an internal space in a key with a backslash
        # when IT writes one (observed straight off a debug binary's own
        # bootstrap SaveAllItems: `Cat_Kademlia\ Search=0`, not
        # `Cat_Kademlia Search=0`) — match that exact on-disk form, or the
        # lookup below misses an already-written key and the fallback
        # (needed only pre-bootstrap, e.g. the release image, which never
        # writes this section at all) would otherwise have to guess where
        # `[Debug]` ends. `grep -F` and perl's `\Q...\E` treat the key as a
        # literal string end to end: the naive `grep`/`sed` BRE pattern this
        # replaced silently read a bare `\ ` as "one space", not "a literal
        # backslash then a space" — it never matched the on-disk key, so
        # every lookup fell through to the fallback and appended a stray,
        # unescaped duplicate that landed in whatever section came last
        # instead of `[Debug]`, and the category never actually enabled.
        key="Cat_$(printf '%s' "$cat" | sed 's/ /\\ /g')"
        if grep -qF -- "${key}=" "$file"; then
            perl -i -pe "s/^\Q${key}\E=.*/\Q${key}\E=1/" "$file"
        else
            # Insert right after the `[Debug]` header rather than at EOF, so
            # a fresh key lands under `[Debug]` even when that section is not
            # the file's last.
            perl -i -pe "s/^\[Debug\]\$/[Debug]\n\Q${key}\E=1/" "$file"
        fi
        IFS='|'
    done
    IFS=$old_ifs
    echo "rmule-amule-kad-debug-categories-enabled"
}

dump_diagnostics() {
    # Collection is best-effort — a missing logfile or a dead EC socket must not
    # abort the caller. `set -e` is restored on the way out so the rest of the
    # script keeps failing loudly.
    set +e
    for command in "Status" "Show log" "Show dl" "Show ul" "Show shared" "Statistics"; do
        printf '===== amulecmd %s =====\n' "$command"
        amulecmd -v -P "$EC_PASSWORD" -c "$command" 2>&1
    done
    printf '===== %s/logfile =====\n' "$CONFIG_DIR"
    sed -n '1,1000p' "$CONFIG_DIR/logfile" 2>&1
    printf '===== logging-related config =====\n'
    grep -niE 'log|debug|verbose|upload|queue|client|message|trace|packet|filter|kad|server' "$CONFIG_DIR/amule.conf" 2>&1
    set -e
}

# Seed a minimal one-server server.met so aMule loads the eserver into m_servers
# at CServerList::Init (LoadServerMet), enriches it from the live connection, and
# re-authors the full record via SaveServerMet on a clean Shutdown
# (AMULE_PERSIST_SERVERLIST=1 — flow H server.met golden).
#
# WHY a seed is needed: amulecmd's `Add ed2k://|server|IP|PORT|/` routes to
# EC_OP_ADD_LINK -> downloadqueue->AddLink (the download queue), NOT the server
# list, and `Connect IP:PORT` opens a socket without adding to m_servers — so
# without a seeded (or server-pushed) entry the list is empty at shutdown and
# SaveServerMet writes 0 servers. The seed is a minimal bootstrap INPUT; the
# harvested golden is aMule's OWN SaveServerMet writer output (never hand-crafted
# bytes). server.met layout (CServerList::LoadServerMet / SaveServerMet, LE):
# [u8 0xE0 magic][u32 count][per server: 4 ip octets a.b.c.d][u16 port][u32
# tagcount]. A zero-tag entry is the smallest LoadServerMet accepts; the live
# connection supplies the name/description/user+file counts aMule then persists.
seed_server_met() {
    seed_ip="$1"
    seed_port="$2"
    seed_out="$3"
    old_ifs="$IFS"
    IFS='.'
    # shellcheck disable=SC2086
    set -- $seed_ip
    IFS="$old_ifs"
    o1="$1"; o2="$2"; o3="$3"; o4="$4"
    plo=$(( seed_port & 255 ))
    phi=$(( (seed_port >> 8) & 255 ))
    {
        printf '\340\001\000\000\000'
        printf "\\$(printf '%03o' "$o1")\\$(printf '%03o' "$o2")\\$(printf '%03o' "$o3")\\$(printf '%03o' "$o4")"
        printf "\\$(printf '%03o' "$plo")\\$(printf '%03o' "$phi")"
        printf '\000\000\000\000'
    } >"$seed_out"
}

# ---------------------------------------------------------------------------
# eD2k server mode (default, unchanged behavior).
# ---------------------------------------------------------------------------
run_ed2k_server_mode() {
    SERVER_HOST="${ED2K_SERVER_HOST:?ED2K_SERVER_HOST is required}"
    SERVER_PORT="${ED2K_SERVER_PORT:-4661}"
    DOWNLOAD_LINK="${AMULE_DOWNLOAD_LINK:-}"
    EXPECTED_FILE_NAME="${AMULE_EXPECTED_FILE_NAME:-shared.bin}"
    EXPECTED_SIZE="${AMULE_EXPECTED_SIZE:-}"

    set_config Port "$TCP_PORT"
    set_config UDPPort "$UDP_PORT"
    set_config Autoconnect 0
    set_config ConnectToKad 0
    set_config ConnectToED2K 1
    set_config Serverlist 0
    set_config AutoConnectStaticOnly 1
    set_config AddServerListFromServer 0
    set_config AddServerListFromClient 0
    set_config Ed2kServersUrl ""
    set_config SafeServerConnect 0
    set_config FilterLanIPs 0
    set_config ParanoidFiltering 0
    set_config IpFilterClients 0
    set_config IpFilterServers 0
    set_config IncomingDir "$INCOMING_DIR"
    set_config TempDir "$TEMP_DIR"
    set_config AcceptExternalConnections 1
    set_config ECAddress 127.0.0.1
    set_config ECPort "$EC_PORT"
    set_config ECPassword "$EC_PASSWORD_MD5"
    # Optional download-rate cap (flow I): throttle so a multi-part download from
    # the staged sources establishes them but never completes (and drops them)
    # during the capture window. `0`/unset leaves aMule's default (unlimited).
    if [ "${AMULE_MAX_DOWNLOAD:-0}" != "0" ]; then
        set_config MaxDownload "$AMULE_MAX_DOWNLOAD"
    fi
    # Optional upload-rate cap (peer-UDP reask EMIT): under 10 KB/s aMule keeps
    # MIN_UP_CLIENTS_ALLOWED = 2 upload slots (UploadQueue.cpp:303-313), so a
    # flow that wants a requester queued holds both. `0`/unset leaves aMule's
    # default (unlimited).
    if [ "${AMULE_MAX_UPLOAD:-0}" != "0" ]; then
        set_config MaxUpload "$AMULE_MAX_UPLOAD"
    fi
    # Optional upload-queue size pref (peer-UDP 0x93 capture, ADR-0057):
    # ClientUDPSocket.cpp answers an UNKNOWN sender's reask for a SHARED file
    # with OP_QUEUEFULL iff (waiting + 50) > GetQueueSize() = QueueSizePref*100,
    # so `0` makes the near-full branch unconditional on a quiet bench. A legal
    # user preference, not a patch; unset leaves aMule's default (50 -> 5000).
    if [ -n "${AMULE_QUEUE_SIZE_PREF:-}" ]; then
        set_config QueueSizePref "$AMULE_QUEUE_SIZE_PREF"
    fi
    # Optional protocol-obfuscation knobs (ADR-0042). The peer-UDP crypt capture
    # runs its counterparties in THIS mode, not direct-peer, so the
    # documented recipe's env has to be honoured here too — aMule obfuscates its
    # outgoing peer datagrams only under IsCryptLayerRequested (plus a public IP).
    # Each is applied only when the env var is set; unset leaves aMule's stock
    # defaults (Supported on, Requested/Required off) exactly as before.
    if [ -n "${AMULE_CRYPT_SUPPORTED:-}" ]; then
        set_config IsClientCryptLayerSupported "$AMULE_CRYPT_SUPPORTED"
    fi
    if [ -n "${AMULE_CRYPT_REQUESTED:-}" ]; then
        set_config IsCryptLayerRequested "$AMULE_CRYPT_REQUESTED"
    fi
    if [ -n "${AMULE_CRYPT_REQUIRED:-}" ]; then
        set_config IsClientCryptLayerRequired "$AMULE_CRYPT_REQUIRED"
    fi

    if [ "$PRINT_CONFIG" -eq 1 ]; then
        print_selected_config
        return 0
    fi

    # IPv4 only: an eD2k server address is 32 bits, and amulecmd's `Connect`
    # refuses anything but `a.b.c.d:port`. On a dual-stack bench network
    # `getent hosts` answers with the name's IPv6 first.
    SERVER_ADDR="$(getent ahostsv4 "$SERVER_HOST" | awk '{ print $1; exit }')"
    if [ -z "$SERVER_ADDR" ]; then
        echo "could not resolve ED2K_SERVER_HOST=${SERVER_HOST}" >&2
        exit 1
    fi

    printf '%s\n' "$INCOMING_DIR" >"$CONFIG_DIR/shareddir.dat"

    # Server-list-persisting variant (flow H golden): seed the eserver into
    # m_servers before amuled starts so a clean Shutdown re-authors a non-empty
    # server.met. Default off keeps every existing ed2k-server scenario unchanged.
    if [ "${AMULE_PERSIST_SERVERLIST:-0}" = "1" ]; then
        seed_server_met "$SERVER_ADDR" "$SERVER_PORT" "$CONFIG_DIR/server.met"
        echo "rmule-amule-serverlist-seeded ip=${SERVER_ADDR} port=${SERVER_PORT} bytes=$(wc -c <"$CONFIG_DIR/server.met")"
    fi

    # Verbose debug logging (diagnostics only): surfaces the download-queue /
    # source handling (why a link-supplied source is added, filtered, or never
    # dialed) in the logfile. Off by default so the passing forward scenarios
    # stay quiet; the reverse-download scenario (rmule serves) turns it on so a
    # RED run records aMule's source decision. Behavior is unchanged — only the
    # AddDebugLogLineN output is unlocked.
    if [ "${AMULE_VERBOSE:-0}" = "1" ]; then
        set_config VerboseDebug 1
        set_config VerboseDebugLogfile 1
    fi
    # A DEBUG-built aMule logs its verdict on a peer's Secure User
    # Identification (`'<nick>' has passed the secure identification`,
    # BaseClient.cpp) only under the `ED2k Client` category, which
    # enable_kad_debug_categories unlocks with AMULE_DEBUG_PEER_CATEGORIES=1
    # (the reverse flow reads aMule's verdict on rmule's SUI).
    if [ "${AMULE_DEBUG_PEER_CATEGORIES:-0}" = "1" ] \
        || [ "${AMULE_DEBUG_SOURCE_CATEGORIES:-0}" = "1" ]; then
        set_config VerboseDebug 1
        set_config VerboseDebugLogfile 1
        enable_kad_debug_categories
    fi

    # Force Low-ID (ADR-0039 callback interop): drop inbound TCP on the aMule
    # listen port so the server's reachability check fails and it assigns a Low
    # ID. Established/related flows are accepted first, so the aMule's own
    # outbound server connection, the server's callback relay that rides it, and
    # the aMule -> rmule dial-back all still work. Requires --cap-add NET_ADMIN.
    if [ "${AMULE_FORCE_LOW_ID:-0}" = "1" ]; then
        iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -p tcp --dport "$TCP_PORT" -j DROP
        echo "rmule-amule-low-id-firewall-installed"
    fi

    amuled -c "$CONFIG_DIR" -o &
    amuled_pid="$!"
    trap 'kill "$amuled_pid" 2>/dev/null || true; wait "$amuled_pid" 2>/dev/null || true' INT TERM

    for _ in $(seq 1 100); do
        amulecmd -P "$EC_PASSWORD" -c Status >/tmp/amule-status.log 2>&1 || true
        if grep -q 'Succeeded! Connection established' /tmp/amule-status.log; then
            break
        fi
        sleep 0.2
    done

    if ! grep -q 'Succeeded! Connection established' /tmp/amule-status.log; then
        echo "aMule external connection did not become ready" >&2
        cat /tmp/amule-status.log >&2 || true
        exit 1
    fi

    amulecmd -P "$EC_PASSWORD" -c "Add ed2k://|server|${SERVER_ADDR}|${SERVER_PORT}|/" >/tmp/amule-add-server.log 2>&1
    amulecmd -P "$EC_PASSWORD" -c "Connect ${SERVER_ADDR}:${SERVER_PORT}" >/tmp/amule-connect.log 2>&1

    for _ in $(seq 1 150); do
        amulecmd -P "$EC_PASSWORD" -c Status >/tmp/amule-status.log 2>&1 || true
        if grep -q 'eD2k: Connected' /tmp/amule-status.log; then
            if ! grep -q "${SERVER_ADDR}:${SERVER_PORT}" /tmp/amule-status.log; then
                echo "aMule connected to a non-local server" >&2
                cat /tmp/amule-status.log >&2
                exit 1
            fi
            amulecmd -P "$EC_PASSWORD" -c 'Show shared' >/tmp/amule-shared.log 2>&1 || true
            cat /tmp/amule-status.log
            cat /tmp/amule-shared.log
            echo "rmule-amule-ready"
            if [ -n "$DOWNLOAD_LINK" ]; then
                amulecmd -P "$EC_PASSWORD" -c "Add ${DOWNLOAD_LINK}" >/tmp/amule-add-download.log 2>&1
                # Download-hold mode: aMule downloads the hash so it
                # get-sources from the server and learns the staged registrant
                # sources, but the sources never serve data, so completion never
                # arrives. Instead of polling for a completed file, settle so the
                # source list fills, report ready, dump the source view, and idle
                # — the harness dials this aMule and asks it for those sources
                # (its packed OP_ANSWERSOURCES is the capture target).
                if [ "${AMULE_DOWNLOAD_NO_WAIT:-0}" = "1" ]; then
                    for _ in $(seq 1 "${AMULE_DOWNLOAD_SETTLE:-25}"); do
                        sleep 1
                    done
                    amulecmd -P "$EC_PASSWORD" -c 'Show dl' >/tmp/amule-downloads.log 2>&1 || true
                    cat /tmp/amule-downloads.log
                    echo "rmule-amule-download-sources-ready"
                    wait "$amuled_pid"
                    exit $?
                fi
                for _ in $(seq 1 300); do
                    amulecmd -P "$EC_PASSWORD" -c 'Show dl' >/tmp/amule-downloads.log 2>&1 || true
                    target="${INCOMING_DIR}/${EXPECTED_FILE_NAME}"
                    if [ -f "$target" ]; then
                        if [ -z "$EXPECTED_SIZE" ] || [ "$(wc -c <"$target")" = "$EXPECTED_SIZE" ]; then
                            cat /tmp/amule-downloads.log
                            # The SUI trail from the logfile: amuled's own
                            # stdout is cut when this script exits, so the
                            # verdict line would otherwise be lost.
                            if [ "${AMULE_DEBUG_PEER_CATEGORIES:-0}" = "1" ]; then
                                sleep 2
                                grep -F -e 'secure identification' -e 'OP_SIGNATURE' \
                                    -e 'OP_PUBLICKEY' -e 'OP_SECIDENTSTATE' "$CONFIG_DIR/logfile" \
                                    | sed 's/^/rmule-amule-sui: /' || true
                            fi
                            echo "rmule-amule-download-complete"
                            exit 0
                        fi
                    fi
                    sleep 1
                done
                echo "aMule did not complete ${DOWNLOAD_LINK}" >&2
                cat /tmp/amule-add-download.log >&2 || true
                cat /tmp/amule-downloads.log >&2 || true
                dump_diagnostics >&2
                exit 1
            fi
            wait "$amuled_pid"
            exit $?
        fi
        sleep 1
    done

    echo "aMule did not connect to ${SERVER_ADDR}:${SERVER_PORT}" >&2
    cat /tmp/amule-add-server.log >&2 || true
    cat /tmp/amule-connect.log >&2 || true
    cat /tmp/amule-status.log >&2 || true
    exit 1
}

# ---------------------------------------------------------------------------
# eD2k-server + Kad mode (flow G): the ed2k→Kad handoff counterparty.
# Unlike run_ed2k_server_mode (which forces ConnectToKad=0), this connects to the
# eD2k server AND runs Kad, so the peer hello it sends rmule carries a live
# CT_EMULE_UDPPORTS Kad half. A running-but-unjoined aMule advertises no Kad port
# (the port is gated on Kad being *connected*), so an optional private nodes.dat
# (AMULE_KAD_NODES_DAT) or an external seed dialing this node's UDP port brings
# Kad to "Connected" first; set AMULE_KAD_WAIT_CONNECTED=1 to block readiness on it.
# ---------------------------------------------------------------------------
run_ed2k_server_kad_mode() {
    SERVER_HOST="${ED2K_SERVER_HOST:?ED2K_SERVER_HOST is required}"
    SERVER_PORT="${ED2K_SERVER_PORT:-4661}"
    KAD_NODES_DAT="${AMULE_KAD_NODES_DAT:-}"
    KAD_PREFS_DAT="${AMULE_KAD_PREFS_DAT:-}"
    USER_HASH="${AMULE_USER_HASH:-}"

    set_config Port "$TCP_PORT"
    set_config UDPPort "$UDP_PORT"
    set_config Autoconnect 0
    set_config ConnectToKad 1
    set_config ConnectToED2K 1
    set_config Serverlist 0
    set_config AutoConnectStaticOnly 1
    set_config AddServerListFromServer 0
    set_config AddServerListFromClient 0
    set_config Ed2kServersUrl ""
    set_config KadNodesUrl ""
    set_config SafeServerConnect 0
    # Config A: the fake-public /24 already passes IsGoodIPPort, so keep the node
    # off LAN mode (default 0; the handoff scenario passes 1).
    set_config FilterLanIPs "${AMULE_KAD_FILTER_LAN_IPS:-0}"
    set_config ParanoidFiltering 0
    set_config IpFilterClients 0
    set_config IpFilterServers 0
    set_config IncomingDir "$INCOMING_DIR"
    set_config TempDir "$TEMP_DIR"
    set_config AcceptExternalConnections 1
    set_config ECAddress 127.0.0.1
    set_config ECPort "$EC_PORT"
    set_config ECPassword "$EC_PASSWORD_MD5"
    # Plaintext Kad (no UDP obfuscation) so the handoff bootstrap is a bare 0xE4.
    set_config IsClientCryptLayerSupported 0
    set_config IsCryptLayerRequested 0
    set_config IsClientCryptLayerRequired 0
    # Non-zero rates so the upload throttler flushes queued Kad control packets.
    set_config MaxUpload "${AMULE_MAX_UPLOAD:-1000}"
    set_config MaxDownload 1000
    if [ -n "$USER_HASH" ]; then
        write_user_hash "$USER_HASH"
    fi

    if [ "$PRINT_CONFIG" -eq 1 ]; then
        print_selected_config
        return 0
    fi

    # IPv4 only: an eD2k server address is 32 bits, and amulecmd's `Connect`
    # refuses anything but `a.b.c.d:port`. On a dual-stack bench network
    # `getent hosts` answers with the name's IPv6 first.
    SERVER_ADDR="$(getent ahostsv4 "$SERVER_HOST" | awk '{ print $1; exit }')"
    if [ -z "$SERVER_ADDR" ]; then
        echo "could not resolve ED2K_SERVER_HOST=${SERVER_HOST}" >&2
        exit 1
    fi

    printf '%s\n' "$INCOMING_DIR" >"$CONFIG_DIR/shareddir.dat"

    # Optional private routing seed so Kad can reach "Connected" without an
    # external dialer, and an optional pinned Kad ID so the node sits at a
    # known keyspace point — a storer for one key, a publisher far from it.
    install_seed AMULE_KAD_NODES_DAT "$KAD_NODES_DAT" nodes.dat
    install_seed AMULE_KAD_PREFS_DAT "$KAD_PREFS_DAT" preferencesKad.dat

    if [ "${AMULE_KAD_VERBOSE:-0}" = "1" ]; then
        set_config VerboseDebug 1
        set_config VerboseDebugLogfile 1
        enable_kad_debug_categories
    fi

    amuled -c "$CONFIG_DIR" -o &
    amuled_pid="$!"
    trap 'kill "$amuled_pid" 2>/dev/null || true; wait "$amuled_pid" 2>/dev/null || true' INT TERM

    for _ in $(seq 1 100); do
        amulecmd -P "$EC_PASSWORD" -c Status >/tmp/amule-status.log 2>&1 || true
        if grep -q 'Succeeded! Connection established' /tmp/amule-status.log; then
            break
        fi
        sleep 0.2
    done

    if ! grep -q 'Succeeded! Connection established' /tmp/amule-status.log; then
        echo "aMule external connection did not become ready" >&2
        cat /tmp/amule-status.log >&2 || true
        exit 1
    fi

    amulecmd -P "$EC_PASSWORD" -c "Add ed2k://|server|${SERVER_ADDR}|${SERVER_PORT}|/" >/tmp/amule-add-server.log 2>&1
    amulecmd -P "$EC_PASSWORD" -c "Connect ${SERVER_ADDR}:${SERVER_PORT}" >/tmp/amule-connect.log 2>&1
    amulecmd -P "$EC_PASSWORD" -c "Connect Kad" >/tmp/amule-kad-connect.log 2>&1 || true

    ed2k_ready=0
    for _ in $(seq 1 150); do
        amulecmd -P "$EC_PASSWORD" -c Status >/tmp/amule-status.log 2>&1 || true
        if grep -q 'eD2k: Connected' /tmp/amule-status.log; then
            ed2k_ready=1
            break
        fi
        sleep 1
    done
    if [ "$ed2k_ready" -ne 1 ]; then
        echo "aMule did not connect to ${SERVER_ADDR}:${SERVER_PORT}" >&2
        cat /tmp/amule-connect.log >&2 || true
        cat /tmp/amule-status.log >&2 || true
        exit 1
    fi

    # Optionally block readiness until Kad reports Connected (the emit gate for
    # the hello's CT_EMULE_UDPPORTS Kad port). A lone node with no seed/dialer
    # stays "Not connected", so this defaults off — the harness seeds it.
    if [ "${AMULE_KAD_WAIT_CONNECTED:-0}" = "1" ]; then
        for _ in $(seq 1 "${AMULE_KAD_READY_TIMEOUT:-120}"); do
            amulecmd -P "$EC_PASSWORD" -c Status >/tmp/amule-status.log 2>&1 || true
            if grep -qE 'Kad: Connected' /tmp/amule-status.log; then
                break
            fi
            sleep 1
        done
    fi

    amulecmd -P "$EC_PASSWORD" -c Status >/tmp/amule-status.log 2>&1 || true
    cat /tmp/amule-status.log
    echo "rmule-amule-server-kad-ready"

    # Optional download: with AMULE_DOWNLOAD_LINK set, the node
    # adds that ed2k file link, as a user would, so it *searches* Kad for the
    # file's sources (CPartFile::Process's Kad source search). aMule runs that
    # search once and re-asks only after KadSourceReaskTime x the search count
    # (PartFile.cpp:1864-1893), so a harness that must first get a row stored
    # sets AMULE_DOWNLOAD_GATE to a path on a mounted volume: the link is added
    # the moment that file appears, never before. Unset, nothing changes.
    DOWNLOAD_LINK="${AMULE_DOWNLOAD_LINK:-}"
    DOWNLOAD_GATE="${AMULE_DOWNLOAD_GATE:-}"
    if [ -n "$DOWNLOAD_LINK" ]; then
        if [ -n "$DOWNLOAD_GATE" ]; then
            while [ ! -e "$DOWNLOAD_GATE" ]; do
                if ! kill -0 "$amuled_pid" 2>/dev/null; then
                    wait "$amuled_pid"
                    exit $?
                fi
                sleep 1
            done
        fi
        amulecmd -P "$EC_PASSWORD" -c "Add ${DOWNLOAD_LINK}" >/tmp/amule-add-download.log 2>&1 || true
        cat /tmp/amule-add-download.log
        amulecmd -P "$EC_PASSWORD" -c 'Show dl' >/tmp/amule-downloads.log 2>&1 || true
        cat /tmp/amule-downloads.log
        echo "rmule-amule-download-added"
    fi
    wait "$amuled_pid"
}

# ---------------------------------------------------------------------------
# Direct-peer mode (ADR-0041): no eD2k server, no Kad — amuled just
# listens on its peer port with Secure User Identification enabled and shares
# /incoming. rmule dials the port directly and runs hello + SUI (+ optionally
# pulls the shared file). Both sides are High-ID on the harness LAN, so the
# broken Low-ID server image (ADR-0040) is irrelevant here.
# ---------------------------------------------------------------------------
run_direct_peer_mode() {
    set_config Port "$TCP_PORT"
    set_config UDPPort "$UDP_PORT"
    set_config Autoconnect 0
    set_config ConnectToKad 0
    set_config ConnectToED2K 0
    set_config Serverlist 0
    set_config AddServerListFromServer 0
    set_config AddServerListFromClient 0
    set_config Ed2kServersUrl ""
    set_config FilterLanIPs 0
    set_config ParanoidFiltering 0
    set_config IpFilterClients 0
    set_config IpFilterServers 0
    set_config IncomingDir "$INCOMING_DIR"
    set_config TempDir "$TEMP_DIR"
    set_config AcceptExternalConnections 1
    set_config ECAddress 127.0.0.1
    set_config ECPort "$EC_PORT"
    set_config ECPassword "$EC_PASSWORD_MD5"
    # Optional upload-rate cap (partial-share seeds): a seed reached only
    # through a link's sources, slow enough that the downloader holds a part
    # verified while others are still arriving. `0`/unset leaves aMule's
    # default (unlimited).
    if [ "${AMULE_MAX_UPLOAD:-0}" != "0" ]; then
        set_config MaxUpload "$AMULE_MAX_UPLOAD"
    fi
    # Secure User Identification on (aMule default, pinned explicitly — the
    # exchange is the whole point of this mode).
    set_config IsSecureIdentEnabled 1
    # Protocol obfuscation (ADR-0042): accept an obfuscated
    # inbound dial. Supported (aMule default) so a plaintext dial still works;
    # Requested/Required are opt-in via env. rmule learns this aMule's runtime
    # User Hash from a plaintext hello, then obfuscate-dials it — a completing
    # handshake proves rmule's 34/203 derivation is aMule-compatible. (aMule
    # generates its own User Hash and ignores a pre-set amule.conf one, so the
    # hash cannot be pinned here.)
    set_config IsClientCryptLayerSupported "${AMULE_CRYPT_SUPPORTED:-1}"
    set_config IsCryptLayerRequested "${AMULE_CRYPT_REQUESTED:-0}"
    set_config IsClientCryptLayerRequired "${AMULE_CRYPT_REQUIRED:-0}"

    if [ "$PRINT_CONFIG" -eq 1 ]; then
        print_selected_config
        return 0
    fi

    # Verbose debug logging (diagnostics only): surfaces the crypt-handshake
    # handling (why an obfuscated inbound is accepted or dropped) in the logfile.
    if [ "${AMULE_VERBOSE:-0}" = "1" ]; then
        set_config VerboseDebug 1
        set_config VerboseDebugLogfile 1
    fi

    printf '%s\n' "$INCOMING_DIR" >"$CONFIG_DIR/shareddir.dat"

    amuled -c "$CONFIG_DIR" -o &
    amuled_pid="$!"
    trap 'kill "$amuled_pid" 2>/dev/null || true; wait "$amuled_pid" 2>/dev/null || true' INT TERM

    for _ in $(seq 1 100); do
        amulecmd -P "$EC_PASSWORD" -c Status >/tmp/amule-status.log 2>&1 || true
        if grep -q 'Succeeded! Connection established' /tmp/amule-status.log; then
            break
        fi
        sleep 0.2
    done

    if ! grep -q 'Succeeded! Connection established' /tmp/amule-status.log; then
        echo "aMule external connection did not become ready" >&2
        cat /tmp/amule-status.log >&2 || true
        exit 1
    fi

    amulecmd -P "$EC_PASSWORD" -c 'Show shared' >/tmp/amule-shared.log 2>&1 || true
    cat /tmp/amule-status.log
    cat /tmp/amule-shared.log
    echo "rmule-amule-direct-peer-ready"
    wait "$amuled_pid"
}

# ---------------------------------------------------------------------------
# Private Kad node mode. Never uses public bootstrap URLs or a public
# nodes.dat: the only bootstrap input is a harness-generated private
# nodes.dat (AMULE_KAD_NODES_DAT) pointing at harness-owned containers.
# ---------------------------------------------------------------------------
run_kad_node_mode() {
    KAD_ROLE="${AMULE_KAD_ROLE:-routing}"
    KAD_NODES_DAT="${AMULE_KAD_NODES_DAT:-}"
    KAD_PREFS_DAT="${AMULE_KAD_PREFS_DAT:-}"
    USER_HASH="${AMULE_USER_HASH:-}"

    set_config Port "$TCP_PORT"
    set_config UDPPort "$UDP_PORT"
    set_config Autoconnect 0
    set_config ConnectToKad 1
    set_config ConnectToED2K 0
    set_config Serverlist 0
    set_config AddServerListFromServer 0
    set_config AddServerListFromClient 0
    set_config Ed2kServersUrl ""
    # Private-only: never fetch a public Kad nodes.dat. The only bootstrap input
    # is the harness-generated private nodes.dat copied below.
    set_config KadNodesUrl ""
    # FilterLanIPs: default 0 keeps the patched-image LAN-mesh scenarios working
    # (they need LAN mode). The stock fake-public swarm (Config A)
    # passes AMULE_KAD_FILTER_LAN_IPS=1 so the
    # node stays on its normal, non-LAN-mode paths — the documentation-range IPs
    # already pass IsGoodIPPort, so LAN mode must not engage.
    set_config FilterLanIPs "${AMULE_KAD_FILTER_LAN_IPS:-0}"
    set_config ParanoidFiltering 0
    set_config IpFilterClients 0
    set_config IpFilterServers 0
    set_config IncomingDir "$INCOMING_DIR"
    set_config TempDir "$TEMP_DIR"
    set_config AcceptExternalConnections 1
    set_config ECAddress 127.0.0.1
    set_config ECPort "$EC_PORT"
    set_config ECPassword "$EC_PASSWORD_MD5"
    # UDP obfuscation. Default OFF so captured Kad datagrams are plain 0xE4
    # (the evidence requirement for every existing Kad scenario). The
    # Kad-UDP crypt capture arms it via AMULE_KAD_CRYPT=1: aMule then obfuscates
    # its outgoing Kad datagrams toward a v6+ contact (rmule) keyed on that
    # contact's Kad ID — the exact input rmule's always-on dual-path receive
    # decrypts under MD5(our_kad_id ‖ random_key) (ADR-0046).
    if [ "${AMULE_KAD_CRYPT:-0}" = "1" ]; then
        set_config IsClientCryptLayerSupported 1
        set_config IsCryptLayerRequested 1
        set_config IsClientCryptLayerRequired 0
    else
        set_config IsClientCryptLayerSupported 0
        set_config IsCryptLayerRequested 0
        set_config IsClientCryptLayerRequired 0
    fi
    # A non-zero rate so the upload bandwidth throttler actually flushes queued
    # Kad control packets (with 0 the throttler can starve the send queue).
    set_config MaxUpload "${AMULE_MAX_UPLOAD:-1000}"
    set_config MaxDownload 1000
    # Seed a fixed, known User Hash (publisher only) so the captured source-row
    # 16-byte ID can be matched against exactly one known identity.
    if [ -n "$USER_HASH" ]; then
        write_user_hash "$USER_HASH"
    fi

    if [ "$PRINT_CONFIG" -eq 1 ]; then
        print_selected_config
        return 0
    fi

    # Seed the chosen Kad identity. aMule reads its 128-bit Kad ID from
    # preferencesKad.dat at startup (CPrefs::ReadFile) and keeps it verbatim when
    # non-zero, so a pre-seeded file fixes the node's identity deterministically.
    install_seed AMULE_KAD_PREFS_DAT "$KAD_PREFS_DAT" preferencesKad.dat

    # Seed the private routing table from the harness-owned nodes.dat only.
    install_seed AMULE_KAD_NODES_DAT "$KAD_NODES_DAT" nodes.dat

    if [ "$KAD_ROLE" = "publisher" ]; then
        printf '%s\n' "$INCOMING_DIR" >"$CONFIG_DIR/shareddir.dat"
    fi

    # Optional verbose Kad debug logging (diagnostics only). Sets the global
    # VerboseDebug/VerboseDebugLogfile keys AND the per-category
    # `/Debug/Cat_*` keys a DEBUG-built aMule's CLogger::IsEnabled also
    # requires before an AddDebugLogLineN call reaches the logfile — see
    # enable_kad_debug_categories. Both are inert on a RELEASE build.
    # `set_config`, not a blind prepend: a DEBUG binary's own throwaway
    # bootstrap (above) already ran SaveAllItems and wrote a disabled
    # VerboseDebug/VerboseDebugLogfile pair, so prepending a second copy left
    # a duplicate key — CLogger::IsEnabled read as false regardless, so the
    # unlock silently never took effect on the very image it exists for.
    if [ "${AMULE_KAD_VERBOSE:-0}" = "1" ]; then
        set_config VerboseDebug 1
        set_config VerboseDebugLogfile 1
        enable_kad_debug_categories
    fi

    # Firewalled-Kad variant (ADR-0058/ADR-0061). Drop UNSOLICITED
    # inbound on the Kad TCP and/or UDP port so this node's firewall self-check
    # fails and it reports firewalled — the precondition for the buddy/direct-
    # callback route tree. ESTABLISHED/RELATED is accepted first, so this node's
    # own outbound bootstrap to rmule (and rmule's replies on that conntrack
    # flow) still work; only a fresh connect-back / UDP probe from a third node
    # is refused. AMULE_KAD_BLOCK_TCP alone = TCP-firewalled/UDP-open (the direct
    # -callback branch); both = TCP+UDP-firewalled (buddy recruitment).
    # Requires --cap-add NET_ADMIN.
    if [ "${AMULE_KAD_BLOCK_TCP:-0}" = "1" ] || [ "${AMULE_KAD_BLOCK_UDP:-0}" = "1" ]; then
        iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        if [ "${AMULE_KAD_BLOCK_TCP:-0}" = "1" ]; then
            iptables -A INPUT -p tcp --dport "$TCP_PORT" -j DROP
            echo "rmule-amule-kad-tcp-firewall-installed port=${TCP_PORT}"
        fi
        if [ "${AMULE_KAD_BLOCK_UDP:-0}" = "1" ]; then
            iptables -A INPUT -p udp --dport "$UDP_PORT" -j DROP
            echo "rmule-amule-kad-udp-firewall-installed port=${UDP_PORT}"
        fi
    fi

    amuled -c "$CONFIG_DIR" -o &
    amuled_pid="$!"
    trap 'kill "$amuled_pid" 2>/dev/null || true; wait "$amuled_pid" 2>/dev/null || true' INT TERM

    for _ in $(seq 1 100); do
        amulecmd -P "$EC_PASSWORD" -c Status >/tmp/amule-status.log 2>&1 || true
        if grep -q 'Succeeded! Connection established' /tmp/amule-status.log; then
            break
        fi
        sleep 0.2
    done

    if ! grep -q 'Succeeded! Connection established' /tmp/amule-status.log; then
        echo "aMule external connection did not become ready" >&2
        cat /tmp/amule-status.log >&2 || true
        exit 1
    fi

    # Join only the private Kad network seeded above. No public bootstrap.
    amulecmd -P "$EC_PASSWORD" -c "Connect Kad" >/tmp/amule-kad-connect.log 2>&1 || true

    # A lone publisher/routing seed cannot reach "Kad: Connected" on its own --
    # it only connects once a requester bootstraps to it. So seeds report ready
    # as soon as Kad has started and then idle; only the requester waits for a
    # genuine connection, and even then a timeout is non-fatal so the node stays
    # alive for capture and diagnostics.
    case "$KAD_ROLE" in
        requester)
            kad_ready=0
            for _ in $(seq 1 "${AMULE_KAD_READY_TIMEOUT:-180}"); do
                amulecmd -P "$EC_PASSWORD" -c Status >/tmp/amule-status.log 2>&1 || true
                # Anchor on "Kad: Connected" so "Kad: Not connected" is not a
                # false positive.
                if grep -qE 'Kad: Connected' /tmp/amule-status.log; then
                    kad_ready=1
                    break
                fi
                sleep 1
            done
            cat /tmp/amule-status.log 2>/dev/null || true
            if [ "$kad_ready" -eq 1 ]; then
                echo "rmule-kad-requester-ready"
            else
                echo "warning: requester Kad did not reach Connected; idling for diagnostics" >&2
                dump_diagnostics >&2 || true
            fi
            # Idle: wait for the harness to inject the Source Lookup Target link,
            # then report the capture window once a source search is active.
            search_seen=0
            while kill -0 "$amuled_pid" 2>/dev/null; do
                amulecmd -P "$EC_PASSWORD" -c 'Show dl' >/tmp/amule-downloads.log 2>&1 || true
                if [ "$search_seen" -eq 0 ] && grep -qiE 'ed2k://|file_hash|Searching|Sources' /tmp/amule-downloads.log; then
                    echo "rmule-kad-source-search-active"
                    search_seen=1
                fi
                sleep 2
            done
            ;;
        *)
            # publisher / routing seed: ready once Kad is up; idle indefinitely.
            amulecmd -P "$EC_PASSWORD" -c Status >/tmp/amule-status.log 2>&1 || true
            cat /tmp/amule-status.log 2>/dev/null || true
            echo "rmule-kad-${KAD_ROLE}-ready"
            wait "$amuled_pid"
            ;;
    esac
}

print_selected_config() {
    file="$CONFIG_DIR/amule.conf"
    printf 'mode=%s\n' "$AMULE_SCENARIO_MODE"
    if [ "$AMULE_SCENARIO_MODE" = "kad-node" ]; then
        printf 'role=%s\n' "${AMULE_KAD_ROLE:-routing}"
    fi
    for key in Port UDPPort ConnectToKad ConnectToED2K ECPort; do
        value="$(grep "^${key}=" "$file" | head -n 1 | cut -d= -f2-)"
        printf '%s=%s\n' "$key" "$value"
    done
}

case "$AMULE_SCENARIO_MODE" in
    ed2k-server)
        run_ed2k_server_mode
        ;;
    ed2k-server-kad)
        run_ed2k_server_kad_mode
        ;;
    direct-peer)
        run_direct_peer_mode
        ;;
    kad-node)
        run_kad_node_mode
        ;;
    *)
        echo "unknown AMULE_SCENARIO_MODE=${AMULE_SCENARIO_MODE}" >&2
        exit 1
        ;;
esac
