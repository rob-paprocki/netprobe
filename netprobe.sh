#!/usr/bin/env bash
# =============================================================================
#  netprobe.sh - one interactive toolkit, three probes.
#
#    1  ping sweep       one pass, lists what answered and what did not
#    2  watch            continuous, announces addresses as they come alive
#    3  TCP port scan    discovery pass, then open ports per host
#
#  Everything shares one address parser, so all three accept the same
#  formats, mixed freely:
#       10.1.30.57                  single address
#       dsp.local                   hostname (resolved at parse time)
#       10.1.30.60-10.1.30.74       range
#       10.1.30.60-74               range, last octet only
#       10.1.30.0/23                CIDR
#       10.1.30.0 255.255.254.0     dotted mask
#
#  Written for bash 3.2, so stock macOS runs it with nothing installed. No
#  associative arrays, no mapfile, no GNU-only flags. If fping or nmap are
#  present it offers to hand off to them, since both are faster than anything
#  a shell loop can do.
#
#  Concurrency is xargs -P re-invoking this script, which works the same on
#  BSD and GNU userland.
# =============================================================================

set -u

SELF=$0
case $SELF in
    /*) : ;;
    *)  SELF=$PWD/${SELF#./} ;;
esac

# Re-invoke through the running bash rather than the path alone: no exec bit
# needed, and noexec mounts stop mattering.
RUNNER=${BASH:-bash}

OS=$(uname -s)
TOOLDIR=$(dirname "$SELF")
MAX_ADDRESSES=65536

# Cheap liveness probe set: an RST from any of these proves the host exists.
# That is better evidence than ICMP, which plenty of AV gear drops.
DISCOVERY_PORTS="22 23 80 135 443 445 3389 8080"

COMMON_PORTS="21 22 23 25 53 69 80 111 135 139 389 443 445 515 548 554 587 623
636 993 1433 1702 1710 1723 1935 2000 3306 3389 5000 5001 5060 5061 5900 5959
5985 5986 6970 7000 8000 8080 8443 8554 9000 41794 41795"

# Generic IT entries are well established; the ones marked (verify) are
# convenience only. Confirm them against the vendor doc for the firmware you
# are actually on. bash 3.2 has no associative arrays, hence the case.
port_label() {
    case $1 in
        21) echo FTP ;;        22) echo SSH ;;         23) echo Telnet ;;
        25) echo SMTP ;;       53) echo DNS ;;         69) echo TFTP ;;
        80) echo HTTP ;;       111) echo RPCbind ;;    135) echo MSRPC ;;
        139) echo NetBIOS-SSN ;; 389) echo LDAP ;;     443) echo HTTPS ;;
        445) echo SMB ;;       515) echo LPD ;;        548) echo AFP ;;
        554) echo RTSP ;;      587) echo SMTP-Sub ;;   623) echo IPMI/BMC ;;
        636) echo LDAPS ;;     993) echo IMAPS ;;      1433) echo MSSQL ;;
        1723) echo PPTP ;;     1935) echo RTMP ;;      2000) echo Cisco-SCCP ;;
        3306) echo MySQL ;;    3389) echo RDP ;;       5000) echo UPnP/misc ;;
        5001) echo alt-HTTP ;; 5060) echo SIP ;;       5061) echo SIP-TLS ;;
        5900) echo VNC ;;      5985) echo WinRM-HTTP ;; 5986) echo WinRM-HTTPS ;;
        8000|9000) echo alt-HTTP ;; 8080) echo alt-HTTP ;; 8443) echo alt-HTTPS ;;
        8554) echo alt-RTSP ;;
        1702) echo 'Q-SYS QRC legacy (verify)' ;;
        1710) echo 'Q-SYS QRC (verify)' ;;
        41794) echo 'Crestron CIP (verify)' ;;
        41795) echo 'Crestron CTP console (verify)' ;;
        5959) echo 'NDI discovery server (verify)' ;;
        6970) echo 'RTP range (verify)' ;;
        7000) echo 'AirPlay (verify)' ;;
        *) echo '' ;;
    esac
}

if [ -t 1 ]; then
    C_RESET=$(printf '\033[0m'); C_GREEN=$(printf '\033[32m')
    C_CYAN=$(printf '\033[36m');  C_GREY=$(printf '\033[90m')
    C_YELL=$(printf '\033[33m');  C_RED=$(printf '\033[31m')
    C_BOLD=$(printf '\033[1m')
else
    C_RESET=; C_GREEN=; C_CYAN=; C_GREY=; C_YELL=; C_RED=; C_BOLD=
fi
# BSD mktemp refuses to run without a template, so never call bare mktemp
tmpf() { mktemp "${TMPDIR:-/tmp}/netprobe.XXXXXX"; }

# Integer ranges go through awk, not seq. BSD seq formats with %g by default,
# six significant digits, so a /16 comes out as 2.852e+09 repeated and sort -u
# collapses 65534 addresses to seven. %.0f keeps every value exact and avoids
# awk's own %d integer conversion at the same time.
int_seq() {
    awk -v a="$1" -v b="$2" 'BEGIN { for (i = a; i <= b; i++) printf "%.0f\n", i }'
}

say()  { printf '%s\n' "$*"; }
info() { printf '%s%s%s\n' "$C_CYAN" "$*" "$C_RESET"; }
dim()  { printf '%s%s%s\n' "$C_GREY" "$*" "$C_RESET"; }
# warn and err go to stderr so that a parse complaint never lands in the
# middle of an address list being piped somewhere
warn() { printf '%s%s%s\n' "$C_YELL" "$*" "$C_RESET" >&2; }
err()  { printf '%s%s%s\n' "$C_RED"  "$*" "$C_RESET" >&2; }
hit()  { printf '%s%s%s\n' "$C_GREEN" "$*" "$C_RESET"; }

# --------------------------------------------------------------- ip plumbing

ip_to_int() {
    IFS=. read -r a b c d <<EOF
$1
EOF
    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

int_to_ip() {
    n=$1
    echo "$(( (n >> 24) & 255 )).$(( (n >> 16) & 255 )).$(( (n >> 8) & 255 )).$(( n & 255 ))"
}

is_ipv4() {
    case $1 in
        *[!0-9.]*) return 1 ;;
    esac
    IFS=. read -r a b c d e <<EOF
$1
EOF
    [ -n "${d:-}" ] || return 1
    [ -z "${e:-}" ] || return 1
    for o in "$a" "$b" "$c" "$d"; do
        [ -n "$o" ] || return 1
        [ "$o" -le 255 ] 2>/dev/null || return 1
    done
    return 0
}

# Dotted mask to prefix length. Rejects non-contiguous masks rather than
# silently accepting something like 255.255.0.255.
mask_to_prefix() {
    m=$(ip_to_int "$1")
    bits=0; t=$m
    while [ "$t" -ne 0 ]; do
        bits=$(( bits + (t & 1) ))
        t=$(( t >> 1 ))
    done
    if [ "$bits" -eq 0 ]; then rebuilt=0
    elif [ "$bits" -eq 32 ]; then rebuilt=4294967295
    else rebuilt=$(( (4294967295 >> (32 - bits)) << (32 - bits) ))
    fi
    [ "$m" -eq "$rebuilt" ] || return 1
    echo "$bits"
}

resolve_host() {
    if command -v getent >/dev/null 2>&1; then
        getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | sort -u
    elif command -v dscacheutil >/dev/null 2>&1; then
        dscacheutil -q host -a name "$1" 2>/dev/null | awk '/^ip_address:/{print $2}' | sort -u
    else
        host "$1" 2>/dev/null | awk '/has address/{print $NF}' | sort -u
    fi
}

# One line in, the integers it covers out, one per line. Bad lines are
# reported and skipped rather than killing the run.
expand_line() {
    line=$(printf '%s' "$1" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    case $line in
        ''|'#'*) return 0 ;;
    esac

    # CIDR
    case $line in
        */*)
            base=${line%%/*}; rest=${line#*/}
            base=$(printf '%s' "$base" | sed -e 's/[[:space:]]*$//')
            rest=$(printf '%s' "$rest" | sed -e 's/^[[:space:]]*//')
            if is_ipv4 "$base" && is_ipv4 "$rest"; then
                prefix=$(mask_to_prefix "$rest") || {
                    warn "    skipped '$line': non-contiguous mask"; return 0; }
            elif is_ipv4 "$base" && [ -z "${rest//[0-9]/}" ] && [ -n "$rest" ] && [ "$rest" -le 32 ]; then
                prefix=$rest
            else
                warn "    skipped '$line': unreadable prefix"; return 0
            fi
            ip=$(ip_to_int "$base")
            if [ "$prefix" -eq 0 ]; then mask=0
            else mask=$(( (4294967295 >> (32 - prefix)) << (32 - prefix) )); fi
            net=$(( ip & mask ))
            bcast=$(( net | (4294967295 ^ mask) ))
            if [ "$prefix" -le 30 ]; then a=$(( net + 1 )); b=$(( bcast - 1 ))
            else a=$net; b=$bcast; fi
            int_seq "$a" "$b"
            return 0
            ;;
    esac

    # dotted mask, space separated
    set -- $line
    if [ $# -eq 2 ] && is_ipv4 "$1" && is_ipv4 "$2"; then
        prefix=$(mask_to_prefix "$2") || {
            warn "    skipped '$line': non-contiguous mask"; return 0; }
        ip=$(ip_to_int "$1")
        if [ "$prefix" -eq 0 ]; then mask=0
        else mask=$(( (4294967295 >> (32 - prefix)) << (32 - prefix) )); fi
        net=$(( ip & mask ))
        bcast=$(( net | (4294967295 ^ mask) ))
        if [ "$prefix" -le 30 ]; then a=$(( net + 1 )); b=$(( bcast - 1 ))
        else a=$net; b=$bcast; fi
        int_seq "$a" "$b"
        return 0
    fi

    # ranges
    case $line in
        *-*)
            first=$(printf '%s' "${line%%-*}" | sed -e 's/[[:space:]]*$//')
            last=$(printf '%s' "${line#*-}" | sed -e 's/^[[:space:]]*//')
            if is_ipv4 "$first" && is_ipv4 "$last"; then
                a=$(ip_to_int "$first"); b=$(ip_to_int "$last")
            elif is_ipv4 "$first" && [ -z "${last//[0-9]/}" ] && [ -n "$last" ] && [ "$last" -le 255 ]; then
                # last-octet form, 10.1.30.60-74
                a=$(ip_to_int "$first")
                b=$(( (a & 4294967040) + last ))
            else
                warn "    skipped '$line': unreadable range"; return 0
            fi
            [ "$a" -le "$b" ] || { t=$a; a=$b; b=$t; }
            int_seq "$a" "$b"
            return 0
            ;;
    esac

    # single address
    if is_ipv4 "$line"; then
        ip_to_int "$line"
        return 0
    fi

    # hostname, resolved here so everything downstream stays numeric
    found=$(resolve_host "$line")
    if [ -n "$found" ]; then
        for f in $found; do is_ipv4 "$f" && ip_to_int "$f"; done
        return 0
    fi
    warn "    skipped '$line': does not resolve"
}

expand_stream() {
    while IFS= read -r l || [ -n "$l" ]; do
        expand_line "$l"
    done
    return 0
}

# Consecutive integers on stdin back into "first-last" strings for display.
compress_ints() {
    sort -n | awk '
        function out(a, b) { if (a == b) print ip(a); else printf "%s-%s\n", ip(a), ip(b) }
        function ip(n) { return sprintf("%d.%d.%d.%d", int(n/16777216)%256, int(n/65536)%256, int(n/256)%256, n%256) }
        NR == 1 { s = $1; p = $1; next }
        $1 == p + 1 { p = $1; next }
        { out(s, p); s = $1; p = $1 }
        END { if (NR) out(s, p) }
    '
}

ints_to_ips() {
    awk '{ printf "%d.%d.%d.%d\n", int($1/16777216)%256, int($1/65536)%256, int($1/256)%256, $1%256 }'
}

# ------------------------------------------------------------ probe workers
#
# These run as child processes under xargs -P. The script re-invokes itself
# rather than exporting functions, which keeps it working under BSD xargs and
# under /bin/sh.

# ping semantics differ: BSD -W is milliseconds, iputils -W is seconds.
ping_once() {
    _ms=$1; _ip=$2
    case $OS in
        Darwin|*BSD)
            ping -c 1 -W "$_ms" -t 2 -q "$_ip" >/dev/null 2>&1
            ;;
        *)
            _s=$(( (_ms + 999) / 1000 ))
            [ "$_s" -lt 1 ] && _s=1
            ping -c 1 -W "$_s" -q "$_ip" >/dev/null 2>&1
            ;;
    esac
}

# Open, Closed and Filtered are told apart by how the connect died: clean exit
# is open, watchdog kill is filtered, anything else is a refusal, which still
# proves a host is there.
tcp_once() {
    _ms=$1; _ip=$2; _port=$3
    _secs=$(awk -v m="$_ms" 'BEGIN { printf "%.2f", m / 1000 }')
    ( exec 3<>"/dev/tcp/$_ip/$_port" ) >/dev/null 2>&1 &
    _cpid=$!
    ( sleep "$_secs"; kill -9 "$_cpid" ) >/dev/null 2>&1 &
    _wpid=$!
    if wait "$_cpid" 2>/dev/null; then _state=open
    else
        _rc=$?
        if [ "$_rc" -gt 128 ]; then _state=filtered; else _state=closed; fi
    fi
    kill "$_wpid" >/dev/null 2>&1
    wait "$_wpid" 2>/dev/null
    printf '%s %s %s\n' "$_ip" "$_port" "$_state"
}

case ${1:-} in
    __ping) ping_once "$2" "$3" && printf '%s\n' "$3"; exit 0 ;;
    __tcp)  tcp_once "$2" "$3" "$4"; exit 0 ;;
esac

# ------------------------------------------------------------ probe drivers

# stdin: addresses. stdout: the ones that answered.
sweep_ping() {
    _ms=$1; _par=$2
    xargs -P "$_par" -I{} "$RUNNER" "$SELF" __ping "$_ms" {}
}

# stdin: "ip port" pairs. stdout: "ip port state".
sweep_tcp() {
    _ms=$1; _par=$2
    xargs -P "$_par" -n 2 sh -c 'exec "$0" "$1" __tcp "$2" "$3" "$4"' "$RUNNER" "$SELF" "$_ms"
}

# Breadth-first: adjacent work items land on different hosts, so the
# concurrency spreads across the subnet instead of dumping every socket on one
# camera at once. Both sides come from files because a /16 host list is about a
# megabyte and will not fit in argv.
#   $1 = file of addresses, $2 = file of ports
pair_stream() {
    awk 'NR == FNR { h[++n] = $1; next } { for (i = 1; i <= n; i++) print h[i], $1 }' "$1" "$2"
}

# Turns a whitespace separated port string into a temp file and echoes its path.
ports_file() {
    _pf=$(tmpf)
    printf '%s\n' $1 | sed '/^$/d' > "$_pf"
    printf '%s\n' "$_pf"
}

# ------------------------------------------------------------ capabilities

PING_OK=0
probe_ping_support() {
    command -v ping >/dev/null 2>&1 || return 1
    ping_once 500 127.0.0.1 || return 1
    return 0
}

HAVE_FPING=0; HAVE_NMAP=0
command -v fping >/dev/null 2>&1 && HAVE_FPING=1
command -v nmap  >/dev/null 2>&1 && HAVE_NMAP=1

# stdin: addresses. stdout: the ones that are alive, by whatever means works.
sweep_alive() {
    _ms=$1; _par=$2
    if [ "$PING_OK" -eq 1 ]; then
        if [ "$HAVE_FPING" -eq 1 ] && [ "${USE_FPING:-0}" -eq 1 ]; then
            fping -a -q -r 0 -t "$_ms" 2>/dev/null
        else
            sweep_ping "$_ms" "$_par"
        fi
    else
        # No usable ICMP. Fall back to knocking on the discovery ports and
        # treating any answer, open or refused, as proof of life.
        _hf=$(tmpf); cat > "$_hf"
        _pf=$(ports_file "$DISCOVERY_PORTS")
        pair_stream "$_hf" "$_pf" \
            | sweep_tcp "$_ms" "$_par" \
            | awk '$3 != "filtered" { print $1 }' \
            | sort -u
        rm -f "$_hf" "$_pf"
    fi
}

# ------------------------------------------------------------ prompts

ask() {
    printf '  %s [%s]: ' "$1" "$2" >&2
    IFS= read -r _r || _r=
    [ -n "$_r" ] && printf '%s\n' "$_r" || printf '%s\n' "$2"
}

ask_int() {
    while :; do
        _v=$(ask "$1" "$2")
        case $_v in
            ''|*[!0-9]*) ;;
            *) if [ "$_v" -ge "$3" ] && [ "$_v" -le "$4" ]; then printf '%s\n' "$_v"; return 0; fi ;;
        esac
        warn "    whole number between $3 and $4."
    done
}

ask_yn() {
    _def=$2
    while :; do
        printf '  %s [%s]: ' "$1" "$_def" >&2
        IFS= read -r _r || _r=
        [ -z "$_r" ] && _r=$_def
        case $_r in
            [yY]*) return 0 ;;
            [nN]*) return 1 ;;
            *) warn "    y or n." ;;
        esac
    done
}

read_address_lines() {
    dim "  Enter $1, one per line. Blank line when done." >&2
    while :; do
        printf '    > ' >&2
        IFS= read -r _l || break
        [ -z "$_l" ] && break
        printf '%s\n' "$_l"
    done
}

# Writes the working set, as sorted integers, to $1. Returns 1 if the user
# backs out or nothing usable comes of it.
get_address_set() {
    _out=$1
    say ''
    dim '  Address formats, mixed freely:'
    dim '    10.1.30.57   dsp.local   10.1.30.60-74   10.1.30.0/23   10.1.30.0 255.255.254.0'
    say ''
    say '    [1] Type them in'
    say '    [2] Read from a text file'
    say '    [0] Back to the menu'

    _raw=$(tmpf); _pool=$(tmpf); _excl=$(tmpf)
    trap 'rm -f "$_raw" "$_pool" "$_excl"' RETURN 2>/dev/null

    while :; do
        _c=$(ask 'Choice' '1')
        case $_c in
            0) rm -f "$_raw" "$_pool" "$_excl"; return 1 ;;
            1) read_address_lines 'addresses' > "$_raw"; break ;;
            2)
                _p=$(ask 'Path to the list' '')
                _p=$(printf '%s' "$_p" | sed -e 's/^"//' -e 's/"$//')
                if [ -f "$_p" ]; then cat "$_p" > "$_raw"; break
                else warn '    cannot find that file.'; fi
                ;;
            *) warn '    1, 2 or 0.' ;;
        esac
    done

    expand_stream < "$_raw" | sort -n -u > "$_pool"
    _n=$(wc -l < "$_pool" | tr -d ' ')
    if [ "$_n" -eq 0 ]; then
        err '  Nothing usable in that list.'
        rm -f "$_raw" "$_pool" "$_excl"; return 1
    fi
    info "  $_n address(es) in the pool."

    if ask_yn 'Exclude anything from that pool?' 'n'; then
        read_address_lines 'addresses to skip' | expand_stream | sort -n -u > "$_excl"
        if [ -s "$_excl" ]; then
            comm -23 "$_pool" "$_excl" > "$_pool.keep" 2>/dev/null \
                || join -v 1 "$_pool" "$_excl" > "$_pool.keep"
            mv "$_pool.keep" "$_pool"
            _k=$(wc -l < "$_pool" | tr -d ' ')
            info "  $(( _n - _k )) excluded, $_k remaining."
            _n=$_k
        fi
    fi

    if [ "$_n" -eq 0 ]; then
        err '  Nothing left after exclusions.'
        rm -f "$_raw" "$_pool" "$_excl"; return 1
    fi
    if [ "$_n" -gt "$MAX_ADDRESSES" ]; then
        err "  $_n addresses is past the $MAX_ADDRESSES ceiling. Check your prefix."
        rm -f "$_raw" "$_pool" "$_excl"; return 1
    fi

    sort -n "$_pool" > "$_out"
    rm -f "$_raw" "$_pool" "$_excl"
    return 0
}

save_lines() {
    _src=$1; _default=$2; _what=$3
    [ -s "$_src" ] || return 0
    ask_yn "Save $_what to a file?" 'n' || return 0
    _p=$(ask 'Path' "$TOOLDIR/$_default")
    if cp "$_src" "$_p" 2>/dev/null; then info "  Written to $_p"
    else err "  Could not write $_p"; fi
}

# ------------------------------------------------------------ mode 1: sweep

mode_sweep() {
    say ''
    info '  --- Ping sweep -------------------------------------'
    _set=$(tmpf)
    get_address_set "$_set" || { rm -f "$_set"; return 0; }

    _count=$(wc -l < "$_set" | tr -d ' ')
    say ''
    _ms=$(ask_int 'Reply timeout in ms' 500 50 30000)
    _par=$(ask_int 'Probes in flight at once' 64 1 1024)

    USE_FPING=0
    if [ "$HAVE_FPING" -eq 1 ] && [ "$PING_OK" -eq 1 ]; then
        ask_yn 'fping is installed. Use it instead of the shell loop?' 'y' && USE_FPING=1
    fi

    _first=$(head -1 "$_set" | ints_to_ips)
    _last=$(tail -1 "$_set" | ints_to_ips)
    say ''
    info "  Sweeping $_count addresses, $_first to $_last"
    say ''

    _alive=$(tmpf); _aliveint=$(tmpf); _gaps=$(tmpf)
    _t0=$(date +%s)
    ints_to_ips < "$_set" | sweep_alive "$_ms" "$_par" | sort -u > "$_alive"
    _t1=$(date +%s)

    while IFS= read -r _ip; do ip_to_int "$_ip"; done < "$_alive" | sort -n > "$_aliveint"
    comm -23 "$_set" "$_aliveint" 2>/dev/null | compress_ints > "$_gaps"

    _up=$(wc -l < "$_alive" | tr -d ' ')
    say ''
    info "  Done in $(( _t1 - _t0 ))s. $_up of $_count answered, $(( _count - _up )) silent."
    say ''

    _sorted=$(tmpf)
    sort -n "$_aliveint" | ints_to_ips > "$_sorted"
    if [ -s "$_sorted" ]; then
        printf '%s  Responded:%s\n' "$C_BOLD" "$C_RESET"
        while IFS= read -r _l; do hit "    $_l"; done < "$_sorted"
        say ''
    fi

    if [ -s "$_gaps" ]; then
        printf '%s  Silent, collapsed to %s range(s):%s\n' "$C_BOLD" "$(wc -l < "$_gaps" | tr -d ' ')" "$C_RESET"
        while IFS= read -r _l; do dim "    $_l"; done < "$_gaps"
        say ''
        dim '  Anything firewalled against ICMP, or powered down when this ran,'
        dim '  looks free here but is not. Cross-check DHCP leases before you claim'
        dim '  any of it.'
        say ''
    fi

    _stamp=$(date +%Y%m%d-%H%M)
    save_lines "$_sorted" "responded-$_stamp.txt" 'the responders'
    save_lines "$_gaps"   "free-$_stamp.txt"      'the silent ranges'
    rm -f "$_set" "$_alive" "$_aliveint" "$_gaps" "$_sorted"
}

# ------------------------------------------------------------ mode 2: watch

mode_watch() {
    say ''
    info '  --- Watch for new hosts ----------------------------'
    dim '  First pass is a silent baseline. After that, every address that'
    dim '  starts answering is printed and logged. Ctrl-C to stop.'

    _set=$(tmpf)
    get_address_set "$_set" || { rm -f "$_set"; return 0; }
    _count=$(wc -l < "$_set" | tr -d ' ')

    say ''
    _ms=$(ask_int 'Reply timeout in ms' 500 50 30000)
    _par=$(ask_int 'Probes in flight at once' 64 1 1024)
    _rest=$(ask_int 'Seconds between passes' 30 0 86400)
    _trans=0; ask_yn 'Also report addresses that go away?' 'n' && _trans=1
    _log=$(ask 'Log file' "$TOOLDIR/found.log")

    USE_FPING=0
    if [ "$HAVE_FPING" -eq 1 ] && [ "$PING_OK" -eq 1 ]; then
        ask_yn 'fping is installed. Use it instead of the shell loop?' 'y' && USE_FPING=1
    fi

    _ips=$(tmpf); ints_to_ips < "$_set" > "$_ips"
    _seen=$(tmpf); _now=$(tmpf); _new=$(tmpf); _gone=$(tmpf)
    _pass=0

    say ''
    info "  Watching $_count addresses, $(head -1 "$_ips") to $(tail -1 "$_ips")"
    dim '  Taking baseline...'

    trap 'rm -f "$_set" "$_ips" "$_seen" "$_now" "$_new" "$_gone"; say ""; return 0' INT

    while :; do
        _pass=$(( _pass + 1 ))
        sweep_alive "$_ms" "$_par" < "$_ips" | sort -u > "$_now"

        if [ "$_pass" -eq 1 ]; then
            cp "$_now" "$_seen"
            info "  Baseline: $(wc -l < "$_seen" | tr -d ' ') of $_count already responding (not reported)."
            info '  Watching for new arrivals...'
            say ''
        else
            comm -13 "$_seen" "$_now" > "$_new"
            while IFS= read -r _ip; do
                [ -z "$_ip" ] && continue
                _line="$(date '+%Y-%m-%d %H:%M:%S')  UP    $_ip"
                say ''
                hit "  $_line"
                printf '%s\n' "$_line" >> "$_log"
            done < "$_new"
            sort -u "$_seen" "$_new" > "$_seen.t" && mv "$_seen.t" "$_seen"

            if [ "$_trans" -eq 1 ]; then
                comm -23 "$_seen" "$_now" > "$_gone"
                while IFS= read -r _ip; do
                    [ -z "$_ip" ] && continue
                    _line="$(date '+%Y-%m-%d %H:%M:%S')  GONE  $_ip"
                    say ''
                    warn "  $_line"
                    printf '%s\n' "$_line" >> "$_log"
                done < "$_gone"
                cp "$_now" "$_seen"
            fi
        fi

        printf '.'
        sleep "$_rest"
    done
}

# ------------------------------------------------------------ mode 3: ports

read_port_set() {
    say '' >&2
    say "    [1] Common AV / IT set ($(printf '%s\n' $COMMON_PORTS | wc -l | tr -d ' ') ports)" >&2
    say '    [2] Type a list, e.g. 22,23,80,443,8000-8100' >&2
    say '    [3] Everything, 1-65535' >&2
    while :; do
        _c=$(ask 'Ports' '1')
        case $_c in
            1) printf '%s\n' $COMMON_PORTS | sort -n -u; return 0 ;;
            3)
                warn '    65535 ports per host. On more than a couple of hosts this runs'
                warn '    for hours.'
                if ask_yn 'Sure?' 'n'; then int_seq 1 65535; return 0; fi
                ;;
            2)
                _spec=$(ask 'Port list' '22,23,80,443')
                _ok=1; _tmp=$(tmpf)
                for _piece in $(printf '%s' "$_spec" | tr ',;' '  '); do
                    case $_piece in
                        *-*)
                            _lo=${_piece%%-*}; _hi=${_piece#*-}
                            case "$_lo$_hi" in *[!0-9]*) _ok=0 ;; esac
                            [ "$_ok" -eq 1 ] || break
                            [ "$_lo" -gt "$_hi" ] && { _t=$_lo; _lo=$_hi; _hi=$_t; }
                            if [ "$_lo" -lt 1 ] || [ "$_hi" -gt 65535 ]; then _ok=0; break; fi
                            int_seq "$_lo" "$_hi" >> "$_tmp"
                            ;;
                        *)
                            case $_piece in *[!0-9]*|'') _ok=0 ;; esac
                            [ "$_ok" -eq 1 ] || break
                            if [ "$_piece" -lt 1 ] || [ "$_piece" -gt 65535 ]; then _ok=0; break; fi
                            printf '%s\n' "$_piece" >> "$_tmp"
                            ;;
                    esac
                done
                if [ "$_ok" -eq 1 ] && [ -s "$_tmp" ]; then
                    sort -n -u "$_tmp"; rm -f "$_tmp"; return 0
                fi
                rm -f "$_tmp"
                warn '    could not read that port list.'
                ;;
            *) warn '    1, 2 or 3.' ;;
        esac
    done
}

mode_ports() {
    say ''
    info '  --- TCP port scan ----------------------------------'
    dim '  TCP only. Dante control and audio, PTP, mDNS discovery and SNMP'
    dim '  are UDP and will never show up here.'

    _set=$(tmpf)
    get_address_set "$_set" || { rm -f "$_set"; return 0; }
    _hostfile=$(tmpf); ints_to_ips < "$_set" > "$_hostfile"
    _hcount=$(wc -l < "$_hostfile" | tr -d ' ')

    _portfile=$(tmpf); read_port_set > "$_portfile"
    _pcount=$(wc -l < "$_portfile" | tr -d ' ')

    say ''
    _ms=$(ask_int 'Connect timeout in ms' 400 50 30000)
    _par=$(ask_int 'Sockets in flight at once' 256 1 1024)

    if [ "$HAVE_NMAP" -eq 1 ]; then
        say ''
        dim '  nmap is installed. It does this faster, with service and version'
        dim '  detection this script has no equivalent for.'
        if ask_yn 'Hand off to nmap?' 'y'; then
            _plist=$(tr '\n' ',' < "$_portfile" | sed 's/,$//')
            say ''
            nmap -Pn -n -T4 --open -p "$_plist" -iL "$_hostfile"
            rm -f "$_set" "$_hostfile" "$_portfile"
            return 0
        fi
    fi

    _discover=0
    if [ "$_hcount" -gt 1 ]; then
        ask_yn 'Probe for live hosts first? (much faster on a sparse subnet)' 'y' && _discover=1
    fi

    say ''
    info "  $_hcount address(es), $_pcount port(s) each"
    _t0=$(date +%s)

    _live=$(tmpf)
    if [ "$_discover" -eq 1 ]; then
        _dpf=$(ports_file "$DISCOVERY_PORTS")
        dim "  Discovery: $(wc -l < "$_dpf" | tr -d ' ') ports per host..."
        pair_stream "$_hostfile" "$_dpf" \
            | sweep_tcp "$_ms" "$_par" \
            | awk '$3 != "filtered" { print $1 }' | sort -u > "$_live"
        rm -f "$_dpf"

        # ICMP as a second chance for hosts that dropped every TCP probe.
        if [ "$PING_OK" -eq 1 ]; then
            _quiet=$(tmpf)
            sort -u "$_hostfile" | comm -23 - "$_live" > "$_quiet"
            if [ -s "$_quiet" ]; then
                sweep_alive "$_ms" "$_par" < "$_quiet" >> "$_live"
            fi
            rm -f "$_quiet"
        fi
        sort -u "$_live" > "$_live.s" && mv "$_live.s" "$_live"

        _lcount=$(wc -l < "$_live" | tr -d ' ')
        info "  Discovery found $_lcount live host(s) in $(( $(date +%s) - _t0 ))s"
        if [ "$_lcount" -eq 0 ]; then
            warn '  Nothing answered. Either this is the wrong VLAN, or every probe'
            warn '  is being dropped. Try again with the discovery phase turned off.'
            rm -f "$_set" "$_hostfile" "$_portfile" "$_live"
            return 0
        fi
    else
        cp "$_hostfile" "$_live"
        _lcount=$_hcount
    fi

    _results=$(tmpf)
    info "  Scanning $_lcount host(s) x $_pcount ports, $_par at a time"
    pair_stream "$_live" "$_portfile" | sweep_tcp "$_ms" "$_par" > "$_results"
    _t1=$(date +%s)

    _open=$(tmpf)
    awk '$3 == "open" { print $1, $2 }' "$_results" \
        | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n -k2n > "$_open"

    _lines=$(tmpf); _lasthost=''
    while read -r _ip _port; do
        [ -z "${_ip:-}" ] && continue
        if [ "$_ip" != "$_lasthost" ]; then
            say ''
            printf '%s  %s%s\n' "$C_BOLD" "$_ip" "$C_RESET"
            _lasthost=$_ip
        fi
        _lbl=$(port_label "$_port")
        [ -n "$_lbl" ] && _lbl=" ($_lbl)"
        hit "    OPEN  $_port$_lbl"
        printf '%s\t%s%s\n' "$_ip" "$_port" "$_lbl" >> "$_lines"
    done < "$_open"

    _nopen=$(wc -l < "$_open" | tr -d ' ')
    _nclosed=$(awk '$3 == "closed"' "$_results" | wc -l | tr -d ' ')
    _nfilt=$(awk '$3 == "filtered"' "$_results" | wc -l | tr -d ' ')
    say ''
    info "  Done in $(( _t1 - _t0 ))s. $_nopen open; $_nclosed closed, $_nfilt filtered."
    say ''

    save_lines "$_lines" "openports-$(date +%Y%m%d-%H%M).txt" 'the open ports'
    rm -f "$_set" "$_hostfile" "$_portfile" "$_live" "$_results" "$_open" "$_lines"
}

# ------------------------------------------------------------ menu

probe_ping_support && PING_OK=1

clear 2>/dev/null
say ''
info '  =========================================='
info '            Network probe toolkit           '
info '  =========================================='
dim  "  $OS, bash ${BASH_VERSION%%(*}"
if [ "$PING_OK" -eq 0 ]; then
    say ''
    warn '  ICMP is not usable here, either ping is missing or the OS is'
    warn '  refusing it. Liveness will fall back to knocking on common TCP'
    warn '  ports instead, which is slower and misses hosts with everything'
    warn '  closed.'
fi
[ "$HAVE_FPING" -eq 1 ] && dim '  fping found.'
[ "$HAVE_NMAP" -eq 1 ]  && dim '  nmap found.'
say ''

while :; do
    say '  [1] Ping sweep      one pass, what answered and what did not'
    say '  [2] Watch           continuous, shout when something appears'
    say '  [3] TCP port scan   discovery pass, then open ports per host'
    say '  [q] Quit'
    say ''
    _choice=$(ask 'Choice' '1')
    case $_choice in
        1) mode_sweep ;;
        2) mode_watch ;;
        3) mode_ports ;;
        q|Q) say ''; exit 0 ;;
        *) warn '  1, 2, 3 or q.' ;;
    esac
    say ''
    dim '  ------------------------------------------'
    say ''
done
