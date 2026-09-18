# netprobe

Two implementations of the same small network probe toolkit: one POSIX shell
script for Unix and macOS, one self-contained `.cmd` for Windows. Both present
the same menu, take the same address formats, and produce the same output.

    netprobe.sh        Linux, macOS, BSD
    Test-Network.cmd   Windows

Neither has dependencies. `netprobe.sh` targets bash 3.2, so stock macOS runs
it with nothing installed. `Test-Network.cmd` carries its PowerShell half
inside itself and runs on Windows PowerShell 5.1 or PowerShell 7.

## Modes

**Ping sweep.** One pass over the address pool. Reports what answered, and
what didn't with the silent addresses collapsed back into ranges, either of
which can be saved to a file. The range output is the useful half when you are
looking for space to assign statics.

**Watch.** The same sweep on a loop. The first pass is a silent baseline, and
after that every address that starts answering is printed and appended to
`found.log`. Optionally reports addresses that stop answering too. Useful when
you are waiting on gear to come up, or trying to catch a device that only
appears intermittently.

**TCP port scan.** An optional discovery pass knocks on eight common ports and
treats any answer, connection or refusal, as proof a host exists. Then it scans
the requested ports against whatever discovery found. Reports open ports with
service labels.

## Address formats

Accepted anywhere the tools ask for addresses, mixed freely in one list:

    10.1.30.57                 single address
    dsp.local                  hostname, resolved when the list is read
    10.1.30.60-10.1.30.74      range
    10.1.30.60-74              range, last octet only
    10.1.30.0/23               CIDR
    10.1.30.0 255.255.254.0    dotted mask

Addresses can be typed at the prompt or read from a file. Either way a second
prompt offers an exclusion list in the same formats, which is usually the
easier direction: take the whole subnet, then subtract what you know is
spoken for. `examples/pool.example.txt` shows the file format.

## Running it

    chmod +x netprobe.sh
    ./netprobe.sh

On Windows, double-click `Test-Network.cmd` or run it from a `cmd` window.

## What it will not tell you

Everything here is ICMP and TCP. Dante control and audio, PTP, mDNS discovery
and SNMP are UDP and will never appear. A silent address is not proof that
nothing is there: hosts that filter ICMP, or that were powered down when the
sweep ran, look identical to free space. Check DHCP leases, or `arp -a` after
a sweep, before claiming an address.

`netprobe.sh` checks at startup whether ICMP is usable at all. Where it isn't,
in a container or on a locked-down host, liveness falls back to knocking on
TCP ports, which is slower and misses hosts with everything closed. It says so
when this happens.

## Where the real tools are better

If `fping` or `nmap` are installed, `netprobe.sh` offers to hand off to them,
and you should usually accept. `nmap -sn 10.1.30.0/23` beats the sweep here,
and for port scanning nmap is not close: it does service and version
detection, OS fingerprinting, and UDP. What these scripts add is the watch
loop, the collapsed free-range output, and running at all on a locked-down
machine where you cannot install anything.

## Notes

Integer ranges are generated with awk rather than `seq`. BSD `seq` formats
with `%g` by default, six significant digits, so a /16 comes out as
`2.852e+09` repeated and `sort -u` collapses 65534 addresses to seven. Host
and port lists move between stages as files rather than arguments, because a
/16 host list is about a megabyte and does not fit in `ARG_MAX` on macOS.

Port labels marked `(verify)` are convenience only. Confirm them against the
vendor documentation for the firmware you are actually on.
