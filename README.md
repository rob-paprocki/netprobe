# netprobe

Ping sweep, watch mode and TCP port scan with no dependencies: one bash script for macOS, Linux and BSD, and one self-contained `.cmd` for Windows.

[![CI](https://img.shields.io/github/actions/workflow/status/rob-paprocki/netprobe/ci.yml?branch=main&label=CI)](https://github.com/rob-paprocki/netprobe/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/rob-paprocki/netprobe)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20BSD%20%7C%20Windows-lightgrey)](#requirements)
[![Shell](https://img.shields.io/badge/bash-3.2%2B-blue)](netprobe.sh)

Both scripts show the same menu, take the same address formats and print the same output. They answer a common question on a locked-down machine: which addresses answer, and which are free for a static?

## Why

- Nothing to install. Stock macOS runs `netprobe.sh`, and Windows runs the self-contained `Test-Network.cmd`.
- The two scripts share one menu, one address syntax and one output format, so notes from one machine make sense on the other.
- Silent addresses are reported as ranges, which makes free space easy to spot when you need a static address.
- Watch mode keeps a baseline and logs each address as it starts answering.
- If `fping` or `nmap` is installed, the script offers to hand the work to it.

## Modes

| Mode | What it does |
|------|--------------|
| Ping sweep | One pass over the pool. Lists what answered and what didn't, with silent addresses collapsed into ranges. Either list can be saved to a file. |
| Watch | The same sweep on a loop. The first pass is a silent baseline. After that, each address that starts answering is printed and appended to `found.log`. It can report addresses that stop answering too. |
| TCP port scan | A discovery pass knocks on eight common ports and treats any answer, open or refused, as proof a host exists. Then it scans the ports you asked for on those hosts and reports the open ones with service labels. |

**Does not:** scan UDP, fingerprint operating systems or detect service versions. Use nmap for that.

## Requirements

| Item | Supported |
|------|-----------|
| `netprobe.sh` | bash 3.2 or newer on macOS, Linux or BSD. Stock macOS works with nothing installed. |
| `Test-Network.cmd` | Windows PowerShell 5.1 or PowerShell 7. The PowerShell half is inside the file. |

## Install

```bash
git clone https://github.com/rob-paprocki/netprobe.git
cd netprobe
./netprobe.sh
```

On Windows, double-click `Test-Network.cmd` or run it from a `cmd` window.

## Quick start

Run the script and pick a mode from the menu. Addresses can be typed at the prompt or read from a file, and a second prompt takes an exclusion list in the same formats. Taking the whole subnet and subtracting what you know is spoken for is usually the easier direction.

```text
192.168.100.57                    single address
printer.example.lan               hostname, resolved when the list is read
192.168.100.60-192.168.100.74     range
192.168.100.60-74                 range, last octet only
192.168.100.0/24                  CIDR
192.168.100.0 255.255.255.0       dotted mask
```

Formats can be mixed in one list. [`examples/pool.example.txt`](examples/pool.example.txt) shows the file format.

## Output files

The scripts write next to themselves.

| File | Written by |
|------|-----------|
| `found.log` | Watch mode, one line per address that comes alive |
| `responded-*.txt`, `free-*.txt` | Ping sweep, if you choose to save |
| `openports-*.txt` | TCP port scan, if you choose to save |

## Limits

Everything here is ICMP and TCP. mDNS discovery, SNMP and PTP are UDP and never show up. A silent address isn't proof that nothing is there: hosts that filter ICMP, or were powered down during the sweep, look the same as free space. Check DHCP leases, or `arp -a` after a sweep, before claiming an address.

At startup `netprobe.sh` checks whether ICMP works at all. In a container or on a locked-down host it doesn't, so liveness falls back to knocking on TCP ports. That is slower and misses hosts with every port closed. The script says so when it happens.

If `fping` or `nmap` is installed, `netprobe.sh` offers to hand off to it, and you should usually accept. `nmap -sn 192.168.100.0/24` beats the sweep here, and for port scanning nmap is far ahead. What these scripts add is the watch loop, the collapsed free-range output, and running on a machine where you can't install anything.

<details>
<summary>Implementation notes</summary>

Integer ranges are generated with awk rather than `seq`. BSD `seq` formats with `%g`, six significant digits, so a /16 comes out as `2.852e+09` repeated and `sort -u` collapses 65534 addresses to seven. Host and port lists move between stages as files rather than arguments, because a /16 host list is about a megabyte and doesn't fit in `ARG_MAX` on macOS.

Port labels marked `(verify)` are a convenience. Confirm them against the vendor documentation for your firmware.

</details>

## Help and contributing

Development happens in a separate repository; this one is updated when a release ships.

Questions and bug reports go in [Issues](https://github.com/rob-paprocki/netprobe/issues).

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE) (c) 2026 Rob Paprocki
