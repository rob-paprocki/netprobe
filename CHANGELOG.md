# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-11-15
**Upgrading:** nothing to do.

### Added

- Ping sweep, watch mode and TCP port scan in `netprobe.sh` (bash 3.2, macOS, Linux and BSD) and `Test-Network.cmd` (Windows), with one shared address format.
- Free ranges are reported as collapsed ranges, which helps when you're looking for addresses to assign statics.
- Optional hand-off to `fping` or `nmap` when they are installed.

### Changed

- The README has a short section on why the tool exists, and a CI status badge.

[Unreleased]: https://github.com/rob-paprocki/netprobe/commits/main
