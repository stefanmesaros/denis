---
name: Bug report
about: Something crashes, errors, is slow, raises a false alarm or misses something
labels: bug
---

**Security problem?** Do not use this form: see SECURITY.md.

**Please do not include** passwords, API tokens or keys, public IP addresses, full MAC addresses,
Wi-Fi names or unredacted packet captures. Replace them with `<redacted>`. The
[tester guide](https://github.com/stefanmesaros/denis/blob/main/docs/community-testing.md#what-to-remove-before-sharing-logs-and-screenshots)
lists what to remove.

**DENIS version** (`denis --version`, or the header of the console)

**Operating system and how you run DENIS** (Linux distribution and architecture, macOS, Docker; installer, systemd service or plain binary)

**Network environment** (home / office / industrial; flat or VLANs; IPv4 only or IPv6 too; mirror/SPAN port or not; Wi-Fi or wired; roughly how many devices)

**Expected behavior**

**Actual behavior** (for a false positive or missed detection: the alert kind, the device type, and why the behavior was normal or what should have been flagged)

**How to reproduce** (command line options, settings, steps)

**Logs or screenshots** (redacted; `journalctl -u denis -n 50` for the systemd service)
