---
name: Incorrect device fingerprint
about: DENIS shows the wrong type, vendor, operating system or name for a device
labels: fingerprint
---

**Please do not include** passwords, tokens, public IP addresses, full MAC addresses or unredacted
packet captures. The [tester guide](https://github.com/stefanmesaros/denis/blob/main/docs/community-testing.md#what-to-remove-before-sharing-logs-and-screenshots)
lists what to remove.

**DENIS version** (`denis --version`, or the header of the console)

**Operating system and how you run DENIS** (Linux distribution and architecture, macOS, Docker)

**Network environment** (home / office / industrial; VLANs; IPv6; mirror/SPAN port or not; Wi-Fi or wired)

**The device's real make, model and firmware version** (as far as you know)

**First three bytes of its MAC address** (for example `3C:5A:B4`; not the whole address)

**Expected behavior** (the type, vendor and OS it should show)

**Actual behavior** (what DENIS shows: type, vendor, OS, and the "Why this guess" text from the device page)

**How the device connects** (Wi-Fi, Ethernet, behind a bridge or repeater, which VLAN) and anything
unusual about it (open ports, banners or names the device page shows)
