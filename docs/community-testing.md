# Tester guide: helping test DENIS

**[Join our Discord Community →](https://discord.gg/DzbeV99xv)** to ask questions, compare notes and share what you find with other testers.

Thank you for testing DENIS. This page tells you how to install it, what to try first, and how to
report what you find so that it is useful to the developer. You do not need programming experience.

**What you are signing up for.** DENIS Community is free for personal networks of up to 100 devices.
It is self-hosted: it runs on your machine and your network traffic stays on your network. It has no
telemetry. The one routine outgoing request is an update check (`api.github.com`, every 6 hours), which
you can turn off with `--no-update-check`. See [Security](security.md).

**Honest status.** The [README's integration status table](../README.md#integration-status-what-is-validated-and-what-is-not) says what is validated and what is not. The integrations with firewalls, switches, cloud and directory services were built
against vendor documentation and test fixtures. None of them has been independently validated against a
real device or service yet. If you have one, that is exactly what we want to hear about, and a "did not
work" report is as useful as a "worked".

## 1. Install

Supported: Linux (x86-64 and ARM64, including Raspberry Pi OS) and macOS (Intel and Apple silicon).
There is also a [Docker image](docker.md). A packaged Windows collector does not exist yet.

* **Quickest look, no real network:** download the binary for your platform from the
  [latest release](https://github.com/stefanmesaros/denis/releases/latest) and run the demo (below).
* **Permanent Linux service:** the signed installer, see [Deployment](deployment.md):

  ```bash
  curl -fLO https://github.com/stefanmesaros/denis/releases/latest/download/install.sh
  less install.sh        # read it first if you like
  sudo bash install.sh
  ```

* **Docker:** `docker compose up demo` for the demo; real capture needs host networking, see
  [Docker](docker.md).

Check the version you run (you will need it for every report): `denis --version`, or the header of the
console.

## 2. Run the demo first

```bash
./denis demo --db demo.db load && ./denis serve --db demo.db --insecure-no-auth
```

This loads a fictional company and serves the console on your own machine only, with no login and no
capture. Click around the Devices, Alerts, Findings and Topology pages to see what DENIS shows when it
is working. Nothing you do there touches a real network. See the [console tour](tour.md).

## 3. Test on your real network

```bash
./denis run
```

It prints a one-time admin password and serves the console at `https://localhost:8080` (self-signed
certificate by default).

**Do I need a mirror/SPAN port?** A mirror (SPAN) port, or a network tap, is **recommended** because it is
the only way DENIS can see traffic between *other* devices. It is **not mandatory**. Without it, DENIS
still finds devices through the broadcast and multicast traffic that reaches its own network card (ARP,
DHCP, mDNS, SSDP, LLDP) plus an active sweep, which is enough for device discovery. With a mirror port
you additionally get per-device traffic baselines, who talks to whom, and industrial (OT) conversations.
To use one, set up the mirror on your switch, choose the interface under *Settings → Network
interfaces*, and start with `--flows` (or `--profile ot` on an industrial network). Details:
[Concepts › Visibility](concepts.md#visibility-what-can-be-seen-from-where).

If nothing shows up, see [Troubleshooting](troubleshooting.md) (capture permissions, wrong interface,
Wi-Fi client isolation).

## 4. What to test in the first 30 minutes

1. **Discovery (5 min).** Open Devices. Is every device you know about listed? Are there devices you do
   not recognise? Count them against your router's client list.
2. **Fingerprints (10 min).** For ten devices, compare the type, vendor and operating system DENIS shows
   with reality. Open the device page and read *Why this guess*. Report the wrong ones (section 5).
3. **Unusual hardware (5 min).** Look specifically at IoT, printers, cameras, TVs, game consoles, smart-home
   hubs, NAS boxes, industrial controllers and anything odd. These are the most valuable reports.
4. **Topology (5 min).** Open Topology. Does the picture match how your network is actually connected?
   If you have VLANs, are they separated the way you expect? If you use IPv6, are your IPv6 devices
   there and attached to the right device?
5. **Alerts (5 min).** Look at the first alerts. Each one shows the reasons behind its score. Were they
   sensible, or noise? (During the first 24 hours DENIS is learning what is normal, so alerts are
   limited by design.)

After the first day, check again for new false alarms, and note if anything DENIS should have flagged
was missed (for example a new device joining, or a device suddenly talking to somewhere new).

Longer-term, useful signals are: CPU and memory use over several days, whether the capture keeps up on a
busy network, and whether anything crashes or restarts. The *Health* page shows warnings.

## 5. How to report what you find

Open an issue on [GitHub Issues](https://github.com/stefanmesaros/denis/issues/new/choose) and pick the
template that fits:

| You found… | Template |
|---|---|
| A crash, error or something that does not work as documented | **Bug report** |
| A device with the wrong type, vendor, OS or name | **Incorrect device fingerprint** |
| A firewall, switch, cloud, directory or other integration, working or not | **Integration testing feedback** |
| Something DENIS should do that it does not | **Feature request** |
| A security vulnerability | **Do not file an issue.** See [SECURITY.md](../SECURITY.md) |

**A false positive** (an alert that should not have fired) is a bug report: say which alert kind, which
device (type only is fine), what the evidence panel listed, and why the behaviour was normal.
**A missing detection** is also a bug report: say what happened on the network and what you expected
DENIS to say.

### Useful hardware and vendor information

For a wrong or missing fingerprint, the following helps the most (all of it is optional, share what you can):

* The device's real make and model, and its firmware version if you know it.
* What DENIS shows: type, vendor, OS, and the *Why this guess* text from the device page.
* The **first three bytes of the MAC address** (for example `3C:5A:B4`). That identifies the vendor
  without identifying the device. You do not need to share the full address.
* How the device connects: Wi-Fi, Ethernet, behind a bridge or repeater, VLAN.
* The device's open ports or banners if the device page shows them.
* For an unusual protocol: the protocol name and a short description of what the device does.

### What to remove before sharing logs and screenshots

Please remove or blur the following before posting anything publicly. **Never post credentials, and do
not attach unredacted packet captures.** If a capture is needed, we will ask you privately and tell you
how to trim it.

* Passwords, API tokens and keys, licence keys, SNMP communities, session cookies, the contents of
  `secrets.key`, and the one-time admin password DENIS prints at first start
* Public IP addresses (your WAN address, VPN endpoints, servers you connect to)
* Full MAC addresses (the first three bytes are fine)
* Wi-Fi network names and passwords, hostnames and device names that identify you or your household or
  company, usernames and email addresses
* Serial numbers, domain names of internal services, and cloud account or tenant identifiers
* Anything in the browser address bar or console header that shows an internal name

Private IP addresses (`192.168.x.x`, `10.x.x.x`, `172.16–31.x.x`) are fine to leave in.

Tip: replace values with `<redacted>` rather than deleting the line, so the structure stays readable.

## Other ways to help

* Translation corrections: see [CONTRIBUTING.md](../CONTRIBUTING.md).
* Tell us what confused you. First-install friction is a valid bug.
* Join the [Discord community](https://discord.gg/DzbeV99xv) and tell other testers what worked on your hardware.
