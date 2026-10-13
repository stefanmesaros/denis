# Mirroring over VLANs and tunnels (RSPAN, ERSPAN, VXLAN)

DENIS learns what is on a network from the frames it sees. The simplest way to show it a switch's
traffic is a local mirror (SPAN) port cabled into a spare network card (`--mirror-iface`, or
Settings > Network interfaces). This page covers the other ways a mirror reaches DENIS:

| Delivery | What the collector receives | DENIS option |
| --- | --- | --- |
| Local SPAN port | the mirrored frames, as they were | `--mirror-iface` |
| RSPAN | the mirrored frames, carried in a dedicated VLAN (802.1Q tag) across the switches | `--mirror-iface` (nothing else to turn on) |
| ERSPAN | the mirrored frames inside GRE/IP, routed to the collector's IP address | `--tunnel-mirror erspan` |
| AWS VPC Traffic Mirroring, Azure vTAP, other VXLAN mirrors | the mirrored frames inside VXLAN (UDP 4789) | `--tunnel-mirror vxlan` |

Status of this feature: new in 4.1.0, **verified on hand-built frames and public sample captures
only, not yet on real switches or cloud mirrors**. See "Verified and not verified" at the end.

## RSPAN and VLAN-tagged frames

RSPAN (Remote SPAN) copies the mirrored traffic into a special VLAN that is carried across trunks to
a switch that has the collector on one of its ports. The collector then sees ordinary Ethernet
frames, each with an 802.1Q tag whose VLAN ID is the RSPAN VLAN (some designs use 802.1ad "QinQ"
outer tags, or two 802.1Q tags). DENIS needs nothing switched on for this: the tag is read through.

What DENIS does with tags:

- The kernel capture filter admits an ARP, IPv4, IPv6, DHCP, mDNS/SSDP, LLDP, CDP, PROFINET or
  GOOSE frame with **no tag, one tag (802.1Q or 802.1ad), or two tags** wherever it admits the
  untagged frame. A third tag is not admitted and not decoded.
- Every decoder (ARP, DHCP, mDNS, SSDP, TCP signatures, flows, passive DNS, IPv6, LLDP/CDP, the
  industrial protocols) reads the same frame the same way whether it carries 0, 1 or 2 tags.
- Since 4.1 DENIS **records** the VLAN ID of a mirrored frame (its outermost tag, or for an ERSPAN
  frame without a tag of its own, the VLAN in the ERSPAN header) as **evidence** on the device ("Seen
  on VLAN 10, 20 via eth1" in the device panel). It does not change what a device *is*: a device is
  still its MAC address at one site, and one MAC seen on two VLANs is **one device**, flagged "several
  VLANs: check that this is one device" (a gateway, router or layer-3 switch is never flagged: it has
  an interface in every VLAN). Only the outer tag of a double-tagged frame is read. See
  [what is annotated and what is not merged](#vlans-in-41-what-is-annotated-and-what-is-not-merged).
  (The switch's SNMP data still gives each device's VLAN, see Settings > Switches.)

Linux versus macOS and Windows: many Linux network cards strip the outermost 802.1Q tag before the
frame reaches the capture library, so the kernel filter sees an untagged frame. On macOS, with Npcap
on Windows, and on Linux cards without VLAN offload, the tag stays in the bytes and the outer
EtherType is 0x8100 (or 0x88a8). DENIS's filter and parser handle both. If you want to see the tags
on Linux, `ethtool -K <iface> rxvlan off` keeps them in the frame. Decoding does not need that, but
**recording the VLAN does**: if your network card strips the tag before the capture library sees the
frame, DENIS sees no VLAN, records none and judges every address claim exactly as before 4.1 (the safe
direction). Whether a given card and libpcap version deliver the tag depends on the driver; check on
your own equipment, and switch the offload off on the capture interface if the device panel shows no
VLAN although the mirror carries them.

### VLANs in 4.1: what is annotated and what is not merged

- **Same address in two VLANs.** ARP does not cross a VLAN boundary, so two devices claiming the same
  address from two *different* VLANs are usually two networks that use the same private range, not
  poisoning. DENIS still raises the conflict (the default, `alert`, severity unchanged) but says so in
  the alert: "seen in different VLANs (10 and 20); usually address reuse, not spoofing". The
  administrator may choose `quiet` (setting `cross_vlan_conflicts` of the noise settings, API
  `PUT /api/noise {"cross_vlan_conflicts": "quiet"}`): such a conflict is then stored in the quiet stream
  with the reason `other_vlan`. It is **never** quiet when the claimed address is the gateway's or the
  claimant claims three or more addresses, in either mode. A frame without a visible VLAN counts as "the
  same VLAN as anything", so an untagged capture behaves exactly as before.
- **Not merged, not guessed.** While two VLANs claim an address, a result that names a device only by
  address (a port scan, a banner, a service probe) is skipped and counted
  (`denis_identity_ambiguous_ip_skips_total`) instead of being put on one of the two devices. The address
  index keeps the first holder; the ambiguity ends an hour after the last cross-VLAN claim.
- **A routed capture point.** A mirror of a router-to-firewall link carries every host's outbound
  packets with the *router's* MAC. Before 4.1 that made the router "claim" every host address and raised
  `arp_conflict` naming the router. The source address of an outbound packet now only binds an address
  nobody holds, never raises a conflict, and a device whose packets carry eight or more different source
  addresses within ten minutes is treated as a forwarder: nothing is bound to it. **Limit:** a host that
  spoofs source addresses only in outbound traffic is therefore no longer reported by that path (its own
  ARP claim still is).
- **Not in 4.1:** address spaces (VRFs), an L2 domain as part of a device's identity, splitting one MAC
  into two devices, the inner tag of a double-tagged frame, per-tunnel-session sources. A MAC address
  that two cloned machines share is still one device (flagged, not split).

### Do not overlap your mirrors

Each capture source (the main interface, each `--mirror-iface`) counts its own traffic and the counts
are **added**. Two sources that see the same packets (a switch session mirrored to two NICs, a TAP and a
SPAN of the same link, an ERSPAN delivered on two interfaces) therefore count every byte twice. DENIS
does not remove the duplicates in 4.1. It estimates the overlap: when the largest conversations of two
sources match in bytes (within 10 %) for three ten-second windows in a row, Health says "Capture
sources eth0 and eth1 appear to see the same traffic; traffic volumes are counted twice", and
`denis_capture_source_overlap_ratio{a,b}` shows the ratio. A TAP that gives each direction on its own
interface does not trigger it (each direction exists on one source only). The fix is on the switch:
mirror each link once. The estimate is approximate (the largest 2,000 conversations per window,
unaligned windows): a hint, never a correction.

The filter is the same expression three times: for an untagged frame, then behind `vlan and` for
one tag, then behind a second `vlan and` for two tags. libpcap's `vlan` keyword moves the offset of
every term after it, and the shifts add up, so the tagged clauses are always the last terms. With flow
accounting on (every mirror interface), the filter also admits a still-tagged frame by its inner
EtherType at fixed offsets, without the `vlan` keyword, so that a capture whose driver keeps the
tag in the frame does not depend on how libpcap treats `vlan` on Linux.

### Configuring RSPAN (Cisco Catalyst, IOS / IOS-XE)

Verify against your firmware's documentation; the commands differ by model and release (some access
switches need a reflector port).

On every switch in the path (and the source switch), define the RSPAN VLAN:

    vlan 999
     name RSPAN
     remote-span

On the source switch:

    monitor session 1 source interface Gi1/0/1 both
    monitor session 1 destination remote vlan 999

On the destination switch (the one with the DENIS network card on port Gi1/0/24):

    monitor session 1 source remote vlan 999
    monitor session 1 destination interface Gi1/0/24

Cable Gi1/0/24 to the network card named in `--mirror-iface`. The card needs no IP address.

## Mirrors delivered as IP packets (ERSPAN, VXLAN, Geneve, GRE)

A switch can mirror a port to a collector that is not on the same cable: ERSPAN wraps each mirrored
frame in a GRE packet addressed to the collector's IP address. Clouds do the same with VXLAN (AWS
VPC Traffic Mirroring, Azure virtual network TAP). To DENIS this arrives as ordinary IP traffic on a
normal network card. With a tunnel switched on, DENIS looks inside those packets and analyses the
**mirrored** frame exactly as if it had come from a local mirror port.

What this does and does not do:

- The outer packet (switch loopback to collector, or cloud network interface to collector) is
  **never** shown to the analysis. The switch and the collector do not become devices and their
  addresses do not appear in flow records. The packets are only counted (see "Counters").
- Only the frames you switch on are decoded. Nothing changes for a capture that does not ask for
  tunnels, and the kernel capture filter is only widened for the kinds you switch on.
- One level of tunnel only. A mirrored frame that is itself one of these tunnels (an overlay
  network carried inside a mirror) is dropped and counted as `nested`.
- The VLAN ID of the mirrored frame (ERSPAN carries it in its header) is recorded as evidence on the
  device when the inner frame has no tag of its own (see above); the ERSPAN session id is only a
  counter label.

### Switching it on

Command line, on `run` and on `agent`:

    denis run --iface eth0 --tunnel-mirror erspan
    denis run --iface eth0 --tunnel-mirror erspan,vxlan --flows

`--tunnel-mirror` takes a comma-separated list. `--erspan` is a hidden shorthand for
`--tunnel-mirror erspan`; use the list in documentation and scripts.

| Value | Decodes | Kernel filter term added |
| --- | --- | --- |
| `erspan` | GRE protocol 0x88BE (ERSPAN Type II) and 0x22EB (ERSPAN Type III) | `ip proto 47` (and `ip6 proto 47` with `--ipv6`) |
| `gre` | GRE protocol 0x6558 (transparent Ethernet bridging, as Linux `gretap` and Open vSwitch send it) | `ip proto 47` |
| `vxlan` | UDP port 4789 (RFC 7348) | `ip and udp dst port 4789` (and the `ip6` form) |
| `geneve` | UDP port 6081 (RFC 8926) | `ip and udp dst port 6081` (and the `ip6` form) |

Optional allowlists:

- `--erspan-session <ID>` (repeatable, 0-1023): only mirror sessions with these ERSPAN session ids
  are analysed. Everything else is dropped and counted as `filtered`.
- `--tunnel-vni <VNI>` (repeatable, 0-16777215): the same for VXLAN and Geneve network identifiers.
- `--tunnel-source <IP or CIDR>` (repeatable): only tunnel packets whose outer source address is on
  the list (the switch's ERSPAN origin address, the cloud interface) are analysed; others are
  dropped and counted as `source`.

**A tunnel is not authenticated.** Anyone who can send a GRE or VXLAN packet to the collector's
address can inject frames that DENIS analyses as mirrored traffic: a made-up device, a forged ARP
reply or DHCP answer. A local mirror port has the same trust only for those who can plug into the
monitored network. Set `--tunnel-source` to the sender's address, and also restrict who can reach
the collector with a firewall (and, in a cloud, a security group or network security group that
allows UDP 4789 only from the mirror source).

On `run`, **Settings > Network interfaces > Mirror tunnels** switches the same four kinds on and
off. A saved choice wins over the command line (also a saved "none"); it applies after DENIS
restarts, like the interface choice, because the kernel filter is built when the capture opens. The
session, VNI and source allowlists are command-line only.

IPv6 outer packets are only looked at with `--ipv6`. A tunnel decodes on every capture interface
(the main one and each `--mirror-iface`); for the mirrored traffic to be accounted as flows or
decoded as industrial protocols the capture needs the wide filter, as for any mirror (`--flows`, a
mirror interface, or `--profile ot`).

### Exactly what is accepted

Everything else on these protocols is counted as dropped, never guessed at.

- **Outer**: Ethernet (up to two VLAN tags are looked through), then IPv4, or IPv6 with `--ipv6`
  and no extension header except a fragment header. Protocol 47 (GRE) or UDP.
- **GRE** (RFC 2784 with the RFC 2890 key and sequence fields): the checksum, key and sequence
  fields are skipped according to their flag bits, and a present checksum is verified (a wrong one
  is dropped as `checksum`; it cannot be verified on a capture cut short by the snapshot length).
  The routing bit, the strict-source-route bit, the recursion-control bits and a non-zero GRE
  version are refused (`unsupported`).
- **ERSPAN Type II** (GRE protocol 0x88BE): an 8-byte header whose version field must be 1
  (otherwise `version`); the 10-bit session id and the truncated bit are read. The mirrored Ethernet
  frame follows.
- **ERSPAN Type III** (GRE protocol 0x22EB): a 12-byte header whose version field must be 2, the
  frame type must be 0 (Ethernet; type 2, an IP packet without Ethernet header, is `unsupported`),
  an 8-byte platform sub-header when the O bit is set, then the Ethernet frame. The direction
  (ingress or egress) is read but not used.
- **ERSPAN "Type I"** (a GRE packet with protocol 0x88BE and no ERSPAN header at all) is **not**
  accepted: it cannot be told from a malformed Type II header, and no specification is at hand to
  check it against.
- **Plain GRE** (`gre`, protocol 0x6558): the Ethernet frame follows the GRE header directly.
- **VXLAN**: flags byte 0x08 (VNI valid), or 0x88 (with the group-policy bit); reserved bytes are
  ignored as RFC 7348 requires; anything else (VXLAN-GPE, reserved flag bits) is `unsupported`.
  The UDP checksum is not verified (VXLAN senders commonly send 0).
- **Geneve**: version 0, protocol type 0x6558, options skipped by their length; an OAM frame or one
  with the critical-options bit is `unsupported` (their meaning is not understood, so the frame is not
  guessed at).
- **ERSPAN marker packets** (UDP 8880, first bytes 00 40 22 eb) that a Cisco Nexus switch sends
  beside its sessions carry a timestamp, not a mirrored frame: counted as `marker`. (Recognised from
  the two Nexus captures on the Wireshark wiki; the field layout is not documented anywhere DENIS
  could check, so only that prefix is matched.)
- **Bounds**: the mirrored frame must be at least 14 and at most 9,216 bytes (`inner_size`);
  every length field is checked against the packet and against the wire length the capture reports
  (a "lying" length is `malformed`); an outer packet that is an IP **fragment** is not reassembled
  (`fragment`); nothing is allocated per packet.

### Counters, Health and metrics

`/metrics` (Prometheus exposition, as the other `denis_` metrics):

| Metric | Meaning |
| --- | --- |
| `denis_tunnel_frames_total{kind}` | mirrored frames decapsulated and analysed; `kind` is `erspan2`, `erspan3`, `gre`, `vxlan`, `geneve` |
| `denis_tunnel_dropped_total{reason}` | tunnel packets skipped: `fragment`, `malformed`, `unsupported`, `version`, `checksum`, `filtered`, `inner_size`, `nested`, `marker`, `source` |
| `denis_tunnel_session_frames{kind,session}` | frames per ERSPAN session id or VXLAN/Geneve VNI since start (at most 1,024 sessions are tracked; more are not listed) |
| `denis_tunnel_seen_while_off_total{kind}` | ERSPAN or VXLAN packets that arrived while that decoder was off |

The Health page says so when tunnel traffic reaches the collector while it is off ("GRE/ERSPAN
traffic is reaching this collector, but decoding of it is switched off ... --tunnel-mirror erspan")
and when a steady share of the tunnel packets arrive fragmented (see MTU below).

`denis replay capture.pcap` decodes every tunnel kind found in a capture file and prints a line
"mirror tunnels: N mirrored frames decoded, M tunnel packets skipped (...)". A capture taken with
`tcpdump -i eth0 -w erspan.pcap 'ip proto 47 or udp port 4789'` at the collector replays as the
mirrored network.

### Which interface, and what the collector needs

- The tunnel is addressed to an **IP address of the collector**. The mirror source must be able to
  route to it. Capture on the interface that owns that address: normally the same network card as
  `--iface`, an ordinary interface, not a mirror port. It does not need promiscuous mode (the
  packets are addressed to it); DENIS asks for it anyway where the driver allows.
- The collector's kernel does not listen for GRE or VXLAN, so it answers each packet with an ICMP
  "protocol/port unreachable" to the switch. Capture happens before the firewall, so dropping them
  loses nothing and stops the replies:

      iptables -I INPUT -p gre -j DROP
      iptables -I INPUT -p udp --dport 4789 -j DROP

- A mirror interface without an IP address (`--mirror-iface`, for local SPAN) cannot receive a
  tunnel: use the interface that has the address.
- ERSPAN needs the mirrored traffic of every session the switch sends (several sessions can go to
  one collector, told apart by the session id and the source address).

### MTU and fragmentation

The tunnel adds a header to every mirrored frame: ERSPAN Type II is 20 (IPv4) + 8 (GRE with
sequence number) + 8 (ERSPAN) = **36 bytes** on top of the mirrored Ethernet frame, Type III 40 or
48, VXLAN 20 + 8 + 8 = 36 (50 with the outer Ethernet header, the figure vendors quote). A
mirrored frame of 1,514 bytes therefore becomes a packet of about 1,550 bytes, which does not fit
an ordinary 1,500-byte path. What happens then depends on the sender: it fragments the outer packet
(DENIS **does not reassemble** fragments, so those frames are lost and counted as `fragment`),
or truncates the mirrored frame (ERSPAN `T` bit), or drops it.

Fix it on the path: raise the MTU between the mirror source and the collector by at least 60 bytes
over the largest mirrored frame (9,000-byte jumbo frames end to end are the clean answer), or tell
the switch to truncate mirrored frames where it can (many ERSPAN sources have an `mtu` or
truncation setting; the headers are what identify a device).
The capture itself keeps the first 1,600 bytes of each packet; a larger mirrored frame is analysed from
its first part and its full length is still counted from the outer headers.

### Throughput

Every mirrored byte arrives again as tunnel bytes plus about 50 bytes per frame, on a normal network
card. A 10 Gbit/s port mirrored to a 1 Gbit/s collector card loses packets, and the loss is silent
at the switch; DENIS shows kernel drops on the Health page. Measure with `examples/tunnel_decap_bench.rs`
(`cargo run --release --example tunnel_decap_bench`): decapsulating a frame costs a small multiple
of the cost of looking at an ordinary one. Prefer mirroring the ports you need (uplinks, server
ports), not everything, and use the session allowlist when a switch sends several sessions to one
collector.

### Configuring the sender

Verify every example against your firmware's documentation: syntax differs between releases and
models, and these examples were not run against real hardware (see "Verified and not verified").
`192.0.2.10` is the collector, `192.0.2.1` the switch.

**Cisco IOS-XE (Catalyst 9000 and others that support ERSPAN source sessions)**

    monitor session 1 type erspan-source
     source interface GigabitEthernet1/0/1
     destination
      erspan-id 100
      ip address 192.0.2.10
      origin ip address 192.0.2.1
     no shutdown

**Cisco NX-OS (Nexus)**

    monitor session 1 type erspan-source
      erspan-id 100
      vrf default
      destination ip 192.0.2.10
      source interface ethernet 1/1 both
      no shut

NX-OS also selects the header type per session (`header-type 2` or `3`) on releases that support
Type III; both are decoded. A Nexus switch additionally sends marker packets (see above).

**Arista EOS** can mirror to a GRE tunnel destination on some platforms (`monitor session ...
destination tunnel mode gre ...`). The exact options and which GRE protocol type is sent differ by
platform; **check that it sends ERSPAN (GRE protocol 0x88BE) or plain Ethernet-in-GRE (0x6558)** and
switch on `erspan` or `gre` accordingly.

**Juniper, MikroTik, Ubiquiti, FS and others**: not covered. MikroTik's packet-sniffer streaming
uses TZSP (UDP 37008) and is **not** supported. Use a vendor's ERSPAN or Ethernet-in-GRE mirror
if it has one, and say which in a bug report with a capture taken at the collector:
`tcpdump -i <iface> -w erspan.pcap -c 200 'ip proto 47 or udp port 4789'`.

**A Linux host as the sender** (useful for a first test without a switch; iproute2 and the kernel
document these):

    # ERSPAN Type II toward the collector, session id 100
    ip link add dev erspan1 type erspan local 192.0.2.1 remote 192.0.2.10 seq key 100 erspan_ver 1 erspan 123
    ip link set erspan1 up
    # mirror everything arriving on eth1 into it
    tc qdisc add dev eth1 ingress
    tc filter add dev eth1 parent ffff: matchall action mirred egress mirror dev erspan1

    # the same as plain Ethernet-in-GRE or VXLAN (VNI 42)
    ip link add dev gretap1 type gretap local 192.0.2.1 remote 192.0.2.10
    ip link add dev vxlan1 type vxlan id 42 dstport 4789 local 192.0.2.1 remote 192.0.2.10

### AWS VPC Traffic Mirroring

AWS copies the traffic of a source network interface to a target as VXLAN (UDP 4789). The target
can be a network interface of the instance that runs DENIS. Sources and targets must be supported
instance types (AWS documents which; Nitro-based instances at the time of writing).

    aws ec2 create-traffic-mirror-target --network-interface-id eni-0target...
    aws ec2 create-traffic-mirror-filter --description "all"
    aws ec2 create-traffic-mirror-filter-rule --traffic-mirror-filter-id tmf-... \
        --traffic-direction ingress --rule-number 100 --rule-action accept \
        --source-cidr-block 0.0.0.0/0 --destination-cidr-block 0.0.0.0/0
    aws ec2 create-traffic-mirror-filter-rule --traffic-mirror-filter-id tmf-... \
        --traffic-direction egress --rule-number 100 --rule-action accept \
        --source-cidr-block 0.0.0.0/0 --destination-cidr-block 0.0.0.0/0
    aws ec2 create-traffic-mirror-session --network-interface-id eni-0source... \
        --traffic-mirror-target-id tmt-... --traffic-mirror-filter-id tmf-... \
        --session-number 1 --virtual-network-id 42

On the DENIS instance: allow inbound UDP 4789 in its security group from the source's address, run
`denis run --iface <the target's interface> --tunnel-mirror vxlan --tunnel-vni 42 --tunnel-source <the source interface's private address>`, and drop the
packets in the host firewall as above. What a cloud mirror shows is IP traffic: **there are no ARP
or DHCP broadcasts in a VPC**, so what DENIS learns about the mirrored instance is its flows and
protocols and (from the inner frame) its interface address, not neighbour discovery. AWS adds about
50 bytes per packet; see the MTU section (the `--packet-length` option of a session truncates
mirrored packets).

### Azure virtual network TAP (vTAP)

Azure's virtual network TAP copies a network interface's traffic to a destination (a network
interface or an internal load balancer front end) encapsulated in VXLAN. Microsoft documents a
fixed VXLAN identifier for it and the feature's availability has varied (preview or general
availability depending on the region and time): read Microsoft's current documentation, then run
`denis run --iface <the destination's interface> --tunnel-mirror vxlan`, with the network security
group allowing UDP 4789 to the collector. As with AWS, expect IP traffic, not ARP or DHCP.

## Verified and not verified

Honestly, in the order of confidence:

**Verified (automated tests and what they cover)**

- libpcap compiles every filter string DENIS builds, and the compiled filter admits tagged
  (802.1Q, 802.1ad, double) and untagged frames of each protocol alike and the outer packets of
  each enabled tunnel kind only. This is libpcap on a dead Ethernet handle: **the Linux-specific
  VLAN offload path of libpcap is not exercised**.
- Every protocol parser reads the same frame identically with 0, 1 or 2 VLAN tags, and the VLAN id of
  each (outer, inner, and the ERSPAN II/III header field) is read as the unit tests say.
- Hand-built ERSPAN II and III (with and without platform sub-header), GRE (every combination of
  checksum, key, sequence), VXLAN, Geneve (with options), IPv6 outer packets, VLAN-tagged outer
  frames, fragments, lying lengths, nested tunnels, truncation at every byte offset, thousands of
  randomly damaged packets, and a fuzz target (`fuzz/fuzz_targets/tunnel.rs`).
- Two real public captures: the Cisco Nexus ERSPAN marker packets on the Wireshark wiki (the
  decoder recognises them and does not turn them into traffic). **No public capture of actual
  ERSPAN-encapsulated frames was found** on that wiki: the data-packet formats above were built
  from the ERSPAN specification and the Linux kernel's implementation, not checked against a vendor
  capture.
- `denis replay` of a capture file with every tunnel kind.

**Not verified**

- Any real switch, router or cloud service as the sender: the exact bytes Cisco, Arista, AWS and
  Azure send (field values, GRE flag usage, optional fields, the marker format beyond its first
  four bytes) are checked against specifications and documentation only.
- Behaviour of libpcap's `vlan` clauses on a live Linux interface with and without VLAN offload.
- Throughput at line rate on real hardware (the benchmark measures decapsulation cost per frame
  only).
- ERSPAN Type III frame types other than Ethernet, GRE routing, VXLAN-GPE, Geneve options: not
  decoded by design.
- Path-MTU behaviour of each sender (fragment, truncate or drop).

Tests on real hardware are planned; until they are done, treat a mirror from a vendor you have
not seen working as unverified, and send a capture (see above) if it does not decode.

## Details from the console

Explanations that used to be printed on the console screens. The console shows them behind a small ? button.

* Mirror interfaces are optional and capture-only: never probed, never used for discovery. Use one on a switch mirror or SPAN port to see traffic between other devices. Saved with the Save button above.
