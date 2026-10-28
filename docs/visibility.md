# What DENIS cannot see

DENIS learns about your network from the packets that reach its capture ports. It sees only those. This
page explains the **What DENIS cannot see** section of Health (Health > What DENIS cannot see) and how to
set up capture so that DENIS sees more of what you care about. It is written as a deployment guide: each
finding on the page links to the paragraph below that explains it.

The section shows what DENIS can see and what it knows it cannot. It never says that DENIS sees
everything, and it never gives one coverage number. Some loss cannot be measured by DENIS at all: a
packet that the switch or the mirror session dropped before it reached the capture port leaves no trace.

Every row says how sure it is:

| Word | Meaning |
| --- | --- |
| Measured | DENIS counted it on a capture port. |
| Estimated | Worked out from the devices DENIS has seen (for example, "no device was seen in this network for three days"). It can be wrong: a quiet network looks like a missing mirror. |
| Not measurable | DENIS has no way to know (for example, loss in the switch before a packet reaches the capture port). |

The picture shows the section for an example network (the numbers are made up): one mirror that loses packets and
delivers many of them twice, a VLAN that does not arrive, and a monitored network without a device.

![What DENIS cannot see](img/visibility.png)

## What the section shows

* **Feeds.** One row per capture interface (the main interface and each mirror): its state, when the last
  packet arrived, the packets it delivered, and what was lost or could not be read on the way. The numbers
  are counted since DENIS started, and over the last 24 hours once the hourly samples exist. Hours without a
  sample mean that DENIS was not running, not that nothing arrived.
* **Findings.** Plain sentences with what to do. Problems that DENIS measured come first; notes of
  information follow.
* **Networks.** The networks you told DENIS to monitor, with the devices seen in each and when the newest
  was seen. Networks whose traffic reaches a capture port, but that are not monitored, are listed with an
  **Add as monitored** button. DENIS never adds a network by itself.
* **VLANs.** The VLANs each interface is expected to carry (you can list them) against the VLANs seen on it
  in the last 24 hours. The seen list is an estimate: DENIS knows which VLANs each device was seen in and
  through which interface, not which VLAN arrived on which interface.
* **History.** The counters are sampled every few minutes and kept per hour for 90 days, so a question such
  as "was it receiving traffic last Tuesday" has an answer.

Remote sites (agents) show their last report. Their capture counters are not sent to the master in this
version, so the page says "not measured" for them.

## Link

DENIS reports a capture interface without a link, one that does not exist, or one it could not open.

* The cable may be unplugged, or the switch port may be off or in an error state.
* For a mirror, the monitor session on the switch may have been removed or changed; check that its
  destination is the port the cable is plugged into.
* An adapter that was unplugged, or an interface that was renamed, is "missing". Plug it in or correct the
  name under Settings > Capture.
* "Could not be opened" is usually a missing capture permission. Health shows the exact error.

An interface that has had no packet for 15 minutes is shown as quiet. A quiet network does this, and so does
a mirror session that sends nothing.

## Dropped packets

* **Dropped by the computer** (kernel drops): DENIS did not read the packets fast enough. Mirror less
  traffic, for example fewer ports or one direction, or use a faster computer.
* **Dropped by the network card**: the card's receive ring was full. Look at the ring size with
  `ethtool -g <interface>` and raise it with `ethtool -G <interface> rx <size>`.

A feed is reported when the drops are at least 0.1 % of the packets and at least 100 packets. Everything DENIS
shows for a feed is based on the packets it did read.

## Unreadable and cut-short frames

* **Unreadable** frames have a network header DENIS cannot read. The usual cause is a mirror that adds a
  header DENIS does not unwrap: an ERSPAN, GRE, VXLAN or Geneve tunnel (see [Tunnel
  mirroring](tunnel-mirroring.md)) or a vendor tag. Damaged frames do the same.
* **Cut-short** frames were captured with fewer bytes than they had on the wire. Their content is missing,
  so names, device fingerprints and industrial messages cannot be read. Raise the packet size limit of the
  mirror session, or turn off packet slicing on the switch.

A feed is reported when at least 1 % of its packets are affected, and at least 100 frames.

## Receive offload

A network card with receive offload (GRO or LRO) merges several packets into one large frame before DENIS
sees it. The frame is larger than the network can carry. Counting bytes still works, but industrial
decoders lose the boundaries of the original packets and can miss messages. DENIS reports it when a feed
received at least 20 such frames and the last was within a day. Switch the offload off on the capture
interface:

```
ethtool -K <interface> gro off lro off
```

Make it permanent in your network configuration, because it does not survive a reboot. The same advice is in
the [OT guide](ot-guide.md).

## Duplicate packets

A mirror session that copies both directions of two ports that talk to each other hands DENIS every packet
twice. Traffic volumes of that feed are then counted too high. By default DENIS counts the copies (Settings >
Capture, duplicate packets: count) and removes none. It warns when more than 5 % of the packets looked at are
copies. A retransmission is not a copy: it usually arrives hundreds of milliseconds later (and removal never touches
IPv6 packets, IPv4 packets with ID 0, TCP segments without payload or fragments, where a second packet can look
exactly like a copy).

The best fix is on the switch: mirror one direction per port, or mirror the VLAN instead of its ports. When the
switch cannot be changed, an administrator can switch **Remove copies** on for that interface (Settings >
Capture, duplicate removal per interface). DENIS then drops the second copy before any analysis, and the feed
row shows how many it removed. It never removes:

* an industrial message (GOOSE, Sampled Values, PROFINET, or TCP and UDP on an industrial port), so no
  industrial command is lost;
* a copy that came on another link (other Ethernet addresses or another VLAN, as on both sides of a router):
  it carries the layer-2 evidence of the device on that side, so it is counted and kept;
* the first copy, or anything on an interface that only counts or is off.

Removal is never on by default and is switched on per interface, with a confirmation. If more than 60 % of an
interface's packets turn out to be copies (a doubled stream is 50 %), or its fixed table has to give up more
than 10 % of its packets too early, DENIS switches that interface back to counting only, records it in the
audit log and warns on Health until an administrator switches removal on again.

Two capture interfaces of the same DENIS that see the same traffic are reported as an estimate ("appear to see
the same traffic"). With **Merge copies across capture interfaces** switched on, DENIS also looks for a packet in
the table of the interface ranked above (the one marked to keep its copy, then the main interface, then by name):
an interface set to remove copies drops a packet the higher-ranked one already delivered; one that only counts
counts it. This works within one DENIS only. Copies between a remote site's agent and the master are not
merged.

## Where to put the sensor

* DENIS sees the traffic that reaches its capture port. On a switch, traffic between two other devices does
  not reach it unless the switch mirrors it. With one network port only, DENIS sees what that port receives
  (broadcasts, and the traffic to and from the computer itself).
* Use a **mirror (SPAN) port** on the switch, or a network **TAP**, cabled to a spare network card of the
  DENIS computer, and add it as a mirror under Settings > Capture. A TAP delivers every packet of one link,
  never drops under load and costs a device. A SPAN port is free but can drop packets when the mirrored
  ports carry more than the destination port.
* A mirror delivered across the network (RSPAN, ERSPAN, VXLAN) is covered in [Tunnel
  mirroring](tunnel-mirroring.md). ERSPAN and the other tunnels are off by default.
* Networks behind a router: if you mirror only the ports of one switch, the traffic of a routed network is
  seen only where it crosses those ports. A routed network that matters needs its own mirror (the router's
  port, or the switch that carries it) or its own capture computer or agent.
* Put a sensor where the traffic you care about crosses: the uplink to the router sees the traffic between
  networks and to the internet, but not the traffic inside one network.

## Both directions

A mirror may carry the received packets of a port, the sent packets, or both. DENIS cannot measure which. A mirror
of one direction shows the requests but not the answers, or the other way around, and flows then look
one-sided. On the switch, mirror both directions of each port (received and sent), but each packet once (see
duplicates above). On a Cisco switch the keyword is `both`; other vendors call it "rx and tx" or "ingress and
egress".

DENIS **estimates** it from the TCP conversations it sees. A TCP conversation always has two directions (even a
one-way transfer gets acknowledgements back), so one of at least 10 packets with bytes in one direction and none in
the other is a sign of a one-sided view. Per capture interface and remote network (/24), over the last 30
minutes: when at least 50 such conversations were seen and more than 80 % of them show the same single direction,
the section lists the pair under **Traffic seen in one direction only** and adds a finding, for example "on eth1
DENIS sees traffic from 10.0.20.0/24 towards 10.0.30.0/24 but almost none coming back". The local side is the
networks of the devices involved.

It is an estimate, labelled as one, and never an alert: some networks route the replies over another link on
purpose (asymmetric routing), and then the advice does not apply. Where it does, mirror both directions of the port
or VLAN. Nothing is measured per packet for it: DENIS counts the flow windows it already keeps. A remote site's
conversations are not judged on the master.

## Networks

* **No device seen in a monitored network.** DENIS estimates this from the devices it knows. A network can be
  quiet, new, or its traffic may not reach a capture port. Check that a mirror of the ports or the VLAN
  that carries it exists. If the network is no longer used, remove it under Settings > Capture, monitored
  networks.
* **Traffic from a network that is not monitored.** DENIS saw frames from addresses outside every monitored
  network and records no devices from them. If it is your network, add it (the **Add as monitored** button
  opens the setting); if it is outside traffic, for example the internet side of a router, leave it.

## VLANs

If you list the VLANs an interface should carry (on the page, **Expected VLANs**), DENIS compares the list with
the VLANs seen in the last 24 hours:

* a VLAN on the list that was not seen: the switch may not be mirroring it. Add it to the monitor session, or
  check that the trunk carries it. A VLAN that is quiet looks the same;
* a VLAN seen that is not on the list: information only.

VLANs are known to DENIS only when frames reach it with a VLAN tag (see [Tunnel
mirroring](tunnel-mirroring.md#rspan-and-vlan-tagged-frames)); a Linux network card may strip the tag.

## IPv6

IPv6 traffic that reaches a capture port while DENIS runs with IPv6 switched off is not analysed. DENIS counts
it in a short sample and tells you. To include it, start DENIS with `--ipv6`.

## Remote sites

A remote site's agent sends its devices and flows to the master, but not its capture counters in this
version. Open the site's own console for its capture feeds. The page shows when the agent last reported, and
warns when it has been quiet for more than 15 minutes.

## For integrations

`GET /api/visibility?site=` returns the same report as JSON (see the [API reference](api.md)): the feeds, the
networks, the VLANs, the findings with their text, values and the link to this guide, and the history. A token
needs the Network area to read it.
