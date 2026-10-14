# Using DENIS on an industrial (OT) network

Industrial networks differ from office networks in ways that change how a monitoring tool must behave:

* Devices are **fragile**. Some PLC/RTU firmware crashes on unexpected connections, ping floods or port scans.
* Traffic is **mostly internal**: the interesting question is not "who talks to the Internet" but "**who talks to
  which controller, and are they reading or changing something?**"
* Change is **rare and deliberate**. A new device, a new communication path, or a STOP/download command is
  significant.

DENIS therefore has an OT mode built around **passive observation**.

## Start in OT mode

```bash
denis run --profile ot --iface eth1
```

`--profile ot` means:

* **Listen only.** No ARP sweep, no ping, no port scan (add `--active` to allow a *slow* ARP sweep, paced
  50 ms per address).
* **Traffic analysis on**: industrial protocols are decoded and a communications matrix is built.
* In *any* profile, devices identified as industrial (by protocol, vendor or type) are **never pinged or
  port-scanned**. Use `--exclude 10.20.0.0/24` (repeatable) to forbid probes to whole ranges; they are still
  observed passively.

### Where to connect

Industrial conversations are only visible if they cross the collector's interface. Connect DENIS to a **SPAN /
mirror port** or a **network TAP** of the switch that carries the cell/area traffic. Use a dedicated capture
interface with no IP address of its own if you can, and run one collector per segment (or per cell). A read-only
mirror port cannot disturb the process network.

### Layer-2 traffic: GOOSE, Sampled Values, PROFINET

Some industrial traffic is not IP at all and stays inside one switch or VLAN, so **where you mirror decides what you see**:

* **IEC 61850 GOOSE** (multicast, EtherType 0x88B8) stays on the **station bus**. **Sampled Values** (0x88BA) stay on the
  **process bus**. A mirror of the uplink to the control centre carries MMS and IEC 104 but usually **no GOOSE**. To see GOOSE
  publishers, mirror a station-bus switch (or its inter-switch link); for Sampled Values, a process-bus switch.
* **PROFINET** real-time traffic and DCP stay inside the cell: mirror the cell switch. Connection management (UDP 34964) crosses a
  router only in unusual setups.
* GOOSE is decoded by default whenever OT decoding is on (it is a low rate). **Sampled Values are off by default**: every stream
  sends about 4,000 frames per second, and a process bus carries 10–30 streams. Switch them on under *Settings → Network
  interfaces → Advanced → IEC 61850 Sampled Values* (or start with `--ot-sv`); the change applies after a restart. DENIS then reads at most
  one frame per stream per second, but the capture interface still receives every frame, so size the collector for it.
* Frames carrying a VLAN tag (common for GOOSE and PROFINET) are accepted. Which frames reach the program on a given network card
  depends on its VLAN offload; check that the publishers you expect show up on the **OT** tab within a few minutes.
* Redundant networks: PRP duplicates parse normally. HSR-tagged frames (EtherType 0x892F) are **not** unwrapped yet.
* A layer-2 message has no IP address. GOOSE and Sampled Values publishers appear as devices without an address, and a multicast
  publication is never a "conversation" (it has no client), so it is not in the communications matrix. Zones made of address
  ranges cannot judge layer-2 traffic.

## What it recognises

Passively decoded (nothing is ever sent):

| Protocol | Port | Reads / writes / control detected | Identity learned |
|---|---|---|---|
| Modbus/TCP | 502 | read, write, diagnostics (restart/listen-only) | – |
| Siemens S7comm (S7-300/400, S7-1200/1500 with PUT/GET) | 102 | read/write variable, **program download**, **PLC start/stop** | – |
| Siemens S7comm-plus (S7-1200/1500: TIA Portal, most HMIs) | 102 | session set-up, read, write. **Stop/start and program download are not reported as control commands** (see below). Marked `s7plus` | engineering or HMI client |
| EtherNet/IP + CIP | 44818 | CIP read/write, reset/start/**stop** | vendor, product, serial, revision (ListIdentity) |
| DNP3 | 20000 | read, write, select/operate, restarts, stop application | – |
| BACnet/IP | 47808 | ReadProperty, WriteProperty, **ReinitializeDevice**, DeviceCommunicationControl | device instance, vendor (I-Am) |
| OPC UA (binary, `opc.tcp`) | 4840 | read, browse, subscribe/publish, **write**, history update, address-space changes, **method call (counted as a write)**, session and the kind of user identity (anonymous, user name, certificate, issued token). Only when the channel is not encrypted: see *Encrypted traffic* | the endpoint address the client asked for |
| IEC 61850 MMS (substations; also ICCP/TASE.2) | 102 | read, write, **operate / select** (the IEC 61850 control model), program-invocation start/stop/reset/kill, domain download, file transfer, dataset changes. An IEC 61850 device is no longer listed as a Siemens PLC just because it answers on port 102 | vendor, model, revision (Identify answer) |
| IEC 61850 GOOSE | link layer (0x88B8) | who publishes, not what: GOOSE is multicast, so there is no "conversation" | the control blocks each publisher announces (at most 8 per device) |
| IEC 61850 Sampled Values | link layer (0x88BA) | off by default: see *Layer-2 traffic*. Checked with hand-built frames only (no public capture exists) | the streams each publisher announces |
| PROFINET IO | UDP 34964 (connection management), link layer (DCP Set) | a controller connecting to an IO device, record read/write, **DCP set station name / IP address**, **DCP factory reset** | order number, serial number and firmware (I&M data; checked with hand-built frames only: the public capture shows the record read, not its answer) |
| CODESYS V2 / V3 | TCP 1200, 2455, 11740, UDP 1740–1743 | **identified only**: the runtime is recognised and the path is shown, nothing is read, written or controlled in the sense of a command | – |
| IEC 60870-5-104 | 2404 | commands (types 45–64), clock sync, reset | – |
| Omron FINS | 9600 | memory/parameter/program area read/write, **run/stop** | – |
| HART-IP | 5094 | protocol and session only (see below) | – |
| MQTT | 1883 | PUBLISH (write), SUBSCRIBE (read) | – |
| CoAP | 5683 | GET (read), POST/PUT/DELETE (write) | – |
| KNXnet/IP | 3671 | protocol and message kind only (see below) | – |
| LLDP, CDP | link layer | – | system name/description, port, capabilities |
| PROFINET DCP | link layer | Identify/Hello answers (and Set, above) | station name, vendor, role, IP |

How much of a command stream each decoder follows (TCP; "complete messages" = every one in a segment, up to 16):

| Protocol | Messages per segment | Split across segments | Protocol-level fragments |
|---|---|---|---|
| Modbus/TCP | all complete | held and completed | not applicable |
| S7comm | all complete (TPKT) | held and completed | COTP pieces (EOT clear) joined and decoded when the last one arrives (up to 4 KB) |
| S7comm-plus | all complete (TPKT); **stop/start/download never reported as control, by design** | held and completed | COTP pieces joined as for S7comm; S7comm-plus's own continuation fragments are not followed |
| IEC 61850 MMS | all complete (TPKT); every item of a write is checked (an `Oper` as a second item counts) | held and completed | COTP pieces joined as for S7comm |
| EtherNet/IP + CIP | all complete; a Multiple Service Packet (0x0A) and an Unconnected Send (0x52) are opened (2 levels, 16 services) | held and completed | not applicable |
| DNP3 | all complete link frames, in a TCP segment or a UDP datagram | held and completed | transport segments (FIR to FIN) joined: the function code is read from the joined data, wherever the frames put it, and the later frames of a message are not counted as messages of their own |
| IEC 104 | all complete APDUs (a supervisory frame in front of a command is fine) | held and completed | not applicable |
| OPC UA | all complete chunks; **no control class**: a method call is a write | held; long chunks classified from their first 1 KB | the first chunk of a multi-chunk message is classified, the middle ones are "message chunk" |
| MQTT | all complete packets | held and completed | not applicable |
| BACnet, FINS, CoAP, KNX (UDP) | first message of the datagram (these protocols carry one message per datagram) | not applicable | not followed |
| HART-IP, CODESYS | first message only (named, not read) | no | no |

**IP fragments** (since 4.1.2): for every protocol above, over TCP and UDP, IPv4 and IPv6 (Fragment extension
header), a datagram between two local devices that was split into IP fragments is put back together before it is
decoded, when it goes to or comes from one of these ports, in any fragment order. Limits and refusals are under
[Limits to know about](#limits-to-know-about).

Each decoder verifies the protocol's own signature (magic bytes, a length field that has to match, a declared
version). **No decoder checks a checksum or CRC**, and DENIS does not validate TCP sequence numbers against the
receiver's state, so a forged frame that looks right is decoded like a real one. So ordinary traffic that merely uses the same port number is not mistaken for industrial traffic,
and **a port number by itself is never treated as identification**. **HART-IP**, **KNXnet/IP** and **CODESYS** are named and
their direction is known, but not read from further: HART's command table and KNX's cEMI/APCI layout would need a
capture to check the exact byte offsets against, which DENIS did not have, so it stops at "this is HART-IP" /
"this is KNXnet/IP" rather than guess at read vs write. CODESYS is the same, with one more caveat: CODESYS publishes no
protocol description and **no public capture of its traffic was found**, so the CODESYS signatures are built from
third-party research papers and have only been tested against hand-written byte fixtures, never a real runtime. The
UDP check (1740–1743) is weaker than the TCP one. If port 1200 shows false CODESYS paths on your network, tell us:
it is shared with unrelated software and V2 on that port can be dropped. The other decoders (including HART-IP and
KNXnet/IP) have been checked against a real capture of that protocol, listed in `tools/ot-samples.sh`; OPC UA is checked
against traffic from an independent open-source implementation (`tools/make-opcua-sample.py`).

What the 2026 decoders have been checked against, honestly. **Real recordings**: S7comm-plus reads, writes and explore requests (S7-1200
and S7-1511 with TIA Portal and HMIs), MMS read, write, name list, identify and a first write, GOOSE publishers, PROFINET DCP Set IP
address and a connection-manager record read. **Hand-built frames only** (no public recording exists, or the available ones are
unusable): MMS operate/select, start/stop and domain download, Sampled Values, the PROFINET I&M identity and DCP factory reset, the
S7comm-plus client kind, and the guard against encrypted OPC UA being mistaken for a write. **Recognised only, not decoded**: CODESYS
(no public capture). The first time one of the hand-built cases appears on your network, confirm it, and tell us if it is wrong.

How much each protocol shows, in plain words:

* **Decoded**: the function (read, write, control) is told from the wire: Modbus, S7comm, EtherNet/IP, DNP3, BACnet,
  OPC UA (unencrypted or signed channels), IEC 61850 MMS, IEC 104, FINS, MQTT, CoAP, PROFINET connection management and DCP Set.
* **Decoded in part**: S7comm-plus. Reads, writes and session set-up are told apart (session set-up is never counted as a write). With TLS only the path shows. A CPU stop/start or a program
  download from TIA Portal looks like any other write to a passive observer unless a recording of it exists to check
  against, and none was available, so these are **not** reported as control commands (the rule `ot_control_command`
  does not fire for S7-1200/1500 over S7comm-plus). The classic S7comm on the same PLC still reports them.
* **Identified only**: HART-IP, KNXnet/IP, CODESYS. The path and the protocol are shown; the commands are not.
* **Publisher only**: GOOSE and Sampled Values show who publishes and which control blocks or streams they announce; the process
  values inside (breaker positions, measurements) are never read or stored.

Ports whose protocol has **no public, checkable signature** (Niagara Fox 1911, GE SRTP 18245, MELSEC 5007, PCWorx
1962, CODESYS V3 gateway 1217) are used **only** for the *"industrial port crossing the boundary"* finding below: seeing that
port leave the network is worth a look regardless of what is really on it, but DENIS never names a conversation,
or judges a read from a write, from a port number alone. The CODESYS runtime ports (11740, 2455) are in that list *and*
decoded as above, so the finding still fires from the port alone.

From this DENIS derives **roles** (server/PLC vs client/HMI), types (`plc`, `rtu`, `hmi`, `building controller`,
`industrial switch`, `industrial device`…) and icons automatically, and shows them on the **OT** tab.

## The OT tab

* **Industrial devices**: name, IP, Purdue level, zone, type, protocols with roles (`S` server, `C` client) and
  the identity the device announced (product, vendor, serial).
* **Communications matrix**: `client → server`, protocol, counts of **reads, writes, control commands**, last seen.
  Rows with control commands are red, with writes amber. Filter by protocol or show only writes/control.
  **Commands seen** lists the functions the path used and how often (`write single register (6)` ×1200, `PLC stop
  (0x29)` ×1). Click one to create an [OT rule](#ot-rules) for it, prefilled with that protocol and target.

Set **Purdue level** (0–5, 3.5 for the DMZ) and **Zone / cell** per device (Edit asset). They appear in the OT
tab, the matrix and reports, so you can spot, for example, an office-level (L4) device talking to a controller
(L1) directly.

## OT alerts

| Rule | When | Score |
|---|---|---|
| `ot_new_conversation` | a client/server/protocol path that did not exist during the learning period appears | 50; +20 writes; +25 control commands; +10 target is a controller; +10 the client itself is new (<1 h); −15 only session set-up |
| `ot_control_command` | DENIS **sees** a STOP/START, program download, restart or operate command (not every command can be seen: read *Limits to know about*; S7comm-plus stop and download are never reported). Never suppressed by learning | 85 the first time this source does it to this target; 45 if it has before; 60 during learning; +10 for industrial targets. Repeats held for 10 min |
| `ot_goose_conflict` | the same **GOOSE control block** (`gocbRef`) is published from two different source MAC addresses: a spoofed or duplicated publisher. PRP copies (one address) do not count; blocks both addresses published during learning are the baseline | 60; +15 a made-up (locally administered) address; +10 different manufacturers; +10 the newer publisher is new (<1 h). Once per 6 h per device, filed under the newer publisher; confRev and the simulation flag are evidence only |
| `ot_internet_exposure` | industrial protocol traffic between a device and an address **outside the local network** | 90, no learning period; once per 6 h per device |

*Learning:* for the first 24 hours (`--learning-minutes`), normal paths are recorded silently. Run DENIS through a
**representative production period** (including maintenance windows if engineers download programs) before
relying on `ot_new_conversation`.

*Engineering workstations* legitimately download programs. After the first alert, an alert for the same source
and target scores 45 instead of 85 and is held for 10 minutes; if it is routine for you, lower
`--rule-weight ot_control_command=…`, or acknowledge it.

<a id="command-watches"></a>
## OT rules

*Rules → OT · industrial → Your OT rules.* An OT rule says: **when this command reaches that device, tell me**. **+ New OT rule** (or **+ New rule → OT rule** at the top of the page) opens the dialog described under [Your own rules](detection-rules.md#your-own-rules-it-rules-and-ot-rules), with a template for each common case and a preview of how often the rule would have fired.

| Field | Meaning |
|---|---|
| Name | Shown in the alert: `Stop commands to line 1: HMI sent PLC stop (0x29) to PLC Line 1 (s7)`. |
| Protocol | one protocol (Modbus, Siemens S7, S7comm-plus, EtherNet/IP, DNP3, BACnet, OPC UA, IEC 104, IEC 61850 MMS / GOOSE / Sampled Values, PROFINET IO / DCP, CODESYS, or *any TLS* and the secured variants) or any. |
| What | **any communication at all** (also encrypted: see below), **any control command** (stop, start, download, restart, operate), **any write** (registers, coils, tags, setpoints), and/or **functions whose name contains** words you type (`PLC stop`, `write single register`, `0x29`, `restart`). Any of them matching is enough. The form offers the functions actually seen on your network. |
| Targets | only when the receiving device is one of these: devices, device types, tags, networks (the address it has now, IPv4 or IPv6), a Purdue level, a register "Zone / cell" value or a site. Empty = any device. |
| Allowed senders | never for these senders (same choices as Targets): your **engineering workstation**, for example. |
| Score / gap | the score the alert gets (1-100; it is raised even if it is under the global minimum, because you asked for it) and at most one alert per sender, target and protocol in this many minutes. |

Start from a ready-made one ("Siemens S7: CPU stop", "Modbus: any write", "DNP3: restart", "BACnet: reinitialize
device", "IEC 61850: operate or select", "OPC UA: any write or method call", "PROFINET: device renamed, re-addressed or
factory reset"…) and adjust it. Because OPC UA method calls are counted as writes, "any write" also covers them; a method
call can do anything from "start the line" to "return a list", so DENIS does not call it a control command, and an
administrator who knows which methods matter uses an OT rule. OT rules also work during the learning period. They are on the same footing as the built-in
rules: the *weight* of `ot_command_watch` scales or switches off all of them, and its alerts carry the same advice
and go to the same channels. An OT rule matches what DENIS decodes from the wire (see *What it recognises*);
**any communication** needs no decoding of the content (next section), but still needs a message DENIS can frame (a segment it cannot make sense of produces nothing).

## Encrypted traffic: who talks to whom is still visible

When a protocol is encrypted (OPC UA over TLS, Modbus/TCP Security, IEC 104 or DNP3 over TLS, MQTT over TLS, or plain TLS to a
controller's web or management port) DENIS cannot read what is said, but the headers are in the clear, and for OT security
that is often enough: **a device that should never talk to a client, and does, is the problem, whatever it says.**

DENIS sees, between two local devices, without reading any content:

* **that they talk**, over which port, in which direction (who opened the session), how many packets and bytes, and when;
* the **protocol**, when a TLS-secured port names it: `opcua-tls` (4843), `modbus-tls` (802), `iec104-tls` (19998),
  `dnp3-tls` (19999), `mqtt-tls` (8883), or plain `tls` on any other port;
* from the **TLS handshake**: the protocol version (1.0 to 1.3: a controller still on TLS 1.0 is worth knowing about) and the
  **server name** the client asked for (SNI). They appear in the OT tab's *commands seen* column, for example
  `TLS 1.3 handshake (server name plc1.plant.local)`.

### What each kind of protection really hides

* **OPC UA (`opc.tcp`, port 4840).** The security *mode* decides. With **None**, the services are readable. With **Sign**, the
  messages are signed but **not encrypted**, so DENIS reads them exactly as with None (Sign is not "encrypted"). With
  **Sign & Encrypt**, DENIS sees the connection, the security policy (named in the channel-opening message, for example
  `Basic256Sha256`), message sizes and counts, but **not whether a message reads or writes**: those messages are listed as
  `encrypted or unrecognised message` and count as neither. DENIS only calls a message a read or a write when the whole request
  header after it also parses with believable values, so encrypted bytes are never mistaken for a write. Over TLS (port 4843) only
  the TLS version and server name are visible, as above.
* **S7comm-plus.** Older S7-1200/1500 firmware and TIA Portal versions before V17 use integrity protection, which is **not**
  encryption: reads and writes are visible. With "secure PG/HMI communication" (TIA Portal V17 and later) the session switches to
  TLS after set-up: DENIS shows who talks to which PLC (`s7plus-tls`) and the TLS version, **not what is said**.
* **IEC 61850 MMS** over TLS (port 3782, IEC 62351-4) shows as `mms-tls`: the path, not the content. GOOSE and Sampled Values with
  IEC 62351-6 security are still recognised as publishers; their authentication data is not checked.
* **CODESYS** V3 has an encrypted variant; DENIS can recognise that the channel is CODESYS and (when it is) encrypted, nothing more.

These paths feed the same rules as decoded ones: `ot_new_conversation` alerts when a path appears that never existed (with the reason
"the content is encrypted: DENIS sees who talks to whom, not what is said", and without the deduction for "only set-up traffic"),
and the **OT matrix** lists them. TLS between two ordinary machines (two office PCs) is **not** recorded: only paths that involve an
industrial device or a known industrial port. Plain TLS on a port no industrial protocol uses (8443, say) counts as an industrial
conversation only when one of the two devices has industrial evidence of its own (a decoded industrial protocol or an industrial
device type; a vendor name is not enough), and is then shown as *TLS (not identified as industrial)*. A path never marks a device
as industrial by itself.

### An allow-list: only these devices may talk to it

The strongest rule for encrypted OT is not about content but about **who**. Add an OT rule (*Rules* → *New OT rule*, or start
from **Only these devices may talk to it**), tick **any communication at all**, set the **targets** to the controller and the
**allowed senders** to the devices that are meant to talk to it (the HMI, the engineering workstation). Any other device that
talks to that controller, over any protocol, encrypted or not, raises the alert `ot_command_watch` with the rule's name, the
sender, the target and "communication" or "encrypted communication". It fires from the first minute, while everything else is still
learning. Give a protocol (for example *OPC UA (TLS)*) to narrow it, or leave *any protocol*.

This needs the mirror port to carry the traffic between the devices (the same requirement as everything in OT mode).

## Trying it without a plant

* **`denis replay capture.pcap`** runs any Ethernet packet capture through the same decoders, inventory and rules the live
  collector uses and prints the devices, the conversations (with the functions used) and the alerts. Nothing is stored. `--subnet`
  narrows what counts as local; `--learning-secs` sets how long new paths are accepted silently (default 0, so every new path alerts).
* **`tools/ot-samples.sh`** downloads real captures from the public [ICS-pcap](https://github.com/automayt/ICS-pcap) and ITI ICS-Security-Tools collections
  (Modbus, Siemens S7 and S7comm-plus, IEC 61850 MMS and GOOSE, PROFINET, IEC 104, BACnet, EtherNet/IP firmware change…) and checks that DENIS finds what each is known to contain, and
  makes a capture of encrypted traffic from real OpenSSL handshakes (`tools/make-encrypted-sample.py`). It also checks OPC UA
  against traffic from the open-source `asyncua` stack (`tools/make-opcua-sample.py`: one session each in modes None, Sign and Sign & Encrypt,
  with a read, a write and a method call; skipped with a notice when `asyncua` is not installed). It runs before every release.
* For a *live* test bench there are open-source simulators (for example Conpot, an ICS honeypot that speaks Modbus, S7 and BACnet,
  and OpenPLC, a soft PLC with Modbus, DNP3 and EtherNet/IP servers); run one in a VM, put DENIS on its virtual switch's mirror and
  point a client at it. DENIS has not been run against them here; the captures above are what it has been checked with.

## Limits to know about

* Decoding is **shallow by design**: enough to say *which protocol, who is the server, is it a read, a write, or
  a state change*. It does not decode individual tags/registers, so it cannot tell *which* value was written.
* **A missing alert is not proof that no command was sent.** DENIS decodes **per TCP segment**, with a small, bounded
  help for messages that do not fit one segment; it does **not** reassemble TCP streams. Exactly what is covered:
  * **Several messages in one segment** (Modbus/TCP, S7comm and the other ISO-on-TCP protocols, EtherNet/IP, DNP3,
    IEC 104, OPC UA, MQTT): every complete message is read, up to 16 per segment, and the segment is reported as the
    strongest message in it (control, then write, then read). A harmless message in front of a command does not hide it.
  * **One message split across two or more segments**: one incomplete message per direction of a connection is held
    (at most 4 KB, for at most 30 s, in at most 1,024 connections, least recently used first out) and completed by
    the **next segment in sequence**. A command cut at any byte, header included, is seen. Anything out of order, with
    a gap, overlapping, or arriving after the time limit, drops what was held and is counted
    (`reassembly gap`): DENIS never reorders segments. These counters are on `/metrics` (`denis_ot_stream_*`, `denis_ot_conversations_dropped_total`) and Health warns when connection states had to be forgotten, a segment held more messages than are read, or a thousand continuations were lost. A message longer than 4 KB is not classified (OPC UA is, from its
    first 1 KB); the bytes after it are skipped so the next message is found.
  * A capture that starts **mid-stream** picks the stream up at the first segment that starts with a valid header.
  * An **exact duplicate** segment (a retransmission, or a doubled SPAN copy) is not counted twice.
  * **A message sent in COTP pieces** (ISO-on-TCP data TPDUs with the end-of-transmission bit clear: a large S7comm or
    MMS message) is put together from its pieces, in order, up to 4 KB, and decoded when the last piece arrives. A
    message that outgrows the 4 KB is dropped together with its remaining pieces (counted as too long to be read).
  * **A DNP3 message over several link frames** (transport FIR to FIN) is put together the same way: the function
    code is read from the joined application data, so a command whose function code sits in the second frame, or
    after a first frame holding only the transport byte, is still seen, and the continuation frames are not counted
    as separate messages. Frames out of transport sequence are read the old way (as "continuation fragment").
  * **Several DNP3 frames in one UDP datagram** are all read (the strongest is reported). The other UDP protocols
    carry exactly one message per datagram, and only that one is read.
  * **A message cut by IP fragmentation** (since 4.1.2) is put back together, IPv4 and IPv6 alike, in any fragment
    order, when the datagram goes to or comes from an industrial port (the ports in the table above); other traffic
    is never reassembled, and unfragmented packets take the same path as before. Hard limits, per capture thread:
    at most 64 datagrams being put together at once and 16 per source address (past that, the oldest is dropped),
    1 MB of buffers in all, 64 fragments and 65,535 bytes per datagram, and 5 seconds from the first fragment to
    the last. **Fragments that overwrite bytes already received with other bytes** (the overlap and teardrop
    evasions), or two different ends of one datagram, drop the whole datagram, and its remaining fragments are
    ignored: DENIS never guesses which copy the device will believe. An exact repeat of a fragment is accepted.
    **Tiny fragments** are refused: a first fragment without the whole TCP or UDP header, or a fragment other than
    the last one with fewer than 48 bytes. When room runs out, datagrams whose first fragment has not arrived go
    before an industrial one, and other traffic never pushes one out. The counters are on `/metrics`
    (`denis_ot_fragments_reassembled_total`,
    `denis_ot_fragments_dropped_total{reason="timeout|limit|overlap|oversize|tiny"}`) and count only datagrams whose
    ports are industrial; Health warns at the first overlapping, tiny, oversized or pushed-out datagram, or after a
    hundred incomplete ones.
  * **Not covered**: protocol-internal fragmentation above these layers (S7comm-plus and OPC UA multi-chunk messages are classified from their first
    chunk); HART-IP and CODESYS (named only); anything encrypted. A device on the cell network can use any of these on purpose, and a capture NIC with GRO/LRO
    on merges frames by itself. **Turn GRO/LRO off on the capture interface**
    (`ethtool -K <interface> gro off lro off`), and keep the mirror's snap length at the default.
  * **No checksum, CRC or TCP-validity check** is done, so a forged or corrupted frame is read like a real one
    (a forged frame can start the 10-minute repeat gap of `ot_control_command`).
  * Encrypted or opaque channels (TLS, Sign & Encrypt, S7comm-plus with TLS) show only the connection, never the commands.
  * Counts are "messages seen", not totals. S7comm-plus and MMS also accept a segment that starts without the usual
    ISO-on-TCP header (headerless COTP continuation); classic S7comm does **not** get that tolerance (a lone TPKT
    header followed by the rest in the next segment is handled by the hold above).
* OPC UA reads, writes and method calls are decoded only when the channel is None or Sign; with Sign & Encrypt they are not
  visible (see *Encrypted traffic*). A message that spans several chunks is counted as one "message chunk". OPC UA PubSub, the HTTPS
  and WebSocket mappings and OPC Classic (DCOM) are not decoded. With Reverse Connect (the server dials the client) the direction is taken from the message type.
* S7comm-plus is told apart from classic S7comm, but CPU stop/start and program download are not reported as control commands, and
  TLS-protected sessions show as paths only. Siemens publishes no specification, so the decoder only reports what it has
  verified against recordings and says "unrecognised" otherwise.
* IEC 61850 GOOSE and Sampled Values: publishers and their control blocks only, and only when the mirror carries the station bus
  (GOOSE) or the process bus (Sampled Values): see *Layer-2 traffic*. DENIS does not follow state numbers or sequence
  numbers, so it does not detect replayed GOOSE; it does report the same control block published from two source addresses
  (`ot_goose_conflict`). R-GOOSE / R-SV (over UDP) and HSR-tagged frames are not decoded.
* PROFINET: connection management, record reads and writes, DCP Set and the I&M identity are decoded. The cyclic real-time data and
  alarms are **not** reported (they would add nothing the connection set-up does not already say).
* CODESYS is identified only (see *What it recognises*).
* Encrypted industrial protocols (OPC UA with Sign & Encrypt, S7comm-plus with TLS, anything in TLS) show as **paths** (who talks to whom, how much,
  the TLS version and server name), never as commands: see *Encrypted traffic*. Cipher suites, certificates and traffic timing patterns
  are not analysed.
* After an update that teaches DENIS to decode more of a protocol (for example OPC UA reads and writes, or S7comm-plus), the paths it
  newly discovers are learned quietly for one learning period, so the update itself does not raise alerts. Control commands are never held back by this.
  After upgrading a remote collector, the same applies to the paths it newly reports.
* IPv4 and (with `--ipv6`) IPv6; the real-time layer of PROFINET and EtherCAT are not analysed.
* Anything not visible on the mirror port is not seen. Verify that the port really carries the traffic you care
  about (the **OT** tab should show the expected controllers within minutes).
* DENIS is a **monitoring** tool. It never sends commands to controllers and, by default, never blocks anything on its
  own (an administrator can optionally disable a switch port from it; see [Disabling a port](switches.md#disabling-a-port);
  automatic enforcement is a separate, experimental, off-by-default switch, see [Enforcement](enforcement.md)).

## SCL import (IEC 61850 engineering file)

An IEC 61850 substation is described by an **SCL file** from the engineering tool (an SCD for the whole station, or a CID, ICD or
IID for one IED). It names every IED, where each one sits on the network, and which GOOSE, Sampled Values and report control
blocks it is engineered to publish. DENIS can import it and use it as **context**: it shows which devices it has observed
are in the file and which are not, and which engineered IEDs it has not seen. It does **not** raise an alert from the file and does
not block anything. (An allow-list rule built on it, "GOOSE from a source that is not in the file", is a possible later step.)

**Import.** On the **OT** tab, under *Engineering file (IEC 61850 SCL)*, choose the file and press *Import SCL file*. Only an
administrator can import or delete. Each site (the local console and each remote collector's site) has its own import, and
importing again **replaces** that site's previous one. *Delete the import* removes it. Every import and delete is written to the
audit log with who did it, the file's SHA-256 and the counts, never the file's content. The file itself is not stored: only the
extracted context is.

**What is read.**

| From the file | Used for |
|---|---|
| each IED: name, type, manufacturer, configuration version | the list of engineered IEDs; shown on the device's row and panel as *Engineered in SCL* |
| the IED's address in the `Communication` section (IP, subnet, gateway, and its MAC when the file gives one) | matching an IED to a discovered device |
| each GOOSE control block: name, data set, `confRev`, GOOSE id, and the `GSE` address (multicast MAC, APPID, VLAN id and priority) | telling whether an observed publisher is engineered; the control block reference is composed the way the wire carries it (`<IED name><LDevice inst>/LLN0$GO$<name>`, or the logical device's `ldName`) |
| each Sampled Values control block: name, `smvID`, data set, `confRev`, sample rate, and the `SMV` address | the same for Sampled Values streams |
| report control blocks and whether an access point holds a `Server` | the count of report blocks, and which IEDs are MMS servers |

**What is never read or kept.** Values of any kind (`Val`, so no setting, set point or data attribute value), the data type
templates, the data set members, the substation section, and anything from a vendor's private extension. Those parts of the
file are only checked for well-formedness and discarded.

**What the OT tab shows after an import.**

* The list of engineered IEDs, with the discovered device each one was matched to (by IP address, or by MAC when the file gives
  the IED's own MAC). A matched device also shows *Engineered in SCL: IED name, manufacturer, control blocks* in the OT
  devices table and in its detail panel.
* **Observed publishers and servers: in the SCL or not.** One row per device and protocol (GOOSE, Sampled Values, MMS server):
  *in the SCL*, *partly in the SCL* (some of the control blocks seen are engineered, some are not) or *not in the SCL*. A GOOSE or
  Sampled Values publisher is judged by the control block it publishes (the `gocbRef` or `svID` seen on the wire), so a device
  that publishes a block the file does not have is *not in the SCL* even when its address matches an IED. The details also
  say when a block's APPID, or its configuration revision, differs from the file (a changed revision means the publisher was
  reconfigured since the file was made). An MMS server is judged by its address.
* **Expected in the SCL but not seen**: IEDs the file engineers to publish or serve something DENIS has not observed on this
  site, with what was missing and whether a device with that address is on the network at all.

**Limits to know.**

* This is a file you provide, not something DENIS verifies. If the file is out of date, devices will correctly look "not in the SCL".
  A device listed as *not in the SCL* is a question to ask, not a finding.
* Sampled Values are only decoded when that is switched on (Settings, Network interfaces), and the mirror port must carry the
  segment: an IED listed as not seen may simply be on a segment the mirror does not cover.
* The multicast address in a `GSE` or `SMV` element is the *destination*. DENIS does not record a frame's destination, so
  the engineered MAC is stored and shown for reference but a publisher is matched by its control block reference and its own
  address, not by the multicast MAC.
* The reader is deliberately strict: UTF-8 only, at most 5 MB, a file with a `DOCTYPE` or any entity declaration is refused (this
  closes external entity and "billion laughs" attacks), as are files nested deeper than 64 levels, with more than 400,000
  elements, more than 64 attributes on one element, more than 1,000 IEDs or more than 4,000 control blocks of one kind. The file
  must be in the IEC 61850 SCL namespace (`http://www.iec.ch/61850/2003/SCL`). Elements from other namespaces (vendor extensions)
  are skipped. A refused file changes nothing, and the reason is shown.
* What was validated: the parser against small hand-written files that follow the structure of the public IEC 61850-6 schema, and
  the GOOSE control block reference form against the GOOSE recordings the OT section already uses. It has **not** been tried against
  real SCD files from every engineering tool; a file that DENIS reads differently from your tool is worth reporting. The
  notes DENIS prints about a file (duplicates, an address that is not an address, an address for a control block the IED
  does not have) are shown under the import.
