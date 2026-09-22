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

## What it recognises

Passively decoded (nothing is ever sent):

| Protocol | Port | Reads / writes / control detected | Identity learned |
|---|---|---|---|
| Modbus/TCP | 502 | read, write, diagnostics (restart/listen-only) | – |
| Siemens S7comm | 102 | read/write variable, **program download**, **PLC start/stop** | – |
| EtherNet/IP + CIP | 44818 | CIP read/write, reset/start/**stop** | vendor, product, serial, revision (ListIdentity) |
| DNP3 | 20000 | read, write, select/operate, restarts, stop application | – |
| BACnet/IP | 47808 | ReadProperty, WriteProperty, **ReinitializeDevice**, DeviceCommunicationControl | device instance, vendor (I-Am) |
| OPC UA | 4840 | protocol and session only | – |
| IEC 60870-5-104 | 2404 | commands (types 45–64), clock sync, reset | – |
| Omron FINS | 9600 | memory/parameter/program area read/write, **run/stop** | – |
| HART-IP | 5094 | protocol and session only (see below) | – |
| MQTT | 1883 | PUBLISH (write), SUBSCRIBE (read) | – |
| CoAP | 5683 | GET (read), POST/PUT/DELETE (write) | – |
| KNXnet/IP | 3671 | protocol and message kind only (see below) | – |
| LLDP, CDP | link layer | – | system name/description, port, capabilities |
| PROFINET DCP | link layer | – | station name, vendor, role, IP |

Each decoder verifies the protocol's own signature (magic bytes, a length field that has to match, a checksum, a
declared version), so ordinary traffic that merely uses the same port number is not mistaken for industrial traffic,
and **a port number by itself is never treated as identification**. **HART-IP** and **KNXnet/IP** are named and
their direction is known, but not read from further: HART's command table and KNX's cEMI/APCI layout would need a
capture to check the exact byte offsets against, which DENIS did not have, so it stops at "this is HART-IP" /
"this is KNXnet/IP" rather than guess at read vs write. Every decoder above (including these two) has been checked
against a real capture of that protocol, listed in `tools/ot-samples.sh`.

Ports whose protocol has **no public, checkable signature** (Niagara Fox 1911, GE SRTP 18245, MELSEC 5007, PCWorx
1962, CODESYS 2455) are used **only** for the *"industrial port crossing the boundary"* finding below: seeing that
port leave the network is worth a look regardless of what is really on it, but DENIS never names a conversation,
or judges a read from a write, from a port number alone.

From this DENIS derives **roles** (server/PLC vs client/HMI), types (`plc`, `rtu`, `hmi`, `building controller`,
`industrial switch`, `industrial device`…) and icons automatically, and shows them on the **OT** tab.

## The OT tab

* **Industrial devices**: name, IP, Purdue level, zone, type, protocols with roles (`S` server, `C` client) and
  the identity the device announced (product, vendor, serial).
* **Communications matrix**: `client → server`, protocol, counts of **reads, writes, control commands**, last seen.
  Rows with control commands are red, with writes amber. Filter by protocol or show only writes/control.
  **Commands seen** lists the functions the path used and how often (`write single register (6)` ×1200, `PLC stop
  (0x29)` ×1). Click one to create a [watch](#command-watches) for it, prefilled with that protocol and target.

Set **Purdue level** (0–5, 3.5 for the DMZ) and **Zone / cell** per device (Edit asset). They appear in the OT
tab, the matrix and reports, so you can spot, for example, an office-level (L4) device talking to a controller
(L1) directly.

## OT alerts

| Rule | When | Score |
|---|---|---|
| `ot_new_conversation` | a client/server/protocol path that did not exist during the learning period appears | 50; +20 writes; +25 control commands; +10 target is a controller; +10 the client itself is new (<1 h); −15 only session set-up |
| `ot_control_command` | a **STOP/START, program download, restart, operate** command is seen. Never suppressed by learning | 85 the first time this source does it to this target; 45 if it has before; 60 during learning; +10 for industrial targets. Repeats held for 10 min |
| `ot_internet_exposure` | industrial protocol traffic between a device and an address **outside the local network** | 90, no learning period; once per 6 h per device |

*Learning:* for the first 24 hours (`--learning-minutes`), normal paths are recorded silently. Run DENIS through a
**representative production period** (including maintenance windows if engineers download programs) before
relying on `ot_new_conversation`.

*Engineering workstations* legitimately download programs. After the first alert, an alert for the same source
and target scores 45 instead of 85 and is held for 10 minutes; if it is routine for you, lower
`--rule-weight ot_control_command=…`, or acknowledge it.

## Command watches

*Rules → OT: your command watches.* A watch says: **when this command reaches that device, tell me**.

| Field | Meaning |
|---|---|
| Name | Shown in the alert: `Stop commands to line 1: HMI sent PLC stop (0x29) to PLC Line 1 (s7)`. |
| Protocol | one protocol (Modbus, Siemens S7, EtherNet/IP, DNP3, BACnet, OPC UA, IEC 104, or *any TLS* and the secured variants) or any. |
| What | **any communication at all** (also encrypted: see below), **any control command** (stop, start, download, restart, operate), **any write** (registers, coils, tags, setpoints), and/or **functions whose name contains** words you type (`PLC stop`, `write single register`, `0x29`, `restart`). Any of them matching is enough. The form offers the functions actually seen on your network. |
| Targets | only when the receiving device is one of these: devices, device types, tags or networks. Empty = any device. |
| Allowed senders | never for these senders: your **engineering workstation**, for example. |
| Score / gap | the score the alert gets (1-100; it is raised even if it is under the global minimum, because you asked for it) and at most one alert per sender, target and protocol in this many minutes. |

Start from a ready-made one ("Siemens S7: CPU stop", "Modbus: any write", "DNP3: restart", "BACnet: reinitialize
device"…) and adjust it. Watches also work during the learning period. They are on the same footing as the built-in
rules: the *weight* of `ot_command_watch` scales or switches off all of them, and its alerts carry the same advice
and go to the same channels. A watch on commands matches what DENIS decodes from the wire (see *What it recognises*);
**any communication** needs no decoding at all (next section).

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

These paths feed the same rules as decoded ones: `ot_new_conversation` alerts when a path appears that never existed (with the reason
"the content is encrypted: DENIS sees who talks to whom, not what is said", and without the deduction for "only set-up traffic"),
and the **OT matrix** lists them. TLS between two ordinary machines (two office PCs) is **not** recorded: only paths that involve an
industrial device or a known industrial port. A path never marks a device as industrial by itself.

### An allow-list: only these devices may talk to it

The strongest rule for encrypted OT is not about content but about **who**. Add a command watch (*Rules* → *Add a watch*, or start
from **Only these devices may talk to it**), tick **any communication at all**, set the **targets** to the controller and the
**allowed senders** to the devices that are meant to talk to it (the HMI, the engineering workstation). Any other device that
talks to that controller, over any protocol, encrypted or not, raises the alert `ot_command_watch` with the watch's name, the
sender, the target and "communication" or "encrypted communication". It fires from the first minute, while everything else is still
learning. Give a protocol (for example *OPC UA (TLS)*) to narrow it, or leave *any protocol*.

This needs the mirror port to carry the traffic between the devices (the same requirement as everything in OT mode).

## Trying it without a plant

* **`denis replay capture.pcap`** runs any Ethernet packet capture through the same decoders, inventory and rules the live
  collector uses and prints the devices, the conversations (with the functions used) and the alerts. Nothing is stored. `--subnet`
  narrows what counts as local; `--learning-secs` sets how long new paths are accepted silently (default 0, so every new path alerts).
* **`tools/ot-samples.sh`** downloads real captures from the public [ICS-pcap](https://github.com/automayt/ICS-pcap) collection
  (Modbus, Siemens S7, IEC 104, BACnet, EtherNet/IP firmware change…) and checks that DENIS finds what each is known to contain, and
  makes a capture of encrypted traffic from real OpenSSL handshakes (`tools/make-encrypted-sample.py`). It runs before every release.
* For a *live* test bench there are open-source simulators (for example Conpot, an ICS honeypot that speaks Modbus, S7 and BACnet,
  and OpenPLC, a soft PLC with Modbus, DNP3 and EtherNet/IP servers); run one in a VM, put DENIS on its virtual switch's mirror and
  point a client at it. DENIS has not been run against them here; the captures above are what it has been checked with.

## Limits to know about

* Decoding is **shallow by design**: enough to say *which protocol, who is the server, is it a read, a write, or
  a state change*. It does not decode individual tags/registers, so it cannot tell *which* value was written.
* OPC UA services are not decoded (the protocol is identified, but read vs write is not).
* Encrypted industrial protocols (OPC UA with security, S7comm-plus, anything in TLS) show as **paths** (who talks to whom, how much,
  the TLS version and server name), never as commands: see *Encrypted traffic*. Cipher suites, certificates and traffic timing patterns
  are not analysed.
* IPv4 only; non-IP real-time protocols (PROFINET RT, EtherCAT) are not analysed, only PROFINET DCP identity.
* Anything not visible on the mirror port is not seen. Verify that the port really carries the traffic you care
  about (the **OT** tab should show the expected controllers within minutes).
* DENIS is a **monitoring** tool. It never sends commands to controllers and never blocks anything.
