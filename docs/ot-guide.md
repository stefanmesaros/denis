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
| LLDP, CDP | link layer | – | system name/description, port, capabilities |
| PROFINET DCP | link layer | – | station name, vendor, role, IP |

Each decoder verifies the protocol's own signature, so ordinary traffic that merely uses the same port number
is not mistaken for industrial traffic.

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
| Protocol | one protocol (Modbus, Siemens S7, EtherNet/IP, DNP3, BACnet, OPC UA, IEC 104) or any. |
| What | **any control command** (stop, start, download, restart, operate), **any write** (registers, coils, tags, setpoints), and/or **functions whose name contains** words you type (`PLC stop`, `write single register`, `0x29`, `restart`). Any of them matching is enough. The form offers the functions actually seen on your network. |
| Targets | only when the receiving device is one of these: devices, device types, tags or networks. Empty = any device. |
| Allowed senders | never for these senders: your **engineering workstation**, for example. |
| Score / gap | the score the alert gets (1-100; it is raised even if it is under the global minimum, because you asked for it) and at most one alert per sender, target and protocol in this many minutes. |

Start from a ready-made one ("Siemens S7: CPU stop", "Modbus: any write", "DNP3: restart", "BACnet: reinitialize
device"…) and adjust it. Watches also work during the learning period. They are on the same footing as the built-in
rules: the *weight* of `ot_command_watch` scales or switches off all of them, and its alerts carry the same advice
and go to the same channels. A watch matches what DENIS decodes from the wire (see *What it recognises*); it cannot
see encrypted or unrecognised traffic.

## Limits to know about

* Decoding is **shallow by design**: enough to say *which protocol, who is the server, is it a read, a write, or
  a state change*. It does not decode individual tags/registers, so it cannot tell *which* value was written.
* OPC UA services are not decoded (the protocol is identified, but read vs write is not).
* Encrypted industrial protocols (e.g. OPC UA with security, S7comm-plus) show as sessions only.
* IPv4 only; non-IP real-time protocols (PROFINET RT, EtherCAT) are not analysed, only PROFINET DCP identity.
* Anything not visible on the mirror port is not seen. Verify that the port really carries the traffic you care
  about (the **OT** tab should show the expected controllers within minutes).
* DENIS is a **monitoring** tool. It never sends commands to controllers and never blocks anything.
