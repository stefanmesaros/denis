# Switches and the physical topology (SNMP)

The **Topology** tab has two maps. *By gateway* is the logical one every install has. **Switches and cables** is the
physical one: which **port** each device is plugged into and how the **switches are cabled together**. It needs your
switches to answer SNMP, so you tell DENIS which ones to read.

## What DENIS reads

For every switch you add (*Settings* → **Switches (SNMP)**), DENIS reads, and only reads, every few minutes:

| MIB | What for |
|---|---|
| system (`sysDescr`, `sysName`) | the switch's name and description |
| IF-MIB (`ifName`, `ifAlias`, `ifOperStatus`, `ifHighSpeed`) | the ports: name, the label somebody typed, up or down, speed |
| LLDP-MIB (`lldpRemTable`, `lldpLocChassisId`) | what each port sees on the other end of the cable: another switch, an access point, a phone: as that device announces itself |
| Q-BRIDGE-MIB (`dot1qTpFdbPort`), else BRIDGE-MIB (`dot1dTpFdbPort`) | the forwarding table: which MAC address was learned on which port |

DENIS never sends a SET and never changes anything on a switch. A table a switch does not implement is simply left out; only
a switch that does not answer at all is an error, shown on the switch's line with the reason.

## Setting it up

1. On the switch, create a **read-only SNMP v2c community** and allow **only the DENIS server's address** to use it (an
   access list on the switch). Give it a long random name: **in v2c the community travels unencrypted**, so treat it as a
   password that anybody who can watch that link could learn.
2. *Settings* → *Switches (SNMP)* → **Add a switch**: a name, the switch's address (`192.168.1.2`, or `192.168.1.2:1161`
   for another port) and the community. The community is stored with the list, is never shown again (leave it blank when
   editing to keep it) and never appears in the audit log.
3. Press **Read now**. It says how many ports, neighbours and MAC addresses were read, or why not ("no answer from the
   device": check that SNMP is on, the community, and that UDP 161 is reachable from the DENIS server).
4. Open **Topology** → *Switches and cables*. A device's own panel also gets a **Connected to** line.

Polling runs from the DENIS collector (not in a `denis serve` viewer). The interval is 5 minutes by default (60 to 3600 seconds).

## How a device is placed

* A device is drawn on the port where its **MAC address was learned**. If it is learned in several places, the port with the
  **fewest** other MACs behind it wins: an access port beats an uplink.
* A port that leads to **another switch you poll** (LLDP says so), or that has **more than 24 MACs** behind it, is a
  trunk: what it learns is only "somewhere further down", so no device is claimed to be plugged into it. The device shows up
  on its real port once the switch it hangs off is added as well.
* A neighbour that **announces itself by LLDP** (an access point, a phone) is drawn with what it says and matched to the
  register by its chassis MAC.
* MACs on access ports that are **not in the register** are only counted (the map says how many).

## What is verified, and what is not

The SNMP client (BER encoding and decoding, GET, GETBULK and GETNEXT walks) is tested against byte sequences worked out
from the specifications, against hostile and corrupted answers (it never panics; every length is bounded), and against
two independent stand-in switches (one written in Rust for the tests, one in JavaScript for the browser test).
**It has not been tried against real switches from any vendor.** Vendors differ (VLAN-specific communities on some
Cisco models, LLDP local port numbering, bridge-port to interface maps), so read the map critically at first and please
report a switch that shows something wrong.

**Not supported yet:** SNMPv3 (authentication and encryption). Until it is, restrict the v2c community as described above.
