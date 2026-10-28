# Enforcement validation

This page says what has been tested for each enforcement connector, at which level, and what has not. It claims
nothing that is not tested. It has two parts: the results of the **validation harness** (a list of scenarios that
runs in DENIS's own test suite against a simulated device of every connector it covers), and the **lab checklist**
for the tests only real equipment can answer.

## The four levels

| Level | What was done | What it can show |
|---|---|---|
| **Unit-tested** | Small pieces on their own: configuration checks, address checks, parsers, the guards. | The piece does what its test says. |
| **Mock-integration-tested** | The real connector, the real plan, apply, release, expiry, reconcile and ledger code, against a **simulated** device (a stand-in server that speaks the vendor's protocol, written from the vendor's documentation). The matrix below is this level. | DENIS's own code behaves as the scenario says when the device behaves as simulated. It says **nothing** about how the real device or its software behaves. |
| **Live-API-validated** | The connector against a real vendor service or a virtual appliance, without a production effect. | None is recorded on this page. |
| **Real-hardware-validated** | The owner's lab: a real device, a test client, a probe that sees whether traffic really stopped. Recorded per action in `NAC_HARDWARE_VALIDATION.md` and in the *Validated* tables of the connector pages. | What the device really did, for the version that was tested. |

A pass at one level does not become a pass at the next. A result for one action does not carry over to another action
of the same connector.

## The scenarios

Every scenario runs in a database and with a simulated device of its own, through the same path as the console:
the plan with its refusals, the apply, the read-back, the release, the expiry job and the reconcile job. A scenario
never switches off a guard: the kill switch and the hourly limit are set the way the settings page sets them, and
nothing else is changed except the simulated device.

| Scenario | What it checks | Lab row |
|---|---|---|
| Kill switch | With the switch off nothing reaches the device. A plan made before the switch was turned off is refused at the apply (the switch is looked at again). A release still works with the switch off. | T14 |
| Hourly limit | With a limit of one, the second action is refused and the device is not touched. | T15 (the concurrent case is lab only) |
| Wrong credential | A credential the device does not accept: no change on the device, no false success, and the credential's bytes appear in no result, audit row or ledger row (checked without printing it). Afterwards the correct credential works again. | T02 |
| Read-only credential | A credential that may read and not write: never reported as enforced, nothing held on the device. | T02 |
| Connection lost before the write | No request reaches the device: not reported as enforced, nothing held, and once the line is back everything ends where it started and a new request works. | T13 |
| Connection lost after any step of the apply | For HTTPS devices the line is cut after each connection of an apply in turn (a forwarder between DENIS and the simulated device). Whatever the cut point: if the device holds the change, an active ledger row can undo it; "enforced" is only reported when the device holds it; after the line is back, the read-back and the release bring the device to where it started. | T13 |
| Reply lost after a successful write | The device applies the write and the answer never arrives: DENIS says unconfirmed or enforced (never failed), the device holds the change, an active row can undo it, no second write is sent by DENIS, the reconcile read-back does not close the row as failed, and the release restores. | T11 |
| Read-back mismatch | The device answers success and did not apply the change: never reported as enforced. | T05 |
| Release after a DENIS restart | The database is opened again, nothing is kept in memory; the active row is there and the release restores the device. | T25 |
| Time ran out while DENIS was down | After a restart past the end time, the first expiry pass releases the overdue action. | T26 |
| Value changed meanwhile | Someone else changes the device after DENIS acted (takes the entry out, or sets another VLAN). The release does not overwrite what the other person did and does not leave the action active. | T19 |
| Duplicate request | The same plan applied twice is one change (the second answer is a replay of the first). A new request for a target that has an active action is refused. | T09 |
| Protected target | A target in the connector's own protected list is refused at the plan and the device is not touched. | T16 |
| Hands-off target | A target on the hands-off list is refused at the plan. | T16 |
| Infrastructure target | A target the inventory knows as the gateway, or a switch uplink, is refused at the plan. | T16 |

The harness checks itself: its own tests break one thing at a time in a simulated device (a credential that appears
in a log, a target nothing protects, a device that does not end where it started, one that does not show the change)
and require the matching scenario to turn red.

## Results of the harness

Run it with `cargo test --lib validation` (about half a minute). Each column is one connector and **its primary
action in the simulation**:

* Cisco: move an access port to the quarantine VLAN (`vmVlan`), simulated Catalyst 2960-X answers.
* Generic SNMP: move an access port to the quarantine VLAN (`dot1qPvid`) on a simulated switch that answers the whole
  standard set, with the VLAN port lists read back.
* Palo Alto: block a device through the **static** address group (candidate change, partial commit).
* FortiGate: block a device through the address group.
* MikroTik: block a device through the address list.
* UniFi: block a wired client by its hardware address (`block_sta`).

<!-- matrix:start -->
| Scenario | Cisco | Generic SNMP | Palo Alto | FortiGate | MikroTik | UniFi |
|---|---|---|---|---|---|---|
| Kill switch blocks writes (looked at again at the apply); a release still works | pass | pass | pass | pass | pass | pass |
| Hourly limit holds | pass | pass | pass | pass | pass | pass |
| Wrong credential: nothing written, credential in no log | pass | pass | pass | pass | pass | pass |
| Read-only credential: nothing written, no false success | pass | pass | pass | pass | pass | pass |
| Connection lost before the write | pass | pass | pass | pass | pass | pass |
| Connection lost after any step of the apply (every cut point) | not covered | not covered | pass | pass | pass | pass |
| Reply lost after a successful write: unknown state, reconcile, no second write | pass | pass | pass | pass | pass | pass |
| Read-back mismatch: success claimed, nothing applied | pass | pass | pass | pass | pass | pass |
| Release after a DENIS restart | pass | pass | pass | pass | pass | pass |
| Time ran out while DENIS was down: released when it starts again | pass | pass | pass | pass | pass | pass |
| Value changed meanwhile by someone else: no overwrite | pass | pass | pass | pass | pass | pass |
| Duplicate request: one change only | pass | pass | pass | pass | pass | pass |
| Protected target refused | not covered | not covered | pass | pass | pass | pass |
| Hands-off target refused | pass | pass | pass | pass | pass | pass |
| Infrastructure target refused | pass | pass | pass | pass | pass | pass |
<!-- matrix:end -->

"Not covered" means the simulation cannot produce the situation. Nothing is skipped silently: each connector declares
its not-covered scenarios in its test, and the test fails when the declared list and the real result differ. The
reasons:

<!-- reasons:start -->
- Cisco / Connection lost after any step of the apply (every cut point): the stand-in is not reached through a line that can be cut (no TCP connection to cut)
- Cisco / Protected target refused: the stand-in has no Protected target
- Generic SNMP / Connection lost after any step of the apply (every cut point): the stand-in is not reached through a line that can be cut (no TCP connection to cut)
- Generic SNMP / Protected target refused: the stand-in has no Protected target
<!-- reasons:end -->

How to read the table, and what it does not show:

* A pass is mock-integration level only (see the table of levels). The simulated devices were written from the
  vendors' documentation and, where it exists, from answers recorded on real devices; they can be wrong about the
  real device.
* SNMP runs over UDP. A wrong community, a lost request and a lost reply all look like silence, so on the two SNMP
  columns a wrong credential ends **unconfirmed** (never enforced, the device untouched, the release closes it) instead
  of refused, and "connection lost" is a lost request. The transport itself may send one identical, absolute SET up to
  three times when no answer comes; the scenario allows exactly that and nothing more.
* A switch has no list of protected addresses of its own; a device behind a port is protected by the hands-off list
  and by the infrastructure rules, which have their own rows.
* An apply that stops half way can leave an unused object made by DENIS (for example a FortiGate address object that
  is in no group). It enforces nothing; the reconcile pass lists it as an orphan and a person removes it from the
  Health page. The harness removes such objects the way that page does and then compares the device with where it
  started. MikroTik keeps two `DENIS managed` drop rules after a release by design, so they are not part of the
  comparison.
* The harness does not test concurrent actions (two browser tabs in the same second), a device reboot, a 24 hour hold
  or repeated cycles. Those are lab rows (T15 concurrent, T18, T22, T23, T24).

### Connectors that are not in the matrix

These have simulated-device tests of their own, run through the same plan, apply and release code, but they do not run
the shared scenario list yet. This is a gap, not a pass.

- Meraki <!-- not-in-matrix:Meraki -->
- AWS <!-- not-in-matrix:Aws -->
- OPNsense <!-- not-in-matrix:Opnsense -->
- Hyper-V <!-- not-in-matrix:Hyperv -->
- SonicWall <!-- not-in-matrix:Sonicwall -->
- NSX <!-- not-in-matrix:Nsx -->
- WatchGuard <!-- not-in-matrix:Watchguard -->
- Check Point <!-- not-in-matrix:Checkpoint -->
- RADIUS Disconnect <!-- not-in-matrix:RadiusCoa -->
- Juniper SRX <!-- not-in-matrix:Juniper -->
- Azure <!-- not-in-matrix:Azure -->
- Proxmox <!-- not-in-matrix:Proxmox -->
- Cisco ASA <!-- not-in-matrix:Asa -->
- Cisco FTD through FDM <!-- not-in-matrix:FtdFdm -->
- Cisco FTD through FMC <!-- not-in-matrix:FtdFmc -->

## What is tested at which level, per connector

The last column repeats what `NAC_HARDWARE_VALIDATION.md` (section 7.1) and the connector page record; this page
adds no hardware result of its own. Anything not named there is not validated on real equipment.

| Connector | Unit-tested | Mock-integration (this matrix) | Live API | Real hardware |
|---|---|---|---|---|
| Cisco Catalyst (SNMP) | yes (port assessment, trunk and neighbour rules) | yes, quarantine VLAN | none recorded | Catalyst 2960-X (WS-C2960X-48TS-L, IOS 15.2(7)E4), SNMPv2c and v3: disable port, quarantine VLAN, release, uplink refusal. The fault and safety rows below are not recorded. |
| Generic SNMP control (`dot1qPvid`) | yes | yes, a simulated switch that answers the whole standard set | none recorded | **None.** No switch model is validated; a D-Link DGS-1100-08V2 gave a partial result (port down works; no forwarding table or VLAN objects over SNMP). |
| Palo Alto | yes | yes, the **static** address group block (and the other static-group paths in the connector's own tests) | none recorded | PA-220, PAN-OS 10.1.14-h9: block through the dynamic address group, block a flow, end sessions, quarantine through the dynamic group. **The static group block is not tested on hardware.** The native timeout was tested on the PA-220 (F6/F7) as a safety net only. |
| FortiGate | yes | yes, address group block | none recorded | FortiGate 40F, FortiOS 7.2.3: block device, block a flow, end sessions, quarantine. Not tested: IPv6, HA, VDOM mode, T02, T04, T11 to T15, T21 to T23. |
| MikroTik | yes | yes, address list block | none recorded | E50UG, RouterOS 7.21.4: block device, block a flow, quarantine by address, end sessions (with prerequisites). Not tested: disabling a port. |
| UniFi | yes | yes, **client block by MAC** (`block_sta`) | none recorded | Cloud Gateway Ultra (UniFi OS 5.1.33, Network 10.6.106): the two firewall-policy actions. **The client block by MAC is not validated** (on the bench the traffic came back before the time was up); its row in the matrix is a mock result only. |

## Lab checklist for the owner

For each connector, on real equipment, with `tools/hwtest/README.md` and the fault-injection notes in
`NAC_HARDWARE_VALIDATION.md` section 8.3. Run the guided self-test first (`denis nac selftest`); the rows below are
the ones the matrix cannot answer. Record each result in `NAC_HARDWARE_VALIDATION.md` section 7.1, not here.

1. **T02 credential failure.** Put a wrong secret, Test, then Block. Expected: refused, nothing written, secret in no
   log. (The matrix shows DENIS's behaviour against a simulated device that refuses the credential.)
2. **T11 and T12 lost answer, T13 dropped connection.** Delay the write answer past DENIS's timeout; separately drop
   the traffic to the device during a write. Expected: *unconfirmed* (never "refused, nothing changed"), the probe shows
   the real state, the read-back closes the row, the release works.
3. **T14 kill switch, T15 hourly limit.** Including the concurrent case (two tabs, same second) that the matrix does
   not cover.
4. **T25 release after restart.** Block, stop DENIS, start it, release. Expected: the device is back to where it started.
5. **T26 expiry while DENIS is down.** Block for five minutes, stop DENIS before the end, start it after. Expected: the
   action is released at the start. On the **Palo Alto** with the native timeout switched on: the tag must vanish about
   15 minutes after the end of the block even if DENIS never returns; then extend a block with the timeout on and check
   the tag lives to the new end. (The native timeout stays off by default until this has been run.)
6. **T19 concurrent edit.** Change the device by hand while DENIS acts and after it acted; DENIS must not undo your change.
7. **Interrupted apply.** Cut the line to the device between two writes of one action (FortiGate: after the address
   object, before the group member; Palo Alto: after the candidate change, before the commit). Expected: the Health
   page lists the unused object as an orphan, removing it works, and the device does not hold a block.
8. **SNMP only.** With a packet capture on the switch, one lost reply: the same SET of the same VLAN arrives up to three
   times and no other value is written. Then a wrong write community: nothing changes on the switch.
9. **T18 reboot, T22 repetition (20 cycles), T23 soak (24 hours), T24 two instances.** As in `NAC_HARDWARE_VALIDATION.md`.

When a lab row passes, the matrix does not change: the hardware result goes into section 7.1 for that device, action
and version. When a lab row fails, add the situation to the simulated device first (so it stays found), then fix the
connector.
