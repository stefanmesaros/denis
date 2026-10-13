# Enforcement: Microsoft Hyper-V

Status: **Experimental. Simulator only: not yet validated on real equipment.** Everything below was built from the Hyper-V PowerShell reference and the WS-Management wire format and checked against a fake WinRM server in DENIS's own tests, which interprets the scripts DENIS sends. It has never been run against a real Hyper-V host. Nothing here is listed as validated on hardware.

Lab use: the VM isolation (the block that existed before 4.1) is allowed only while an administrator has switched on *Allow connectors that are not validated on real equipment (lab use)* under *Settings → Enforcement*. The actions new in 4.1 (flow block, quarantine VLAN, disconnect) additionally need *Allow experimental actions (lab use)*. Releasing an action and removing what DENIS made always work.

Besides the connector's own refusals, every action through it is refused for a loopback, unspecified, broadcast or multicast address, for DENIS itself and for the gateway, for the addresses on this connector's protected list, for a VM that holds such an address, for the Hyper-V host's own address, for a VM on the **Never quarantine these VM names** list (by name or by id) and for an address in an open `arp_conflict` alert (unless the administrator ticks a box to accept that), before anything is sent. Releasing is never refused for these reasons.

## What DENIS can do on a Hyper-V host

The old route names a VM by its **name**. The new actions name a device by its **address** (the VM that owns it is found) or, for the actions on one virtual network adapter, by the VM's **id** and the adapter's name as `<VM id>/<adapter name>`. Every write on the new path addresses the VM by its id (`Get-VM -Id`), never by its name.

| Action | What DENIS writes | What it does not do |
|---|---|---|
| **Block device** (isolate the VM) | Two port ACLs with `Add-VMNetworkAdapterAcl`: deny all IPv4 (`0.0.0.0/0`) and deny all IPv6 (`::/0`), in both directions. Removed again with `Remove-VMNetworkAdapterAcl` using exactly those parameters. | It does not change or reorder any other ACL: the ACLs the VM had before are untouched and are what is left when the action ends. |
| **Quarantine** (access VLAN) | One virtual network adapter is put in the **quarantine VLAN you built**: `Set-VMNetworkAdapterVlan -Access -VlanId <n>`. The adapter's prior mode (untagged or access, and its VLAN id) is recorded and set back exactly. | It never creates a VLAN, a DHCP scope, a gateway or an ACL, and **never writes an allow ACL**. What the VLAN may reach is decided by your own network. A device with a static address loses its connection until the VLAN is restored. |
| **Block flow** (deny ACL) | One extended ACL per direction with `Add-VMNetworkAdapterExtendedAcl`, action `Deny`, on the VM that owns an end of the flow: a local and a remote address, protocol and port, a weight from DENIS's reserved band, not stateful. Read back. | Only with the per-instance switch *Allow DENIS to create deny rules on this Hyper-V host*. Deny only: no code path builds an allow ACL. Never `any`, never a network, never a name. An ACL has no name or comment, so the owner marker is the weight and the exact fields (see below). |
| **Disable port** (disconnect) | `Disconnect-VMNetworkAdapter` for one virtual network adapter. The prior switch name is recorded; `Connect-VMNetworkAdapter -SwitchName` puts it back. | Only a virtual network adapter of a VM: never a network interface of the host and never an adapter of the management OS. It does not touch the adapter's VLAN or ACL settings. |
| End sessions | Not available: Hyper-V has no call DENIS can use to end the sessions of a VM. | |

## The flow ACL's weight is its owner marker

An extended ACL has no name and no comment, so DENIS cannot write its owner marker into it. DENIS therefore **reserves the weights 60000 to 64999**: the ACL it makes for ledger row `n` has the weight `60000 + (n mod 5000)`. It identifies the ACL by its **exact fields** (direction, action, local and remote address, protocol, local and remote port, weight), reads it back, and removes it by those exact fields only. An ACL of yours is never touched.

* A VM that already holds an ACL with a weight from 60000 to 64999 that no active DENIS action accounts for is refused (*"Those weights are reserved for DENIS"*). Give your own ACLs another weight.
* A VM that holds an ACL of its own with a weight of 65000 or more is refused too: Hyper-V may evaluate it before DENIS's deny ACL **[verify]**. Keep your own ACLs below 60000.
* A deny ACL in the band that no active action accounts for is an **orphan** (for example after a lost record): the reconcile job lists it, and an administrator can remove it. The reconcile job lists only deny ACLs in the band and only removes what it listed, by its exact fields.
* A device that stores the new ACL with another weight than DENIS sent is detected by the read-back: the action fails and DENIS removes the ACL by the fields the device showed.

## How a VM is found

The action path names a device by its IP address (and hardware address when the request has one). DENIS reads `Get-VM | Get-VMNetworkAdapter` and acts only when **exactly one** VM owns the address:

* no VM has it: refused. The addresses come from the integration services of a running VM, so a VM that is off, or has no integration services, has none **[verify]**; the hardware address is always known;
* more than one VM has it: refused, DENIS acts on none;
* the address and the hardware address belong to different VMs: refused;
* more than 2000 network adapters: refused (too many to search by address).

A VM that holds an address of DENIS itself, the gateway, a DNS or directory server or a protected network, or the Hyper-V host's own address, is never acted on, whichever of its addresses was named.

**Identity.** Every write names the VM by its id. Before a release DENIS checks that the VM behind the id still has the hardware addresses it had when the action was planned: if the id now belongs to another machine, DENIS does not touch it, and the release stays open and loud. A VM that no longer exists has nothing left to restore, and the release says so. A rename does not matter.

**Live migration and clusters.** One connector reaches one host. A VM that moved to another host, or a cluster node, is not found by id on this host: the action is refused, and a release of an action whose VM is gone from this host has nothing to restore and closes. For a failover cluster, add one connector per host and put the VMs that move on the protected list or accept the refusals.

## Setup

1. **WinRM.** Enable WinRM on the Hyper-V host, over **HTTPS** (port 5986). **DENIS speaks only WinRM Basic authentication**, not NTLM or Kerberos: enable it on the host (`Set-Item WSMan:\localhost\Service\Auth\Basic $true`). HTTP (5985) works only if the host has separately opted into `AllowUnencrypted`, which would send the password in the clear on every action: do not. Kerberos and NTLM are the right long-term answer and are a known limitation of this connector.
2. **A Windows account for DENIS** that can manage VM network adapters: a member of Hyper-V Administrators, or a narrower delegated account that may read VMs and their network adapters and write their port ACLs, extended ACLs, VLAN settings and connections (`Get-VM`, `Get-VMNetworkAdapter*`, `Add/Remove-VMNetworkAdapterAcl`, `Add/Remove-VMNetworkAdapterExtendedAcl`, `Set-VMNetworkAdapterVlan`, `Disconnect/Connect-VMNetworkAdapter`). With Basic authentication this has to be a **local** account on the host, or a domain account the host accepts for Basic **[verify]**.
3. **Connector settings** under *Settings → Enforcement* → **Microsoft Hyper-V** → **Add…**: the **WinRM host**, the **port**, the **username** (for example `Administrator`), the **password**, whether to **use HTTPS**, whether to **verify the TLS certificate** (a self-signed WinRM listener certificate is the common case), and *Never quarantine these VM names*: names as Hyper-V shows them, or VM ids. **Put the VM DENIS itself runs in, and any router or firewall VM, on this list.**
4. **Quarantine VLAN (optional).** Build the VLAN yourself, with its DHCP scope, gateway and ACLs: allow what a quarantined VM needs (DHCP, DNS, NTP, a remediation server) and deny the rest. DENIS never creates any of it. Enter its id (1 to 4094) in *Quarantine VLAN id*. Leave it empty to switch quarantine off. The virtual switch has to carry that VLAN on its external port.
5. **Flow blocks:** tick *Allow DENIS to create deny rules on this Hyper-V host* only if you accept that DENIS writes ACLs on your VMs. It is off by default, and DENIS will not create or delete any ACL while it is off. Changing it needs your password. A wrong deny ACL can cut off traffic.

## Refusals that protect the VM and the host

* Quarantine and disconnect refuse an adapter that is **not connected** to a switch (there is nothing to do), and a quarantine refuses an adapter that is a **trunk** or uses a **private VLAN** (it belongs to a VM that carries several networks), and one already in the quarantine VLAN.
* A release never moves a VLAN or a switch somebody else changed: if the adapter is not in the state DENIS left it in (a third VLAN, another switch), DENIS does not touch it and the release stays open. If somebody already put it back, the release only closes the record.
* Only one DENIS action holds a virtual network adapter at a time.

## What is verified

Only against the fake WinRM server in `src/nac_hyperv/connector/tests.rs` (the SOAP envelopes are real, the PowerShell is interpreted): finding the VM (an address, a hardware address, ambiguity, a mismatch, a list that cannot be read), the old isolation with the same cmdlets as before, the id-addressed isolation, the VLAN and the disconnect with exact restore (untagged, access), the extended ACL (creating, identifying by exact fields, removing, both directions, two VMs), the weight band and the orphan list, the opt-in and lab refusals, lost and dropped answers (a command that never reaches its finished state is *not confirmed* and can still be released), a refused cmdlet (compensated, nothing left behind, or *partly applied* and still releasable), a VM that was replaced or is gone, a VLAN or switch that somebody else changed, orphans, expiry, and the password never appearing in the ledger or the audit log.

Behaviours that are unproven vendor facts (marked **[verify]** in the code):

* `Get-VM -Id '<guid>' | Add-VMNetworkAdapterAcl ...` (the VM from the pipeline) behaves like `-VMName`, and with no adapter named the ACLs apply to every network adapter of the VM. (The old module assumed one adapter per VM.)
* `Get-VMNetworkAdapter` reports `VMId`, `VMName`, `Name`, `Id`, `MacAddress`, `SwitchName`, `Connected` and `IPAddresses`; `IPAddresses` is filled only for a running VM with integration services.
* `Add-VMNetworkAdapterExtendedAcl` accepts `-Action Deny -Direction Inbound|Outbound -LocalIPAddress -RemoteIPAddress -Protocol -LocalPort -RemotePort -Weight -Stateful`, and `Remove-VMNetworkAdapterExtendedAcl` with the same parameters removes exactly that ACL. An ACL with the **higher weight is evaluated first**. `Get-VMNetworkAdapterExtendedAcl` reports the fields back, writing "any" as `*` or leaving it empty.
* `Set-VMNetworkAdapterVlan -Access -VlanId` and `-Untagged` put an adapter back as it was; `Get-VMNetworkAdapterVlan` reports `OperationMode`, `AccessVlanId`, `NativeVlanId` and the allowed list.
* `Disconnect-VMNetworkAdapter` keeps the adapter's VLAN and ACL settings, and `Connect-VMNetworkAdapter -SwitchName` reconnects it.
* A new ACL or VLAN stops new traffic of the adapter. **Whether an ACL cuts a connection that is already open is not verified.** The ACL is expected to drop the next packet either side sends, because the switch sees every packet of the port and a plain ACL has no "allow established" exception, but this has not been tried, and it can differ by Windows Server version and by the other switch extensions on the host. The read-back confirms what the cmdlets report; nothing confirms that the switch's compiled filter state has caught up.
* A command that is still running after five short polls is an unknown outcome, never a failure: it may still finish on the host.

## Limits

* One host per connector; a VM that moved is refused.
* IPv4 and IPv6 are both accepted for host actions and flows.
* Traffic between two VMs on the same host switch is filtered by an ACL on the VM that owns the end; DENIS puts an ACL on each end that is a VM of this host.
* The old isolation applies to the VM as a whole; the quarantine and the disconnect to one adapter.
* End sessions is not available.

## Credentials

The WinRM password is stored only in the encrypted secret store (`nac.hyperv.password`) and sent as the HTTP Basic credential of the WinRM request. It is never written to the ledger, the audit log or a notification.

## Existing instances

Instances from earlier versions keep working and nothing changes for them: the same VM name as the target, the same cmdlets in the same order (read the ACL list, add both entries in one script, read it back), the same ledger row with the ACL list as found, and the old *Block…* and *Unblock…* buttons act as before. The connection test only checks that the configuration is complete: there is no harmless WinRM request that does not name a VM, so the host is first contacted when you plan a block. Records the old routes made are released through the old *Unblock…*; records of the new actions are released through the new action list. What changed is only who writes the record: the ledger row is now written by the enforcement orchestrator, which also applies the hourly cap and the kill switch and stamps the row with the connector instance.
