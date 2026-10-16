# Enforcement: RADIUS CoA / Disconnect (RFC 5176)

Status: **Experimental. Simulator only: not yet validated on real equipment.** Everything below was built from RFC 2865, 2866, 2869 and 5176 and checked against a fake access device on UDP in DENIS's own tests. It has never been run against a real wireless controller, switch, Cisco ISE, Aruba ClearPass or FreeRADIUS. Nothing here is listed as validated on hardware.

Lab use: ending a session (the pre-4.1 action of this connector) is allowed only while an administrator has switched on *Allow connectors that are not validated on real equipment (lab use)* under *Settings → Response policy*. It is the pre-4.1 "block" under a new name, so the second switch for new actions is not needed. Releasing always works.

Besides this connector's own refusals, every action through it goes through DENIS's common guards before anything is sent: loopback, unspecified, broadcast and multicast addresses, DENIS itself, the gateway, and an address or MAC in an open `arp_conflict` alert are refused, and a list DENIS cannot read refuses the action.

**A protocol, not one vendor.** DENIS speaks to whatever already authenticated the session: a wireless controller, a RADIUS-fronted switch, Cisco ISE, Aruba ClearPass, FreeRADIUS, or anything else that implements RFC 5176.

## What each action does, and what it does not do

| Action | What DENIS does | What it does not do |
|---|---|---|
| **End sessions** (`radius_disconnect`) | Sends one **Disconnect-Request** over UDP to the access device that authenticated the session, and reads its answer. | It ends **one session** and leaves nothing on the device. The device may sign in again at once, and what the access device's own policy gives it then is not decided by DENIS. **It is not a block.** |
| Block device | **Unsupported.** A RADIUS Disconnect ends a session. It is not a block. | |
| Block a flow | **Unsupported.** RADIUS cannot filter traffic. | |
| Quarantine | **Unsupported.** A CoA quarantine is applied again by the RADIUS server at the next sign-in. Real quarantine belongs in your policy server (ISE, ClearPass, FreeRADIUS). | |
| Disable port | **Unsupported.** RADIUS controls no switch port. | |

**The CoA-Request of RFC 5176 is not built.** It changes a session's attributes without ending it, for example to move it to a quarantine VLAN. The attributes that do that are vendor specific (Cisco `Filter-Id` and AV-pairs, Aruba and HPE VSAs), they need an ACL or VLAN that already exists on the access device, and the RADIUS server applies its own policy again at the next authentication. Building it here would put one vendor's connector under a "protocol, not one vendor" label. If you need it, it belongs in its own vendor connector, or in your policy server.

### There is nothing to roll back

A Disconnect has no undo and leaves no state on the device. So:

* its **durability is none**: nothing stays on the device;
* the record is closed as **completed** as soon as the access device acknowledges (Disconnect-ACK); there is no end time and nothing for the expiry job to do;
* a **release sends nothing** and has nothing to restore. On the action path a completed action cannot be released ("not active"). The old *Unblock…* button only closes DENIS's own record and sends no packet.

## DENIS has no session data, so the plan says what it sends

DENIS holds **no RADIUS session data**: no accounting feed and no session list. A Disconnect-Request has to name the session by an attribute the access device recorded, so DENIS names it by **one attribute**, the one set in the connector as the *session attribute*:

| Session attribute | Sent as | Where DENIS gets the value |
|---|---|---|
| `calling_station_id` | Calling-Station-Id (31) | the device's **MAC address**, written in the format set in *MAC address format in Calling-Station-Id* (`dash_upper` `AA-BB-CC-DD-EE-FF` by default, `dash_lower`, `colon_upper`, `colon_lower`, `dot_lower` `aabb.ccdd.eeff`, `plain_lower`). Use the format your access device records; it matches the attribute as it stored it. |
| `framed_ip_address` | Framed-IP-Address (8) | the device's **IPv4 address** |
| `user_name` | User-Name (1) | **you type it** (DENIS knows no user name for a device) |
| `acct_session_id` | Acct-Session-Id (44) | **you type it** (DENIS knows no accounting session) |

* A typed value is the action's `params.value` (API) and is sent exactly as typed. Without one, `user_name` and `acct_session_id` are **refused with the reason**, and nothing is sent. For these two attributes the connector's own *Block…* button (the old route) takes the value as the target. For `calling_station_id` and `framed_ip_address` an action from a device needs no typed value.
* Every packet also carries **NAS-IP-Address** (only when the connector sets one) and a **Message-Authenticator** signed with the shared secret. Nothing else.
* The **plan** lists exactly this: the Disconnect-Request, the access device's address and port, the attribute and its value, the NAS-IP-Address, the number of tries and the wait, and that nothing is left to undo. The shared secret is never shown.
* An access device that holds no session with that value answers with a Disconnect-NAK (`Session Context Not Found`, 503): the action then **fails** with that cause and nothing changed.

## Retries and answers

One UDP send, then at most **5** more tries of the **same** packet (the same Identifier: a retransmission, not a new request), each waiting at most **30 seconds** (the settings: *Retries* 0 to 5, *Timeout* 100 to 30000 ms). The wait is bounded and never open ended.

* **Disconnect-ACK**: the session was ended. Completed.
* **Disconnect-NAK**: the access device refused. Failed, with its Error-Cause in the message. Not retried.
* **Signed answers** (since 4.1.3): when an answer carries a Message-Authenticator, it must match the shared secret, or the answer counts as not genuine (**unconfirmed**). An answer **without** one is accepted on its Response Authenticator alone, because many access devices do not sign their answers; so the signature check protects only against a forged signed answer. If your access device signs every answer, tick **Require a signed answer (Message-Authenticator)**: an unsigned answer is then treated as not genuine too. Since 4.1.4 DENIS also remembers, per connector, that the device has signed an answer: from then on an unsigned answer counts as not genuine without any tick, so nobody on the path can swap in an unsigned one. A device that never signs keeps working as before. If a device really stopped signing (new firmware, another device at the same address), tick **My access device stopped signing its answers**: unsigned answers are accepted again.
* **No usable answer after every try**, or an answer whose authenticator does not match the secret: **unconfirmed**. DENIS does not know whether the access device acted. A reply that fails the authenticator check is not read and not retried (it means a wrong secret, or an answer that is not from the configured device).
* Nothing is sent at all when the plan is refused, when a lab switch is off, or when the session value is missing.

## Setup

1. On the access device enable **RFC 5176 Dynamic Authorization** (CoA / Disconnect) for DENIS's address, and note its listening port (UDP 3799, or 1700 on some) and the **shared secret** DENIS must use. The access device must accept Disconnect-Requests from DENIS **[verify per vendor]**.
2. Decide which attribute identifies a session on your access device: **User-Name**, **Calling-Station-Id** (a MAC address on most), **Acct-Session-Id** (the most precise, but DENIS does not know it) or **Framed-IP-Address**. Prefer `calling_station_id` or `framed_ip_address`: DENIS can take those from a device.
3. *Network → Equipment* → **RADIUS CoA** → **Add…**: the **NAS address** (a plain IP address, no host name), the **port**, an optional **NAS-IP-Address**, the **shared secret** (a sealed secret), the **session attribute**, the **MAC address format**, targets never to disconnect (DENIS itself, your management devices; MACs are compared whatever separator they use), a **timeout** and a **retry count**, and whether every answer must be signed.

## Orphans and the secret

A Disconnect creates no object on the access device, so there is nothing to list or remove. The **shared secret** is read from the encrypted secret store for the one action and never written to the ledger, the audit log, a step or a notification.

## What is verified

Only against the fake access device in `src/nac_radius_coa/orch_tests.rs` (and the authenticator tests in `src/nac_radius_coa.rs`, which check the HMAC-MD5 of RFC 2202 and a hand derived Request and Response Authenticator): the old routes send the same packet byte for byte and write the same ledger row as the pre-4.1 code, and the old unblock sends nothing; the Calling-Station-Id in every format, the Framed-IP-Address, typed User-Name and Acct-Session-Id; refusal when DENIS has no value for the attribute, for a device with no MAC or no IPv4 address, and for a protected value; the plan's statement of what is sent; NAK with its cause, silence after the bounded identical tries, a lost first packet repeated, a reply with the wrong secret; a release that sends nothing; the secret in no row, step or audit entry; the lab refusals sending zero packets; every unsupported action refused with zero packets; only Disconnect-Requests ever built. **Not verified on any real access device.**

Behaviours that are unproven vendor facts (marked **[verify]**):

* Whether a given access device requires the Message-Authenticator (DENIS always sends it) and whether it accepts Disconnect-Requests for the attribute you chose.
* How a vendor writes Calling-Station-Id (hence the format setting) and whether it matches it case-insensitively.
* Whether an access device really drops the session on a Disconnect-ACK, and how long until the supplicant authenticates again.
* IPv6: NAS-IPv6-Address (RFC 3162) is not implemented, so the NAS-IP-Address is IPv4 only. Framed-IP-Address is IPv4 only.

## Limits

* Transient: it ends one session; the device may sign in again at once.
* One access device per connector instance.
* A MAC address in a format the access device does not recognise names no session; the NAK says so.

## Credentials

A single RADIUS shared secret (`nac.radius_coa.shared_secret`), in the encrypted secret store.
