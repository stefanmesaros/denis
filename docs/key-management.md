# Key management (4.4)

DENIS encrypts every stored secret: integration credentials, notification channel passwords, AI keys, SNMP
communities, the authenticator apps of your users, the Autopilot keys and the push subscriptions. This page is for
the person who looks after those keys: what the keys are, how to change them, how to keep a copy that survives a lost
disk, and how to move a tenant to another installation with its secrets.

**Updating from 4.3 is one way for the secrets.** The first start of 4.4 changes the format of the stored secrets
(`enc1:` to `enc2:`); an older version cannot read it. Take your own backup first. The ways back are
`denis secrets downgrade-envelope` or restoring the copy made before the update
([Security](security.md#upgrading-the-secret-format-44)); for a PostgreSQL pair the whole checklist is in
[Upgrading a pair to 4.4](high-availability.md#upgrading-a-pair-to-44).

Nothing on this page has to be done for DENIS to work. It is here for the day a key may have leaked, an administrator
who knew a key leaves, or a disk is lost.

## The two keys

| Key | Where it is | What it protects | If it is lost |
|---|---|---|---|
| **Master key** | The file `secrets.key` in the data directory, mode `0600`, outside every database | Opens the data key of every tenant, and a few values it seals itself (operator authenticator apps and MSP link keys in the control store, the MSP link's relay token) | Every integration credential and authenticator app of every tenant has to be entered again. The inventory and history are not affected. |
| **Data key** (one per tenant) | In that tenant's own database, encrypted by the master key | Every secret of that tenant | It cannot be recovered without the master key; with the master key it is in the database |

Keep `secrets.key` apart from your database backups (not in the same place or archive). Losing it is the one loss DENIS
cannot repair. See [Security](security.md#upgrading-the-secret-format-44) for the formats.

`denis secrets status` (with the same `--db`, `--data-dir` and, on PostgreSQL, `--database-url` as `denis run`) shows
the id of the master key, each tenant's data key, an unfinished rotation, a kept previous key and the escrow copy.
The key id is a short, harmless label (it cannot be turned back into the key); it is what the audit trail uses.

## Change the data key of a tenant

```
denis secrets rotate --tenant acme            # one tenant
denis secrets rotate --tenant default         # the installation's own database
denis secrets rotate --all                    # the installation's own database and every registered tenant
denis secrets rotate --tenant acme --dry-run  # only count
```

A new data key is made and every secret of that tenant is encrypted under it, in **one transaction** (all of them or
none; a value that changed in between makes it fail and change nothing, then you run it again). The old key is kept
for a few seconds (`--grace-seconds`, default 5) so that a save that was in flight a moment ago still reads, then the
values written in those seconds are encrypted under the new key and the old key is deleted. Nothing outside that tenant
is touched.

* **It is safe while DENIS runs.** No restart, no downtime. Run it in a quiet moment if you can; a second run
  is harmless.
* **If it is interrupted** (the command is killed, the machine stops), run it again: it first finishes the earlier
  rotation (it sees the kept old key), then rotates once more. `denis secrets status` says when one is unfinished.
* **It refuses** a database that has no data key yet (run `denis secrets migrate`, or start DENIS 4.4 once), and a
  database stamped for another tenant than the one you named.
* The audit trail gets an entry `secrets.rotate_dek` with the tenant, the counts and the new key id, never a value.

When to do it: after a person who could read the database left, after a database backup of unknown safety was
exposed. Rotating the data key does not help against someone who also has `secrets.key` and a copy of the database
from **before** the rotation.

## Change the master key

```
denis secrets rotate-master --dry-run
# stop DENIS (on a pair: stop both nodes)
denis secrets rotate-master --confirm-stopped
```

Only the small data key rows are encrypted again (one write per tenant, the secrets themselves are not touched),
plus the few values the master key seals itself. In order:

1. Everything is checked with both keys first. A store that opens with neither key, a leftover `secrets.key.new`
   without a record, or a previous key that was not retired stops the command **before anything is written**.
2. The new key is written to `secrets.key.new` (mode `0600`) and a small journal `secrets.rotation` is written. The
   journal holds check values only, never a key.
3. Each database is encrypted again in its own transaction; the control store too. Every value is tried with the old
   key and, if that does not open it, with the new one, so running the command again after any interruption just
   continues.
4. Everything is read back with the new key.
5. Only then is `secrets.key` replaced (atomically). The previous key stays as **`secrets.key.old`**: backups made
   before the rotation open only with it. The pair's check value in the shared database is updated.

If anything fails, `secrets.key` is still the old key and the databases are either still on it or partly on the new one;
**run the command again** (do not delete `secrets.key.new` or the journal). `denis secrets status` says when a
rotation is unfinished.

When you no longer need backups from before the rotation, and after a start has shown that everything works:

```
denis secrets retire-old-key --confirm
```

It checks that nothing in the installation still needs the old key, overwrites the file and deletes it.

**On a PostgreSQL pair** (the pair is Experimental, as in [High availability](high-availability.md)):

1. Stop DENIS on the standby, then on the leader ([the commands](high-availability.md#stopping-both-nodes-for-a-command-line-tool)).
2. On the leader: `denis secrets rotate-master --confirm-stopped` with its `--database-url` and `--data-dir`.
3. Copy the new `secrets.key` to the standby's data directory (mode `0600`, owned by the service user). Do not copy
   `secrets.key.old` to the standby unless you want the same backups to open there.
4. Start the leader, then the standby. A standby that still has the old file refuses to start with the usual message
   about the key, which is the protection working.

Why DENIS must be stopped: a running process holds the old key in memory and would stop being able to read its secrets
as soon as the data key rows change. Rotating the data key (above) does not have this limit.

## Keep a copy of the master key that survives a lost disk

```
denis secrets key-export --to /safe/place/denis-master-key.json
```

You are asked for a passphrase twice (at least 12 characters). It is typed at the terminal, never taken from an
argument, a file or the environment, and DENIS does not store it. The file holds the master key encrypted with
AES-256-GCM under a key made from the passphrase with Argon2id (64 MiB, 3 passes). Without the passphrase it is
useless, and **nobody can recover a forgotten passphrase**, including us.

* `denis secrets key-check --file ...` asks for the passphrase and says whether it opens the file and whether the
  key inside is the one this installation uses now. It changes nothing. Do this once after you made the file.
* `denis secrets key-import --from ...` puts `secrets.key` back on a new machine (it refuses to replace an existing
  `secrets.key`). Then restore the database and start.
* After `rotate-master` the file holds the **old** key. Make a new one.

### Optional escrow

An escrow copy is that same file, kept by someone else or somewhere else on purpose (a safe, a second administrator),
so that a lost `secrets.key` is not the end of every credential. **It is off by default.** To say that one exists,
add `--escrow`:

```
denis secrets key-export --to /safe/place/denis-master-key.json --escrow
```

DENIS then records a note (the time and the key id, never the passphrase), and `denis secrets status` says whether the
copy is current or out of date after a rotation. DENIS never sends the file anywhere and has no way to open it
without the passphrase. The passphrase must be kept by the person or place you choose; do not store it with the file.

## Move a tenant with its secrets

A tenant export normally carries secrets only this installation can open (the importing installation asks for them
again). To bring them along:

```
denis tenant export acme --to acme.db --with-secrets     # on the source: you type a passphrase twice
denis tenant import acme --from acme.db --name "Acme" --with-secrets   # on the target: you type it once
```

The export contains the tenant's data key encrypted under the passphrase (the same Argon2id and AES-256-GCM as above),
and every secret of the tenant under that data key. The import opens the data key with the passphrase, encrypts it
under the target's master key and goes on as for any import. A wrong passphrase does **not** stop the import: the
secrets are asked for again in the tenant's console, exactly as without the flag, and the command says so. The
passphrase is needed only until the import is done; nothing remains of it on either side.

The live tenant on the source is not changed. The export file is still sensitive (anyone who has it and the
passphrase can open the secrets): move it as you would move the secrets.

## What this does not do

* It does not protect against someone with root on the DENIS host, a memory dump of the running process, or someone
  holding the master key and the database together.
* It does not re-encrypt backups made earlier. Keep `secrets.key.old` while you may still restore one.
* There is no button in the console for these commands yet. They run on the DENIS host.
* Typing a passphrase works on Linux and macOS.

## Evidence

Tested on SQLite and on PostgreSQL 16: a rotation reads back every value (connector credentials, AI keys, notification
channels, SNMP communities, Autopilot keys, push subscriptions, authenticator apps), a failure in the middle changes
nothing, the master key rotation can be interrupted and finished, and unsafe states are refused before anything is
written. Not tested: a rotation of a very large installation (best guess: seconds), the pair runbook on two real nodes.
