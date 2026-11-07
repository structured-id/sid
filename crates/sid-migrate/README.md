# sid-migrate

Offline data transfer between SQLite and PostgreSQL through the portable
snapshot of `sid-storage`. Stop the source's writers and workers before
export; the snapshot is consistent only when nothing writes while it is read.
Exporting does not disable the source: an ordinary backup lets the original
installation continue. This utility does not implement live migration,
replication or point-in-time recovery.

```sh
head -c 32 /dev/urandom > archive.key            # keep it apart from the archive
sid-migrate export --source sqlite:///var/lib/sid/source.db --output snapshot.sidsnap --key-file archive.key
sid-migrate import --target sqlite:///var/lib/sid/target.db --input snapshot.sidsnap --key-file archive.key
sid-migrate verify --source sqlite:///var/lib/sid/source.db --target sqlite:///var/lib/sid/target.db
```

## The archive

An export is never written unencrypted. The archive holds the snapshot
encrypted with AES-256-GCM under the 32-byte archive key, behind a manifest
(format, snapshot id, source backend, installation organization, SHA-256 of
the snapshot) that is readable without the key and authenticated with the
contents. Export creates a new file with mode `0600` on Unix and refuses an
existing output path. The archive key protects this archive only: it is not a
key-encryption key, opens no sealed field and does not replace recovery of
the installation's server keys.

## What a snapshot carries

The installation organization, the OIDC issuer registry with every signing-key
generation (sealed as stored), device key bindings live and revoked, accounts,
credentials, complete password history for every profile with the history
evaluator's sealed keys and its own key versions, the sealed OPAQUE server
setup, the public field-encryption derivation parameters, durable work and the
completions and bindings of keyed commands. It contains neither a plaintext
key, an unwrapped OPAQUE setup nor any master key.

## Import

Import checks the archive, the snapshot's identity, schema and references
before it writes anything to the target. The target is an uninitialized
installation (no installation organization, issuers or profiles), or one
holding the interrupted import of this same snapshot, which import then
resumes. An initialized installation, of the same authority or another, is
not an import destination; neither is a target holding another snapshot's
import. Import records its snapshot's id and digest first, so only that
snapshot resumes it.

Import starts nothing: authentication, issuance and restored work begin only
when the restored installation is started. Before activating it, the
deployment stops or fences the superseded installation's writers and workers
and restores the exact external key versions the sealed fields need. For an
offline move the source stays stopped after the destination is activated.
A restored copy of a still-running installation would be a second issuer of
the same identity; nothing in the database can tell a copy apart, so keeping
one of them stopped is the deployment's decision.

Each owner's history and its audit commit in one transaction, before
credentials are installed. An exact repeated record is a no-op; a different
stored record is refused rather than overwritten, rolled back or merged.
Retired history epochs stay retired. The whole import is not one transaction:
after an interruption, keep the target stopped and run the same import again.

## Verify

`verify` compares the installation organization, issuers and their keys,
the sealed OPAQUE setup, derivation parameters, cutoffs, history contents,
history keys and device key bindings, not just record counts. It decrypts
nothing: it does not establish key availability or completeness after a
rollback.
