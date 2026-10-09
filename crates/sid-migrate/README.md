# sid-migrate

Offline data transfer between SQLite and PostgreSQL. Stop writers before export
and keep the target offline until import and verification finish. This utility
does not implement live migration, replication or point-in-time recovery.

```sh
sid-migrate export --source sqlite:///var/lib/sid/source.db --output snapshot.json
sid-migrate import --target sqlite:///var/lib/sid/target.db --input snapshot.json
sid-migrate verify --source sqlite:///var/lib/sid/source.db --target sqlite:///var/lib/sid/target.db
```

Snapshot format 3 requires explicit history state for every profile. It preserves
history revisions, retained accepted entries, epoch manifests and statuses,
including retired provenance, and sealed epoch keys. It also carries the public
field-encryption derivation parameters and sealed OPAQUE server setup. It contains
neither a plaintext epoch key, unwrapped OPAQUE setup nor the external master key.
Protect the snapshot as authentication data; export
creates a new file with mode `0600` on Unix and refuses an existing output path.

Restore the installation's existing organization identity and server key custody
before importing its data. Import requires the same installation organization ID:
a new organization is a different password-history input domain. The archive
restores the original sealed OPAQUE setup before password credentials: starting
the destination first can generate a conflicting setup, which import refuses.
Issuer custody remains a separate prerequisite. Restore the exact external
key-source versions required by sealed fields
and check that the owning evaluator can open the keys before enabling password
replacement. Database equality alone does not prove key availability.

Import validates history references and sealed-key owner/epoch context before
writing. It also checks the setup's sealing context and key-version reference,
and refuses an OPAQUE credential without its setup. This checks public metadata,
not decryption: verify external key custody before enabling the destination.
Each owner's complete history and its audit commit in one transaction,
before credentials are installed. An exact repeated history is a no-op; an
existing different history is refused rather than overwritten, rolled back or
merged. Retired epochs stay retired, including provenance whose eligible key was
already destroyed. Epochs are ordered by creation time and ID; entries by
descending sequence and epoch ID. Import refuses noncanonical archives before
writing. The whole instance import is not one transaction: after an interruption,
keep it offline and inspect the import result before continuing. The history and
credential phases support exact retries; this does not establish retry safety
for every other entity. Repeated credentials are accepted only when their
complete stored record is identical.

Old snapshots without complete history must be re-exported. Existing unconverted
Poseidon history causes export, live history reads, epoch preparation and proved
password replacements to refuse. Reset also refuses before removing the old
credential, including when no policy proof is supplied. Refusal rolls back the
reset, credential, history and session changes together. Ordinary credential
reads remain available; retaining unsupported rows does not mean the current
private-history checker enforces them. Reconcile them before transfer
rather than discarding them. A stale snapshot cannot recreate later records;
conflicting target history is never treated as permission to reset retention.

`verify` compares history contents, sealed OPAQUE setup, sealed history keys and derivation parameters, not
just record counts. It does not decrypt keys or establish completeness after a
rollback. Independent key-custody and consistent database backups remain needed.
