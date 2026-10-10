# StructuredID

StructuredID is person-centric trust infrastructure for portable identities and privacy-preserving relationships.

Identity belongs to the person. Trust is independently verifiable. Relationships are scoped to the relying party.

## Features

- **OAuth 2.0 / OpenID Connect** - Standard-compliant identity flows
- **WebAuthn / Passkeys** - Passwordless authentication
- **OPAQUE** - Zero-knowledge password authentication
- **Federation** - Progressive enrollment (OIDC → DNS + X.509 → Enterprise CA)
- **Plugin Architecture** - Extensible via plugins

## Quick Start

```bash
# Build
cargo build --release

# Run
./target/release/sid

# Or with cargo
cargo run -p sid-server
```

## Architecture

```
crates/
├── sid-core/      # Domain models (Profile, Credential, Session), errors
├── sid-proto/     # gRPC service definitions (generated from proto/)
├── sid-plugin/    # Plugin API traits (StorageBackend, AuthProvider)
├── sid-authn/     # Authentication (OPAQUE, WebAuthn, OAuth2/OIDC, MFA) — consumable lib
├── sid-auth/      # Auth decision service (PDP): forward-auth, JWT validation, route policy
├── sid-auth-proxy/# Application forward-proxy (PEP) for legacy apps
├── sid-authz/     # Authorization (RBAC, Cedar policies)
├── sid-fed/       # Federation (X.509 certificate chains, instance discovery)
├── sid-admin/     # Admin ops library + CLI (backup, integrity, bulk import)
├── sid-storage/   # Storage backends (PostgreSQL, SQLite)
└── sid-server/    # Main binary (HTTP + gRPC servers)
```

**Note:** Profile IS the user in CE (no separate User entity).
CE instance IS the organization (implicit).

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SID_ISSUER` | - (required) | Public base URL of the installation; its host is the installation organization's domain |
| `SID_DATABASE_URL` | - (required) | PostgreSQL connection string |
| `SID_GRPC_BIND` | `127.0.0.1:50051` | gRPC listen address |
| `SID_BIND` | - | HTTP listen address of the embedded transcoder (OIDC endpoints, SCIM); unset serves no HTTP |
| `SID_SCIM_BASE_URL` | `SID_ISSUER` | Public URL the SCIM endpoint is reached under (`/scim/v2` follows) |
| `SID_AUTHZ_REQUEST_VERIFIERS_FILE` | - | JSON file naming the services trusted to confirm sender proofs of original requests (see below); unset trusts none |
| `SID_ZKPP_ENABLED` | `true` | Build policy-proof verifiers; accepts only `true`, `false`, `1` or `0` |
| `SID_ZKPP_REQUIRE_PROOF` | `true` | Require a password-policy proof for password setup; `false` explicitly permits policy-unverified setup. Cannot be `true` while verifiers are disabled |
| `SID_ZKPP_POLICY_VERSION` | `1` | Accepted compiled password policy; an unknown or malformed version stops startup |
| `SID_PASSWORD_HISTORY_EPOCH_NOT_BEFORE` | - | RFC 3339 instant: no history entry is written under a key created before it (a suspected key compromise), and such keys are replaced at their owner's next password operation. Raised at start into this server's history store and the in-process evaluator's; an older or unset value lowers nothing. A malformed or future value stops startup |
| `SID_PASSWORD_HISTORY_EVALUATOR` | - | gRPC address of a separately deployed password-history evaluator; unset runs the evaluator in this server (see below) |
| `SID_PASSWORD_HISTORY_EVALUATOR_RESOURCE` | - | Resource indicator of the evaluator; required with `SID_PASSWORD_HISTORY_EVALUATOR` |
| `SID_PASSWORD_HISTORY_TOKEN_UPSTREAM` | - | gRPC address of the issuer this server obtains its token for the evaluator from; required with `SID_PASSWORD_HISTORY_EVALUATOR` |
| `SID_PASSWORD_HISTORY_CALLER_*` | - | This server's client credential at the evaluator: `_CLIENT_ID`, `_ISSUER`, `_METHOD` and the method's `_SECRET_FILE` or `_KEY_FILE`/`_ALGORITHM`/`_KEY_ID`; required with `SID_PASSWORD_HISTORY_EVALUATOR` |
| `RUST_LOG` | `sid=info` | Log level |

Malformed explicit ZKPP settings stop startup. Optional proof setup still verifies
every submitted proof; it never accepts an invalid proof as policy-unverified.
Verifier keys must enforce the configured policy, with one key per history-domain
count. A pending password operation whose policy is no longer accepted must be
restarted before it can install a password. Ordinary password login does not
generate a new policy proof.

A password's policy evidence names the verifying key (artifact) that accepted its
proof. Upgrading demotes verdicts stored before artifacts were recorded to
policy-unverified and keeps what they claimed in `credential_policy_evidence_legacy`;
the next proved password change records a new verdict. Ordinary login and other
factors are unaffected.

A replaced password-history key takes no new entries, but the passwords already
retained under it are still compared until retention removes them; the key is
then destroyed. Replacement does not make previously copied keys or entries
secret again.

Password history has two authorities: the evaluator holds the per-owner history
keys and answers blinded requests; the checker, in this server, receives each
proved password's tag, runs the history KSF and compares it with the retained
entries. This server runs both and seals history keys with its field keys, so
whoever controls it holds both: a tag together with its key lets that password
be guessed without the KSF. A deployment that keeps them apart runs the
evaluator as its own service, with its own database and keys, and points this
server's `SID_PASSWORD_HISTORY_EVALUATOR` at it; this server then holds no
history key, and the evaluator never receives a tag or a retained entry. The
client relays the evaluator's proofs, which this server verifies itself.

### Trusted request verifiers

A permission checker asking about an original request's subject may hand
over its confirmation that it verified the request's DPoP proof. The
authorization API accepts it only from a service this file names for the
target resource and proof kind, and only while that service also holds the
checker role there:

```json
{"verifiers": [{"subject": "oauth_client:<client_id>",
                "resources": ["https://orders.example.com"],
                "profiles": ["dpop"]}]}
```

`subject` is `oauth_client:<client_id>` or `machine:<machine user id>`;
`resources` are registered resource indicators. Without a matching entry, a
DPoP-bound token gets no decision. The deployment still has to deliver the
verifier's calls over its authenticated transport (for example mesh mTLS);
a file that cannot be read or parsed stops start-up.

### Role administration

Using a role and managing who holds it are separate rights. The installation's
administrator manages every role; anyone else administers only through an
administrative assignment: an ordinary `AssignRole` whose `admin` envelope names
the permitted operations (assign, revoke, edit role, redelegate), the roles, the
permissions those roles may hold at most, the eligible recipient kinds (and
optionally one group) and the longest validity it may give. Holding the role
alone administers nothing, and an administrator does not need the roles it
assigns.

- One envelope must cover the whole change; envelopes are never combined.
- Nobody assigns to themselves, directly or through a group they belong to,
  and a Profile that granted a group a role cannot join that group.
- Every administered assignment expires within the envelope and its source.
- Each assignment records who granted it and on what authority
  (`provenance`); one an envelope approved keeps that envelope's permission
  ceiling, and `UpdateRole` never widens its role past it
  (`FAILED_PRECONDITION`, `APPROVED_CEILING`) until it is reauthorized.
- A redelegated administrative assignment ends with its source; ordinary
  grants outlive the administrator who made them.

Embedding applications call the same core, `sid_authz::admin::RoleAdministration`;
`cargo run -p sid-authz --example role_administration` walks through a grant,
its use, the refusals and the revocation.

### SCIM 2.0 inbound

With the default `scim` feature, `{SID_SCIM_BASE_URL}/scim/v2` serves RFC 7644
(`application/scim+json`) to HR systems and identity managers. Each source is a
provisioning connector registered through `sid.v1.admin.ProvisioningService`
and granted a role on the SCIM directory resource; it authenticates with its
SCIM bearer or with an OAuth client-credentials token from the installation's
issuer (`GetScimInboundConfig` returns the token endpoint and `client_id`).
Logins it provisions are federated usernames `userName#<organization domain>`.

## Password client conformance

[The installed-client suite](ci/password-clients/README.md) exercises the
immutable published TypeScript package in Node and Chromium against real gRPC registration, login,
password change and reset. It checks mandatory proofs, evaluator authenticity,
operation binding, retained-password refusal and durable registration retries.
The test adapter is separate from the product and uses the client's actual KSF
and prover; it does not replace them with reduced-cost fixtures.

## License

AGPL-3.0-only, see [LICENSE](LICENSE) for details.

> Proto definitions (`proto/`) are licensed separately under Apache 2.0 to allow unrestricted integration by third parties.

Contributions are accepted under the [Structured World Contributor License Agreement](https://sw.foundation/cla); see [CONTRIBUTING.md](CONTRIBUTING.md).
