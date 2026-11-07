# sid-attestation

Device key attestation for StructuredID: enrolling, rotating, revoking and
reading the key a device holds for its Profile
(`sid.v1.attestation.AttestationService`). CE stores the attestation without
verifying its chain, so a device is never marked hardware-attested by it.

A key is bound only by its ceremony: `StartDeviceEnrollment` issues a
single-use challenge to the owner's own sufficient sign-in, and
`FinishDeviceEnrollment` (or `RotateDeviceKey` for a rotation) carries the
device-key proofs over it. The finish commits the device, its key, the
consumed ceremony and the outcome together; a retry with the same operation
key (`Idempotency-Key` and `SID-Operation-Period`) gets the recorded answer.

## Running it as its own process

The service is one more process serving the installation's **account API**
resource. A call is admitted with an access token for that resource:

- A device's **owner** acts on its keys by this service's own rule, with no
  role: the Profile is the one of the stored, live sign-in the token was
  issued from, never read from the token's subject. Because an owner's call
  asks the issuer no permission question, the receiver asks the issuer at
  admission whether the token is still current (RFC 7662 inspection).
- Any **other caller** is decided by the issuer for that device
  (`device:<id>`) or Profile (`profile:<id>`): the installation's
  administrator holds every action through the built-in
  `installation-administrator` assignment. A device the caller may not reach
  answers as an unknown one.
- Changing a key needs a Profile's own sign-in: a machine token or an
  impersonation is refused even with the action.

| Method | Action |
|---|---|
| `GetDeviceAttestation` | `attestation.device.read` |
| `StartDeviceEnrollment`, `FinishDeviceEnrollment`, `RotateDeviceKey`, `RevokeDeviceKey` | `attestation.device.change` |
| `ListDeviceAttestations` | `attestation.profile.read` |

No shared cache is involved: an ended sign-in is refused at the next call, by
every replica, including one started afterwards.

### What the installation registers

- A **machine client** for this service holding, on the account API
  resource, the built-in `permission-checker` role (to ask about other
  callers) and the built-in `token-inspector` role (to ask whether an owner's
  token is current). The two are separate permissions.

### Configuration

| Variable | Meaning |
|---|---|
| `DATABASE_URL` | The installation's database, where devices, sign-ins and attestations live |
| `SID_MASTER_KEY_FILE` | The installation's master key file, mounted as for the issuer: it seals the pending ceremonies every replica reads |
| `SID_GRPC_UPSTREAM` | The installation's gRPC address |
| `SID_ISSUER_URL` | The installation's public URL |
| `SID_RECEIVER_RESOURCE` | The account API resource indicator |
| `SID_RECEIVER_ORIGIN` | The scheme and authority callers address this service at |
| `SID_AUTHZ_CHECKER_CLIENT_ID`, `SID_AUTHZ_CHECKER_ISSUER`, `SID_AUTHZ_CHECKER_METHOD`, `SID_AUTHZ_CHECKER_SECRET_FILE` | The machine client above |

A service that cannot load its checker credential does not start.

### Browser callers

`sid-ui-host` sends this service's calls to its process with the session's
account API token:

```
SID_UI_API_ROUTES=sid.v1.attestation.AttestationService=http://sid-attestation:50061
```
