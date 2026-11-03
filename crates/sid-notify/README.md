# sid-notify

Notification delivery for StructuredID: it consumes the facts owed to it from
the event bus, routes them to channels (email, webhook, web push) and serves
the template API (`sid.v1.admin.NotificationTemplateService`) that the
administration UI uses.

## Running it as its own process

The template API is one more process serving the installation's **account
API** resource, the resource the administration UI signs in to. A call is
admitted with an access token for that resource; the issuer decides, for each
call, whether its subject may perform the method's action, and that same
question establishes that the token, its sign-in and its subject are still
current. No shared cache is involved: a sign-out or revocation is refused at
the next call, by every replica, including one started afterwards.

| Method | Action |
|---|---|
| `ListTemplates`, `GetTemplate`, `PreviewTemplate` | `notify.template.read` |
| `UpdateTemplate`, `ResetTemplate` | `notify.template.change` |
| `SendTestNotification` | `notify.template.test` |

The installation's administrator holds every action through the built-in
`installation-administrator` assignment. Another operator is given exactly
the actions it needs by a role assigned on the account API resource.

### What the installation registers

- A **machine client** for this service (its client ID and secret), holding
  the built-in `permission-checker` role on the account API resource. It asks
  the issuer's authorization API about callers; it gains none of their rights.

### Configuration

| Variable | Meaning |
|---|---|
| `SID_GRPC_UPSTREAM` | The installation's gRPC address (issuer registry and authorization API) |
| `SID_ISSUER_URL` | The installation's public URL |
| `SID_RECEIVER_RESOURCE` | The account API resource indicator |
| `SID_RECEIVER_ORIGIN` | The scheme and authority callers address this service at |
| `SID_AUTHZ_CHECKER_CLIENT_ID`, `SID_AUTHZ_CHECKER_ISSUER`, `SID_AUTHZ_CHECKER_METHOD`, `SID_AUTHZ_CHECKER_SECRET_FILE` | The machine client above: its issuer (the installation's `/i/<handle>` issuer), `client_secret_basic` and the file holding its secret |
| `SID_IDENTITY_GRPC_ADDRESS` | The identity service; a test send without a recipient goes to the caller's own address, asked of it with the caller's own token |
| `SID_NOTIFY_DATABASE_URL`, `SID_NATS_URL`, `SID_EVENT_RECEIVERS` | Delivery jobs, the event bus and the deployment's required receivers |

A service that cannot load its checker credential does not start.

### The administration UI

`sid-ui-host` sends the template API's calls to this process with the same
session token as every account API call:

```
SID_UI_API_ROUTES=sid.v1.admin.NotificationTemplateService=http://sid-notify:9040
```
