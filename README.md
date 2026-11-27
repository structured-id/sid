# StructuredID Community Edition

StructuredID signs users in to your applications and checks what they may
do there. You run it yourself: your installation manages its own local
accounts and their access.

- **For a developer:** add sign-in and access checks to an application
  without writing an account system.
- **For an administrator:** manage the users of your installation, their
  sign-in methods and their roles from a web console.

One installation serves your applications. Local sign-in works on its own:
it needs no account at structured.id and no outside service. Federation is
optional, in a delivery that supports the platform you choose.

What an installation gives you:

- an OpenID Connect and OAuth 2.0 provider your applications sign users in
  with, through any conforming client library;
- password sign-in in which the server never receives the password (OPAQUE),
  and passkeys;
- an account page where users manage their own sign-in methods and sessions;
- an administration console for users, applications, roles and settings;
- permission checks for your applications and their APIs;
- user provisioning from an HR system or identity manager over SCIM 2.0;
- sign-in links and one-time codes by email, where an administrator has
  enabled them and configured a mail provider.

## Two ways to use it

**A server beside your application.** Run the published image and point your
application at it as an OpenID Connect provider. The application needs only a
client library; it does not embed anything. Two images are published:

| Image | Storage |
|---|---|
| `ghcr.io/structured-id/sid:embedded` | SQLite on its own volume; nothing else to run |
| `ghcr.io/structured-id/sid:latest` | Your PostgreSQL server |

Both run as a separate process; `embedded` names the image that carries its
own database, not a library.

**The engine inside a Rust application.** The `structured-id` crate
([crates/sid](crates/sid), library name `sid`) opens an installation over the
storage you give it and offers sign-in, accounts, OAuth and administration as
a Rust API, with no network transport and no web UI of its own; the UI is
optional. Use it from this repository at a release tag; it is not published
on crates.io. It is licensed as the rest of the repository (see
[License](#license)).

The authorization core can be tried by itself, without opening an
installation: `cargo run -p sid-authz --example role_administration` walks
through granting a role, using it, the refusals and the revocation.

## Quick start

The embedded image runs a complete installation with no database or broker
to set up. It serves the account pages and the administration console from
the same address. The port is published on this machine only:

```bash
docker run -d --name sid -p 127.0.0.1:8080:8080 \
  -e SID_ISSUER=http://localhost:8080 \
  -v sid-data:/var/lib/sid \
  ghcr.io/structured-id/sid:embedded
```

1. **Claim the installation.** Until it has an administrator, the server
   logs a claim token at startup (`docker logs sid`, the line "No
   administrator yet"). Open <http://localhost:8080/account/register>,
   register, and enter the token: that account becomes the administrator.
2. **Use your account** at <http://localhost:8080/account/>.
3. **Open the console** at <http://localhost:8080/admin/>. It works in the
   session you already have, with no second sign-in. The console checks your
   rights on every call: an account that does not administer the
   installation is refused (`the caller may not perform this operation`).

Next, sign users in to an application of your own:
[examples/compose-web-app](examples/compose-web-app/README.md) adds an
installation to a Compose project, registers a web application in the
console and signs in from the application's own link, with the checks that
another account and a request with no session are refused.

## Running it for real

- **Issuer.** `SID_ISSUER` is the installation's issuer. An application
  recognises an account by the pair of issuer and subject, and takes the
  issuer from its own registration, so keep the issuer stable. A public
  installation needs an `https://` issuer. Where the sign-in pages or the
  console are shown can change without changing it.
- **Data with SQLite.** The volume at `/var/lib/sid` holds the
  installation's database and its keys. Back them up together.
- **Data with PostgreSQL.** The `latest` image takes `SID_DATABASE_URL` and
  keeps the installation's keys on the same volume. A restore needs both a
  backup of the database and those keys; neither restores the installation
  alone ([sid-migrate](crates/sid-migrate/README.md) describes the archive
  and the keys). The image does not fall back to SQLite when the database
  cannot be reached.
- **Who may register.** Decide it before the address is public (console,
  enrollment settings).
- **Where the console is.** The console's address is an installation setting
  (Settings, Addresses): another path on the installation's address or a host
  of the same site. The account pages stay at `/account/`.

| Variable | Default in the images | Meaning |
|---|---|---|
| `SID_ISSUER` | none, required | The installation's issuer |
| `SID_DATABASE_URL` | none, required by the `latest` image | PostgreSQL connection string |
| `SID_DATABASE_MAX_CONNECTIONS` | `20` | Most connections one process opens to PostgreSQL; each replica opens its own |
| `SID_BIND` | `0.0.0.0:8080` | HTTP address: sign-in, the account pages, the console, SCIM |
| `SID_GRPC_BIND` | `0.0.0.0:50051` | gRPC address of the API |
| `RUST_LOG` | `sid=info` | Log level |

## Security

Report a vulnerability privately, as [SECURITY.md](SECURITY.md) describes,
not in a public issue.

## License

AGPL-3.0-only, see [LICENSE](LICENSE). Copyright 2026 Dmitry Prudnikov, see [NOTICE](NOTICE). Each crate's `Cargo.toml` names its license: `sid-crypto` and `sid-keys` are Apache-2.0 primitives and carry their own license file.

> Proto definitions (`proto/`) are licensed separately under Apache 2.0 to allow unrestricted integration by third parties.

Contributions are accepted under the [Structured World Contributor License Agreement](https://sw.foundation/cla); see [CONTRIBUTING.md](CONTRIBUTING.md).
