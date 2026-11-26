# Sign users in to a web application with StructuredID in Docker Compose

Add a StructuredID installation to a Compose project and sign users in to a
server-side web application with it. You will sign in from the application's
own link, save a note and read it, and verify that another account, and a
request with no session, cannot read that note.

## Context

| | |
|---|---|
| Audience | A developer of a server-side web application |
| Edition and mode | Community Edition, as a separate service beside the application |
| Installation | `ghcr.io/structured-id/sid:embedded`: SQLite on its own volume, nothing else to run |
| Who signs in | Local accounts of your own installation. Nothing is registered at structured.id and nothing leaves your machine |
| Application | Node 24 or newer, the [`openid-client`](https://www.npmjs.com/package/openid-client) library, version 6 |
| Protocol | OpenID Connect authorization code flow with PKCE, a confidential client |
| Source | This directory: `compose.yaml`, `server.ts`, `check/walk.ts` |

The application here is a small Node server so the whole recipe is one file
to read. Any language works the same way with a conforming OpenID Connect
library: the installation is a standard provider.

## Prerequisites

- Docker with Compose v2.
- Ports 8080 and 3000 free on `localhost`.
- A browser.

## Steps

All commands run in this directory, on your machine.

### 1. Start the installation

```sh
docker compose up -d sid
```

Expected result: <http://localhost:8080/.well-known/openid-configuration>
answers, and its `issuer` is exactly `http://localhost:8080`.

### 2. Claim the installation

An installation with no administrator prints a claim token at startup:

```sh
docker compose logs sid
```

Find the line "No administrator yet" and copy the token that starts with
`sidclaim_`. On its first start the installation also prepares the keys it
checks passwords with, which takes some seconds; the line "ZKPP verifying
keys ready" in the same log says it has. Then open
<http://localhost:8080/account/register>, enter the token, a login and a
password, and create the account.

Expected result: you are signed in to your account, and that account
administers the installation.

### 3. Register the application

Open <http://localhost:8080/admin/applications/create>.

1. Name the application `Notes`, choose **Web App**, press **Next**.
2. Enter the redirect URI `http://localhost:3000/callback`, exactly.
3. Leave **Sign users in (OpenID Connect)** on, press **Create**.

Expected result: the page shows a **Client ID** and a **Client Secret**, and
the line "The application can sign users in". The secret is shown once.

What the choice in step 3 did: an application obtains a token only for a
resource it was given access to. A sign-in needs the installation's UserInfo
resource, so the wizard gave the application access to it and saved it as the
application's default target. The application's page shows this under
**Access**, where you can also give it to an application created without it.

### 4. Connect the application

Copy `.env.example` to `.env` and paste the two values:

```sh
SID_CLIENT_ID=<the Client ID>
SID_CLIENT_SECRET=<the Client Secret>
```

`.env` is read by the application's container only. The secret is a server
setting: it never goes into a page, a script or a URL.

```sh
docker compose up -d --build app
```

Expected result: `docker compose logs app` shows
`Notes listens on http://localhost:3000, signs in at http://localhost:8080`.

The application's code, in `server.ts` (server-side only):

- `snippet:configuration`: the issuer, the client and the application's one
  callback come from settings; there is no default issuer.
- `snippet:discovery`: the issuer's metadata is read once, and the client
  authenticates with `client_secret_basic`, the method a web application
  created in the console is registered with.
- `snippet:sign-in`: the sign-in is started with a state, a nonce and a PKCE
  verifier kept for this browser; the callback redeems the code with them and
  the library verifies the ID token before anything is read from it. The
  account is the pair of the token's issuer and subject. The subject is an
  opaque value: do not parse it, and do not use an email as the account key.
- `snippet:permission`: the application's own rule, checked on the server on
  every read. Being signed in is not permission to read another account's
  note.

## Verify

1. Open <http://localhost:3000> and press **Sign in**. You already have a
   session at the installation, so it asks only whether **Notes** may sign
   you in. Press **Allow**.

   Expected result: the application shows "You are signed in."

2. Save a note. Expected result: the note's page, at an address under
   `/notes/`. Copy that address.

3. Open a private browser window. Register a second account at
   <http://localhost:8080/account/register> (no claim token this time), then
   open <http://localhost:3000>, sign in and open the copied address.

   Expected result: **403**, "This note belongs to another account."

4. Ask the server directly, with no session:

   ```sh
   curl --silent --output /dev/null --write-out '%{http_code}\n' '<the copied address>'
   ```

   Expected result: `401`.

5. Press **Sign out** in the application. Expected result: the application's
   session ends and its pages ask to sign in. The session at the
   installation is the installation's own and stays, so the next sign-in may
   not ask for the password.

`check/walk.ts` performs these steps in a real browser from an empty
installation and removes everything it started:

```sh
cd check
npm ci
npx playwright install chromium
node walk.ts
```

It prints the image digest and the client library version it ran against.

## Troubleshoot

The application logs the reason of a refused sign-in
(`docker compose logs app`); the user is shown only that the sign-in did not
complete.

| What you see | Cause | Correction |
|---|---|---|
| Creating the account in step 2 does not complete right after the first start | The installation is still preparing the keys it checks passwords with | Wait for "ZKPP verifying keys ready" in `docker compose logs sid`, then create the account again |
| The installation answers `invalid_target` | The application has access to no resource, or no default target | On the application's page in the console open **Access**, add **OIDC UserInfo** with `openid`, press **Make default**. Sign in again |
| The log says `invalid_client: authentication failed` | The client secret in `.env` is not this client's, or the library sends it in the request body | Check `SID_CLIENT_ID` and `SID_CLIENT_SECRET`; keep `oidc.ClientSecretBasic` in `snippet:discovery`. Then `docker compose up -d app` |
| The installation refuses the redirect URI | The callback the application sends differs from the registered one | Make the registered redirect URI equal to `APP_URL` followed by `/callback`, to the character |
| The application exits with "`SID_CLIENT_ID` is not set" | `.env` is missing or empty | Do step 4 |
| "This sign-in was not started in this browser, or it has expired" | The callback was opened without the sign-in it belongs to, or ten minutes passed | Press **Sign in again** |
| Discovery fails at start with an issuer mismatch | `SID_ISSUER` of the application differs from the installation's | Set both to the same address in `compose.yaml` |

## Production transition

This recipe proves the integration on one machine. A deployment changes:

- **Addresses.** `SID_ISSUER` becomes the installation's public `https://`
  address, and stays that address for good: accounts are keyed by it. The
  application gets its own `https://` address; register that exact callback.
  The shared network namespace of `compose.yaml` exists only so that
  `localhost` means the same thing to the browser and the application; with
  public addresses the two services are ordinary separate services.
- **Cookies.** Over `https` the application's cookies are sent with `Secure`
  (the example does this from `APP_URL`).
- **The application's state.** Sessions, pending sign-ins and notes are in
  the process memory here. An application with more than one replica keeps
  them in its own shared store.
- **Storage of the installation.** The `sid-data` volume holds the database
  and the signing keys: back it up. PostgreSQL is an explicit choice, with
  the `ghcr.io/structured-id/sid:latest` image and `SID_DATABASE_URL`.
- **The client secret.** Deliver it through your platform's secret store,
  not a file in the project directory.
- **Registration.** Decide who may register at the installation before it is
  public (console, enrollment settings).

## Next step

Give the application its own API: register the API as a resource, give the
client access to it under **Access**, and request tokens for it with the
`resource` parameter.
