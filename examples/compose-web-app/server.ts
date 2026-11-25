// Notes: a small server-side web application that signs its users in at a
// StructuredID installation (OpenID Connect authorization code flow) and
// keeps its own session and its own permissions.
//
// What the application owns: the session cookie, the notes and the rule
// "a note is read by the account that wrote it". What the installation
// owns: who the user is. The application identifies an account by the pair
// (issuer, subject) of the verified ID token and by nothing else: not by an
// email, and not by reading anything into the subject's shape.
//
// Run: node server.ts (Node strips the types; there is no build step).
import { randomBytes, timingSafeEqual } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import * as oidc from "openid-client";

/** A setting the application cannot start without. */
function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    console.error(`${name} is not set; see README.md, "Connect the application"`);
    process.exit(2);
  }
  return value;
}

// snippet:configuration
// The issuer exactly as the installation names itself (its SID_ISSUER), the
// client the console registered for this application, and this
// application's own public address. There is no default issuer.
const ISSUER = new URL(required("SID_ISSUER"));
const CLIENT_ID = required("SID_CLIENT_ID");
const CLIENT_SECRET = required("SID_CLIENT_SECRET");
const APP_URL = new URL(required("APP_URL"));
const PORT = Number(process.env.PORT ?? APP_URL.port ?? 3000);
/** The one callback registered for the client, to the character. */
const CALLBACK = new URL("/callback", APP_URL).toString();
// end:configuration

// snippet:discovery
// Discovery reads the issuer's metadata once at start and refuses a document
// that names another issuer. Plain http is accepted only for a local
// installation; a deployed one is https.
const local = ISSUER.protocol === "http:" && ISSUER.hostname === "localhost";
// The client authenticates at the token endpoint the way it is registered:
// a web application created in the console uses client_secret_basic (its
// page shows the method under Credentials). The installation refuses any
// other method for this client.
const provider = await oidc.discovery(
  ISSUER,
  CLIENT_ID,
  undefined,
  oidc.ClientSecretBasic(CLIENT_SECRET),
  local ? { execute: [oidc.allowInsecureRequests] } : undefined,
);
// end:discovery

/** An account of this application: the verified issuer and subject. */
type Account = string;
const accountOf = (issuer: string, subject: string): Account =>
  JSON.stringify([issuer, subject]);

interface Session {
  account: Account;
  /** Sent back by every form of this session; a request without it is refused. */
  csrf: string;
}
interface PendingSignIn {
  state: string;
  nonce: string;
  verifier: string;
  startedAt: number;
}
interface Note {
  owner: Account;
  text: string;
}

// One process, so memory is enough for the example. An application behind a
// load balancer keeps these three in its own shared store.
const sessions = new Map<string, Session>();
const pendingSignIns = new Map<string, PendingSignIn>();
const notes = new Map<string, Note>();

const SESSION_COOKIE = "notes_session";
/** Ties a started sign-in to the browser that started it. */
const SIGN_IN_COOKIE = "notes_sign_in";
const SIGN_IN_LIFETIME_MS = 10 * 60 * 1000;
const MAX_FORM_BYTES = 16 * 1024;

const token = () => randomBytes(32).toString("base64url");

function cookies(request: IncomingMessage): Map<string, string> {
  const jar = new Map<string, string>();
  for (const part of (request.headers.cookie ?? "").split(";")) {
    const at = part.indexOf("=");
    if (at > 0) jar.set(part.slice(0, at).trim(), part.slice(at + 1).trim());
  }
  return jar;
}

function setCookie(name: string, value: string, maxAgeSeconds: number): string {
  const secure = APP_URL.protocol === "https:" ? "; Secure" : "";
  return `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}${secure}`;
}

function sessionOf(request: IncomingMessage): Session | undefined {
  const id = cookies(request).get(SESSION_COOKIE);
  return id ? sessions.get(id) : undefined;
}

function sameText(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

const escapeHtml = (text: string) =>
  text.replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );

function page(response: ServerResponse, status: number, body: string): void {
  response.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    // An answer for one account is never stored for another.
    "cache-control": "no-store",
  });
  response.end(
    `<!doctype html><meta charset="utf-8"><title>Notes</title><main>${body}</main>`,
  );
}

function redirect(
  response: ServerResponse,
  to: string,
  setCookies: string[] = [],
): void {
  response.writeHead(303, {
    location: to,
    "cache-control": "no-store",
    ...(setCookies.length ? { "set-cookie": setCookies } : {}),
  });
  response.end();
}

async function form(request: IncomingMessage): Promise<URLSearchParams | null> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    size += (chunk as Buffer).length;
    if (size > MAX_FORM_BYTES) return null;
    chunks.push(chunk as Buffer);
  }
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

// snippet:sign-in
/** Sends the browser to the installation to sign in. */
async function startSignIn(response: ServerResponse): Promise<void> {
  const verifier = oidc.randomPKCECodeVerifier();
  const pending: PendingSignIn = {
    state: oidc.randomState(),
    nonce: oidc.randomNonce(),
    verifier,
    startedAt: Date.now(),
  };
  const key = token();
  pendingSignIns.set(key, pending);
  const to = oidc.buildAuthorizationUrl(provider, {
    redirect_uri: CALLBACK,
    scope: "openid",
    state: pending.state,
    nonce: pending.nonce,
    code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
    code_challenge_method: "S256",
  });
  redirect(response, to.toString(), [
    setCookie(SIGN_IN_COOKIE, key, SIGN_IN_LIFETIME_MS / 1000),
  ]);
}

/**
 * Completes the sign-in this browser started: the code is redeemed with the
 * verifier kept for it, and the ID token is verified (signature, issuer,
 * audience, nonce, expiry) before anything is read from it.
 */
async function finishSignIn(
  request: IncomingMessage,
  response: ServerResponse,
  url: URL,
): Promise<void> {
  const key = cookies(request).get(SIGN_IN_COOKIE);
  const pending = key ? pendingSignIns.get(key) : undefined;
  if (key) pendingSignIns.delete(key);
  if (!pending || Date.now() - pending.startedAt > SIGN_IN_LIFETIME_MS) {
    page(
      response,
      400,
      `<p>This sign-in was not started in this browser, or it has expired.</p><p><a href="/login">Sign in again</a></p>`,
    );
    return;
  }
  let subject: { iss: string; sub: string };
  try {
    const tokens = await oidc.authorizationCodeGrant(provider, url, {
      pkceCodeVerifier: pending.verifier,
      expectedState: pending.state,
      expectedNonce: pending.nonce,
      idTokenExpected: true,
    });
    const claims = tokens.claims();
    if (!claims) throw new Error("the installation sent no ID token");
    subject = { iss: claims.iss, sub: claims.sub };
  } catch (refusal) {
    // The reason goes to the operator's log; the user is told only that the
    // sign-in did not complete. An OAuth error carries its code and text.
    const { message, error, error_description } = refusal as Error & {
      error?: string;
      error_description?: string;
    };
    console.error(
      "sign-in refused:",
      error ? `${error}: ${error_description ?? ""}` : message,
    );
    page(
      response,
      400,
      `<p>The sign-in could not be completed.</p><p><a href="/login">Sign in again</a></p>`,
    );
    return;
  }
  // Only the account key is kept: the tokens are not this application's
  // session, and they are not forwarded anywhere.
  const id = token();
  sessions.set(id, {
    account: accountOf(subject.iss, subject.sub),
    csrf: token(),
  });
  redirect(response, "/", [
    setCookie(SESSION_COOKIE, id, 8 * 60 * 60),
    setCookie(SIGN_IN_COOKIE, "", 0),
  ]);
}
// end:sign-in

// snippet:permission
/**
 * The application's own rule, checked on the server for every read: a note
 * is read by the account that wrote it. Being signed in is not enough.
 */
function readNote(
  request: IncomingMessage,
  response: ServerResponse,
  id: string,
): void {
  const session = sessionOf(request);
  if (!session) {
    page(response, 401, `<p>Sign in to read a note.</p><p><a href="/login">Sign in</a></p>`);
    return;
  }
  const note = notes.get(id);
  if (!note) {
    page(response, 404, `<p>There is no such note.</p>`);
    return;
  }
  if (note.owner !== session.account) {
    page(response, 403, `<p>This note belongs to another account.</p>`);
    return;
  }
  page(
    response,
    200,
    `<h1>Your note</h1><p data-test="note">${escapeHtml(note.text)}</p><p><a href="/">Back</a></p>`,
  );
}
// end:permission

function home(request: IncomingMessage, response: ServerResponse): void {
  const session = sessionOf(request);
  if (!session) {
    page(
      response,
      200,
      `<h1>Notes</h1><p>You are not signed in.</p><p><a href="/login" data-test="sign-in">Sign in</a></p>`,
    );
    return;
  }
  const own = [...notes]
    .filter(([, note]) => note.owner === session.account)
    .map(
      ([id, note]) =>
        `<li><a href="/notes/${id}">${escapeHtml(note.text.slice(0, 40))}</a></li>`,
    )
    .join("");
  page(
    response,
    200,
    `<h1>Notes</h1><p data-test="signed-in">You are signed in.</p>
<form method="post" action="/notes"><input type="hidden" name="csrf" value="${session.csrf}">
<input name="text" maxlength="500" required aria-label="Note"><button data-test="save">Save note</button></form>
<ul data-test="notes">${own}</ul>
<form method="post" action="/logout"><input type="hidden" name="csrf" value="${session.csrf}"><button data-test="sign-out">Sign out</button></form>`,
  );
}

/** A form of a signed-in session, or the refusal already sent. */
async function ownForm(
  request: IncomingMessage,
  response: ServerResponse,
): Promise<{ session: Session; fields: URLSearchParams } | undefined> {
  const session = sessionOf(request);
  if (!session) {
    page(response, 401, `<p>Sign in first.</p><p><a href="/login">Sign in</a></p>`);
    return undefined;
  }
  const fields = await form(request);
  if (!fields || !sameText(fields.get("csrf") ?? "", session.csrf)) {
    page(response, 403, `<p>This form was not sent from this session.</p>`);
    return undefined;
  }
  return { session, fields };
}

async function route(
  request: IncomingMessage,
  response: ServerResponse,
): Promise<void> {
  const url = new URL(request.url ?? "/", APP_URL);
  const method = request.method ?? "GET";
  const note = /^\/notes\/([A-Za-z0-9_-]{43})$/.exec(url.pathname);

  if (method === "GET" && url.pathname === "/") return home(request, response);
  if (method === "GET" && url.pathname === "/health") {
    response.writeHead(200, { "content-type": "text/plain" }).end("ok");
    return;
  }
  if (method === "GET" && url.pathname === "/login") return startSignIn(response);
  if (method === "GET" && url.pathname === "/callback") {
    return finishSignIn(request, response, url);
  }
  if (method === "GET" && note) return readNote(request, response, note[1]!);
  if (method === "POST" && url.pathname === "/notes") {
    const sent = await ownForm(request, response);
    if (!sent) return;
    const text = (sent.fields.get("text") ?? "").trim().slice(0, 500);
    if (!text) return redirect(response, "/");
    const id = token();
    notes.set(id, { owner: sent.session.account, text });
    return redirect(response, `/notes/${id}`);
  }
  if (method === "POST" && url.pathname === "/logout") {
    const sent = await ownForm(request, response);
    if (!sent) return;
    // This ends the application's own session. The installation's sign-in is
    // its own and stays: the next "Sign in" may not ask for the password.
    sessions.delete(cookies(request).get(SESSION_COOKIE)!);
    return redirect(response, "/", [setCookie(SESSION_COOKIE, "", 0)]);
  }
  page(response, 404, `<p>Not found.</p>`);
}

createServer((request, response) => {
  route(request, response).catch((failure) => {
    console.error("request failed:", failure);
    if (!response.headersSent) page(response, 500, `<p>Something went wrong.</p>`);
    else response.end();
  });
}).listen(PORT, () => {
  console.log(`Notes listens on ${APP_URL.origin}, signs in at ${ISSUER.origin}`);
});
