// Walks the recipe of ../README.md from an empty installation, in a real
// browser, exactly as a reader does it: claim the installation, register the
// application in the console, connect it, then sign in as two accounts and
// read a note as its owner, as the other account and with no session.
//
// Run from this directory: `npm ci`, `npx playwright install chromium`,
// `node walk.ts`. It starts the parent directory's Compose file as a project
// of its own and removes that project, with its volume, when it ends: a
// reader's installation started from the same directory is another project,
// whose containers and data volume the walk never touches (its published
// ports then make the walk fail to start, which removes nothing of it). An
// `.env` already present in the parent directory is somebody's connection:
// the walk refuses to start rather than overwrite it.
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium, type Browser, type Page } from "playwright";

const recipe = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const envFile = resolve(recipe, ".env");
const SID = "http://localhost:8080";
const APP = "http://localhost:3000";

/** The walk's own Compose project: never the one a reader's `docker compose up` made. */
const PROJECT = "compose-web-app-walk";

const compose = (...args: string[]) =>
  execFileSync("docker", ["compose", "--project-name", PROJECT, ...args], {
    cwd: recipe,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  });

function expect(what: string, got: unknown, wanted: unknown): void {
  if (got !== wanted) {
    throw new Error(`${what}: expected ${String(wanted)}, got ${String(got)}`);
  }
  console.log(`ok: ${what}: ${String(got)}`);
}

async function until<T>(
  what: string,
  read: () => Promise<T | undefined> | T | undefined,
  seconds: number,
): Promise<T> {
  const deadline = Date.now() + seconds * 1000;
  for (;;) {
    const value = await Promise.resolve()
      .then(read)
      .catch(() => undefined);
    if (value !== undefined) return value;
    if (Date.now() > deadline) throw new Error(`${what}: not within ${seconds}s`);
    await new Promise((done) => setTimeout(done, 1000));
  }
}

// Test credentials of this walk: generated here, used here, printed nowhere.
const account = (name: string) => ({
  login: `${name}-${randomBytes(3).toString("hex")}@sid.example.com`,
  password: `Rc!${randomBytes(12).toString("base64url")}9a`,
});

async function register(
  page: Page,
  who: { login: string; password: string },
  claim?: string,
): Promise<void> {
  await page.goto(`${SID}/account/register`, { waitUntil: "networkidle" });
  if (claim) await page.getByLabel("Claim token").fill(claim);
  await page.getByLabel("Login").fill(who.login);
  await page.getByLabel("Password", { exact: true }).fill(who.password);
  await page.getByLabel("Confirm password").fill(who.password);
  await page.getByRole("button", { name: "Create account" }).click();
  await page.waitForURL(
    (url) => !url.pathname.startsWith("/account/register"),
    { timeout: 180_000 },
  );
  await page.waitForLoadState("networkidle");
}

/** README, "Register the application": the console's create wizard. */
async function registerApplication(
  page: Page,
): Promise<{ clientId: string; clientSecret: string }> {
  await page.goto(`${SID}/admin/applications/create`, {
    waitUntil: "networkidle",
  });
  await page.getByLabel("Application name").fill("Notes");
  await page.getByText("Web App", { exact: true }).click();
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page
    .getByPlaceholder("https://app.example.com/callback")
    .fill(`${APP}/callback`);
  // "Sign users in (OpenID Connect)" is left on, as the README says.
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await page.locator('[data-test="sign-in-saved"]').waitFor({ timeout: 60_000 });
  const shown = await page
    .locator(".q-stepper__step-inner input[readonly]")
    .evaluateAll((fields) =>
      fields.map((field) => (field as HTMLInputElement).value),
    );
  const [clientId, clientSecret] = shown;
  if (!clientId || !clientSecret) {
    throw new Error("the wizard did not show a client id and a client secret");
  }
  return { clientId, clientSecret };
}

/** README, "Verify": the application's own sign-in link, to its home page. */
async function signIn(
  page: Page,
  who?: { login: string; password: string },
): Promise<void> {
  await page.goto(`${APP}/`, { waitUntil: "networkidle" });
  await page.locator('[data-test="sign-in"]').click();
  const settled = (path: string) => () =>
    new URL(page.url()).pathname === path ? true : undefined;
  await page.waitForLoadState("networkidle");
  if (who && (await until("login page", settled("/account/login"), 15).catch(() => false))) {
    await page.getByLabel("Login").fill(who.login);
    await page.getByLabel("Password", { exact: true }).fill(who.password);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.waitForURL((url) => url.pathname !== "/account/login", {
      timeout: 120_000,
    });
    await page.waitForLoadState("networkidle");
  }
  const allow = page.getByRole("button", { name: "Allow", exact: true });
  const first = await Promise.race([
    allow.waitFor({ timeout: 60_000 }).then(() => "consent" as const),
    page
      .waitForURL(`${APP}/`, { timeout: 60_000 })
      .then(() => "application" as const),
  ]);
  if (first === "consent") {
    await allow.click();
    await page.waitForURL(`${APP}/`, { timeout: 60_000 });
  }
  expect(
    "the application's page after sign-in",
    await page.locator('[data-test="signed-in"]').innerText(),
    "You are signed in.",
  );
}

async function saveNote(page: Page, text: string): Promise<string> {
  await page.goto(`${APP}/`, { waitUntil: "networkidle" });
  await page.getByLabel("Note").fill(text);
  await page.locator('[data-test="save"]').click();
  await page.waitForURL((url) => url.pathname.startsWith("/notes/"));
  return page.url();
}

if (existsSync(envFile)) {
  console.error(`${envFile} exists; the walk does not overwrite a connection`);
  process.exit(2);
}

let browser: Browser | undefined;
let failure: unknown;
try {
  compose("up", "-d", "sid");
  await until(
    "the installation's discovery",
    async () => ((await fetch(`${SID}/.well-known/openid-configuration`)).ok ? true : undefined),
    120,
  );
  // What this run tested, recorded by the run itself.
  const container = compose("ps", "-q", "sid").trim();
  const image = execFileSync(
    "docker",
    ["inspect", "--format", "{{.Image}} {{index .Config.Image}}", container],
    { encoding: "utf8" },
  ).trim();
  console.log(`installation image: ${image}`);
  const lock = JSON.parse(
    readFileSync(resolve(recipe, "package-lock.json"), "utf8"),
  ) as { packages: Record<string, { version?: string }> };
  console.log(
    `client library: openid-client ${lock.packages["node_modules/openid-client"]?.version}`,
  );

  const claim = await until(
    "the claim token in the installation's log",
    () => compose("logs", "sid").match(/sidclaim_[A-Za-z0-9_-]+/)?.[0],
    60,
  );
  // README, step 2: a password is registered once the installation has
  // prepared the keys it checks passwords with on its first start.
  await until(
    "the password keys in the installation's log",
    () => (compose("logs", "sid").includes("ZKPP verifying keys ready") ? true : undefined),
    300,
  );

  browser = await chromium.launch({
    executablePath: process.env.CHROME_PATH || undefined,
  });
  const owner = account("owner");
  const other = account("other");

  // The administrator: claims the installation, registers the application.
  const first = await (await browser.newContext()).newPage();
  await register(first, owner, claim);
  const client = await registerApplication(first);
  writeFileSync(
    envFile,
    `SID_CLIENT_ID=${client.clientId}\nSID_CLIENT_SECRET=${client.clientSecret}\n`,
    { mode: 0o600 },
  );
  compose("up", "-d", "--build", "app");
  await until(
    "the application",
    async () => ((await fetch(`${APP}/health`)).ok ? true : undefined),
    180,
  );

  // The first account already has a session at the installation.
  await signIn(first);
  const note = await saveNote(first, "the owner's note");
  expect("the owner reads the note", (await first.goto(note))?.status(), 200);

  // A second account, in a browser of its own.
  const second = await (await browser.newContext()).newPage();
  await register(second, other);
  await signIn(second, other);
  const refused = await second.goto(note);
  expect("another account reads the note", refused?.status(), 403);
  expect(
    "what the other account is told",
    (await second.locator("main").innerText()).trim(),
    "This note belongs to another account.",
  );
  const own = await saveNote(second, "the other account's note");
  expect("the other account reads its own note", (await second.goto(own))?.status(), 200);

  // The server asked directly, with no session.
  expect(
    "no session reads the note",
    (await fetch(note, { redirect: "manual" })).status,
    401,
  );

  // Signing out ends the application's session only.
  await second.goto(`${APP}/`, { waitUntil: "networkidle" });
  await second.locator('[data-test="sign-out"]').click();
  await second.waitForURL(`${APP}/`);
  expect("after sign-out the note", (await second.goto(own))?.status(), 401);
} catch (caught) {
  failure = caught;
} finally {
  await browser?.close().catch(() => {});
  if (failure) {
    console.error(compose("logs", "--tail", "60"));
  }
  compose("down", "--volumes", "--rmi", "local");
  rmSync(envFile, { force: true });
}
if (failure) {
  console.error("WALK FAILED:", failure);
  process.exit(1);
}
console.log("walk passed");
