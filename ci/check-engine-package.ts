// SPDX-License-Identifier: AGPL-3.0-only
// Qualify the embedded engine as a package: package its crate closure,
// unpack the archives, build a fresh external consumer against them only
// (no workspace path, no lockfile carried over), check what its dependency
// graph holds and run it.

import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");

// The engine closure: every local crate a host's build of the engine needs.
const ENGINE = [
  "sid-crypto",
  "sid-keys",
  "sid-core",
  "sid-proto-build",
  "sid-proto",
  "sid-plugin",
  "sid-opaque-ke",
  "sid-voprf",
  "sid-authn",
  "sid-authz",
  "sid-storage",
  "structured-id",
];

// What a host embedding the engine must never receive: service binaries and
// transport adapters, unselected database drivers, a native provider it did
// not choose, and private crates.
const FORBIDDEN = [
  "sid-server",
  "sid-infra",
  "sid-auth",
  "sid-auth-proxy",
  "sid-serve",
  "sid-admin",
  "sid-fed",
  "sid-notify",
  "sid-ui-host",
  "sid-attestation",
  "sid-migrate",
  "sid-test-issuer",
  "tonic",
  "sqlx-postgres",
  "sqlx-mysql",
  "aws-lc-rs",
  "aws-lc-sys",
  "openssl",
  "openssl-sys",
  "ring",
];

// sqlx from its main branch until a sqlx release admits the SQLite the
// engine links (see the workspace [patch] section).
const SQLX = ["sqlx", "sqlx-core", "sqlx-macros", "sqlx-macros-core", "sqlx-postgres", "sqlx-sqlite"];
const SQLX_GIT = "https://github.com/launchbadge/sqlx";

type Metadata = {
  packages: {
    name: string;
    version: string;
    license: string | null;
    dependencies: { name: string; kind: string | null; path?: string; source: string | null }[];
  }[];
};

// The full `cargo metadata` of a consumer build runs past Node's default
// 1 MiB of captured output; the bound only guards against a runaway child.
const OUTPUT_LIMIT = 256 * 1024 * 1024;

function run(cwd: string, env: NodeJS.ProcessEnv, ...argv: string[]): string {
  return execFileSync(argv[0], argv.slice(1), {
    cwd,
    env,
    encoding: "utf8",
    maxBuffer: OUTPUT_LIMIT,
    stdio: ["ignore", "pipe", "inherit"],
  });
}

function main(): void {
  const work = mkdtempSync(join(tmpdir(), "sid-engine-package-"));
  const env = { ...process.env, CARGO_TARGET_DIR: join(work, "target") };
  // The packaged proto sources only, never a directory of this checkout.
  delete env.SID_PROTO_DIR;
  try {
    // The ZKPP crate lives in its own workspace (the zkpp submodule); the
    // engine resolves it by version, as its consumers will.
    const patch = "patch.crates-io.sid-pake-core.path='zkpp/crates/sid-pake-core'";
    // Packaging resolves against the registry, not the workspace [patch]:
    // sqlx from its main branch is named here as well.
    const sqlx = SQLX.flatMap((name) => [
      "--config",
      `patch.crates-io.${name}.git='${SQLX_GIT}'`,
      "--config",
      `patch.crates-io.${name}.branch='main'`,
    ]);
    run(root, env, "cargo", "package", "--locked", "--no-verify", "--config", patch, ...sqlx, ...ENGINE.flatMap((p) => ["-p", p]));
    run(join(root, "zkpp"), { ...env, CARGO_TARGET_DIR: join(work, "zkpp-target") }, "cargo", "package", "--locked", "--no-verify", "-p", "sid-pake-core");

    const unpacked = join(work, "crates");
    mkdirSync(unpacked);
    const archives = [join(work, "target/package"), join(work, "zkpp-target/package")].flatMap((dir) =>
      readdirSync(dir)
        .filter((name) => name.endsWith(".crate"))
        .map((name) => join(dir, name)),
    );
    const sources = new Map<string, string>();
    for (const archive of archives) {
      run(unpacked, env, "tar", "-xzf", archive);
    }
    for (const dir of readdirSync(unpacked)) {
      const manifest = join(unpacked, dir, "Cargo.toml");
      const metadata: Metadata = JSON.parse(
        run(root, env, "cargo", "metadata", "--manifest-path", manifest, "--no-deps", "--format-version", "1", "--offline"),
      );
      const pkg = metadata.packages[0];
      for (const dependency of pkg.dependencies) {
        if (dependency.kind !== "dev" && dependency.path !== undefined) {
          throw new Error(`${pkg.name}: ${dependency.name} resolves through a path, not the registry`);
        }
      }
      if (!pkg.license) {
        throw new Error(`${pkg.name}: the package declares no license`);
      }
      sources.set(pkg.name, join(unpacked, dir));
    }
    for (const name of [...ENGINE, "sid-pake-core"]) {
      if (!sources.has(name)) {
        throw new Error(`${name} is missing from the packaged closure`);
      }
    }
    // The proto sources the messages are generated from travel with them.
    const protos = run(unpacked, env, "find", sources.get("sid-proto")!, "-name", "*.proto");
    if (!protos.includes("/proto/sid/v1/")) {
      throw new Error("sid-proto carries no proto sources");
    }

    // A fresh consumer resolving every SID crate to the unpacked archives.
    const consumer = join(work, "consumer");
    cpSync(join(root, "ci/engine-consumer"), consumer, { recursive: true });
    const manifest = join(consumer, "Cargo.toml");
    const patches = [...sources].map(([name, dir]) => `${name} = { path = ${JSON.stringify(dir)} }`);
    // A host takes sqlx from its main branch as the engine workspace does.
    for (const name of SQLX) {
      patches.push(`${name} = { git = ${JSON.stringify(SQLX_GIT)}, branch = "main" }`);
    }
    writeFileSync(manifest, `${readFileSync(manifest, "utf8")}\n[patch.crates-io]\n${patches.join("\n")}\n`);

    // Each host store the engine supports, as its own build: a host
    // selecting CoordiNode receives no SQL driver at all.
    const stores = [
      { name: "sqlite", forbidden: FORBIDDEN },
      { name: "coordinode", forbidden: [...FORBIDDEN, "sqlx", "sqlx-core", "sqlx-sqlite", "libsqlite3-sys"] },
    ];
    for (const store of stores) {
      const features = ["--no-default-features", "--features", store.name];
      const graph = run(consumer, env, "cargo", "tree", ...features, "-e", "normal,build", "--prefix", "none", "-f", "{p}");
      const held = new Set(graph.split("\n").filter((line) => line.trim()).map((line) => line.split(" ")[0]));
      const unexpected = store.forbidden.filter((name) => held.has(name));
      const privateCrates = [...held].filter((name) => name.startsWith("sid-ee") || name.startsWith("sid-saas"));
      if (unexpected.length > 0 || privateCrates.length > 0) {
        throw new Error(`the ${store.name} engine closure holds ${[...unexpected, ...privateCrates].join(", ")}`);
      }
      console.log(`verified: the ${store.name} engine closure of ${held.size} packages holds no service, unselected driver, native provider or private crate`);
      // Each SID package the build selects is the unpacked archive at its
      // packaged version: a patch Cargo did not apply would show here.
      const resolved: Metadata & { packages: { manifest_path: string }[] } = JSON.parse(
        run(consumer, env, "cargo", "metadata", ...features, "--format-version", "1"),
      );
      for (const pkg of resolved.packages) {
        const owned = pkg.name === "structured-id" || pkg.name.startsWith("sid-");
        const published = pkg.name === "sid-ids" || pkg.name === "sid-ids-proto";
        if (!owned || published) {
          continue;
        }
        const archive = sources.get(pkg.name);
        if (archive === undefined || !pkg.manifest_path.startsWith(`${archive}/`)) {
          throw new Error(`${pkg.name} ${pkg.version} resolved from ${pkg.manifest_path}, not its archive`);
        }
      }
      console.log(`verified: every SID package of the ${store.name} build is its unpacked archive`);
      execFileSync("cargo", ["run", ...features, "--", store.name], { cwd: consumer, env, stdio: "inherit" });
    }
  } catch (error) {
    console.log(`failed package evidence preserved in ${work}`);
    throw error;
  }
  rmSync(work, { recursive: true, force: true });
}

main();
