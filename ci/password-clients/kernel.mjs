// Test-process IPC only. Production messages are encoded by the gRPC client
// in the Rust test; this adapter calls only the installed package's public API.
import { createInterface } from "node:readline";
import { loadZkppClient } from "@structured-id/opaque";
import { commands } from "./commands.mjs";

const client = await loadZkppClient({ kernel: "ts" });
const call = commands(client);
const encode = (_, v) => v instanceof Uint8Array ? Array.from(v) : v;
for await (const line of createInterface({ input: process.stdin })) {
  try {
    const result = await call(JSON.parse(line));
    console.log(JSON.stringify({ ok: true, result }, encode));
  } catch (error) {
    // Do not print crypto states, proofs or requests even when a test fails.
    console.log(JSON.stringify({ ok: false, error: String(error) }));
  }
}
