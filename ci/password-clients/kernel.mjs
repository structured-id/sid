// Test-process IPC only. Production messages are encoded by the gRPC client
// in the Rust test; this adapter calls only the installed package's public API.
import { createInterface } from "node:readline";
import { loadZkppClient } from "@structured-id/opaque";

const client = await loadZkppClient({ kernel: "ts" });
const bytes = (v) => Uint8Array.from(v);
const context = (v) => ({
  ...v,
  operationId: bytes(v.operationId),
  ownerDomain: bytes(v.ownerDomain),
  domains: v.domains.map((d) => ({
    comparisonDomain: bytes(d.comparisonDomain),
    evaluatorPublicKey: bytes(d.evaluatorPublicKey),
  })),
});
const encode = (_, v) => v instanceof Uint8Array ? Array.from(v) : v;
let start;
let history;
let login;
for await (const line of createInterface({ input: process.stdin })) {
  try {
    const v = JSON.parse(line);
    let result;
    switch (v.method) {
      case "start":
        start = await client.registrationStart(v.password);
        result = start.request;
        break;
      case "history":
        history = await client.historyRequest(v.password, bytes(v.ownerDomain));
        if (history === null) throw new Error("test password must be provable");
        result = history.blinded;
        break;
      case "prove":
        result = await client.prove(v.password, start, {
          context: context(v.context),
          history: {
            request: history,
            evaluations: v.evaluations.map((e) => ({
              evaluatedElement: bytes(e.evaluatedElement),
              proof: { challenge: bytes(e.proof.challenge), response: bytes(e.proof.response) },
            })),
          },
        });
        if (result === null) throw new Error("test password must be provable");
        break;
      case "record":
        result = await client.registrationFinish(v.password, start.state, bytes(v.response));
        break;
      case "loginStart":
        login = await client.loginStart(v.password);
        result = login.request;
        break;
      case "loginFinish":
        result = await client.loginFinish(v.password, login.state, bytes(v.response));
        break;
      default:
        throw new Error("unknown test command");
    }
    console.log(JSON.stringify({ ok: true, result }, encode));
  } catch (error) {
    // Do not print crypto states, proofs or requests even when a test fails.
    console.log(JSON.stringify({ ok: false, error: String(error) }));
  }
}
