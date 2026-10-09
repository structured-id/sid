import { loadZkppClient } from "@structured-id/opaque";
import { commands } from "./commands.mjs";

const client = await loadZkppClient({ kernel: "ts" });
globalThis.passwordClient = { kernel: client.kernel, call: commands(client) };
