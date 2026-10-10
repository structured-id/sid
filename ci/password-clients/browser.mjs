// Genuine browser cryptography with the same test IPC as kernel.mjs. This is
// not a browser transport or UI test: Rust drives the actual gRPC endpoint.
import { createInterface } from "node:readline";
import { createServer } from "node:http";
import { once } from "node:events";
import { build } from "esbuild";
import { chromium } from "playwright";

const bundle = await build({
  entryPoints: [new URL("browser-client.mjs", import.meta.url).pathname],
  bundle: true, format: "esm", platform: "browser", write: false,
  logLevel: "silent",
});
const server = createServer((request, response) => {
  response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  response.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  if (request.url === "/") {
    response.setHeader("Content-Type", "text/html");
    response.end('<!doctype html><script type="module" src="/client.mjs"></script>');
  } else if (request.url === "/client.mjs") {
    response.setHeader("Content-Type", "text/javascript");
    response.end(bundle.outputFiles[0].contents);
  } else {
    response.writeHead(404).end();
  }
});
server.listen(0, "127.0.0.1");
await once(server, "listening");
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  await page.waitForFunction(() => globalThis.passwordClient !== undefined);
  const kernel = await page.evaluate(() => globalThis.passwordClient.kernel);
  if (kernel !== "ts") throw new Error("browser must exercise the requested TS kernel");
  for await (const line of createInterface({ input: process.stdin })) {
    const result = await page.evaluate(async (command) => {
      try {
        const value = await globalThis.passwordClient.call(command);
        return JSON.stringify({ ok: true, result: value },
          (_, v) => v instanceof Uint8Array ? Array.from(v) : v);
      } catch (error) {
        return JSON.stringify({ ok: false, error: String(error) });
      }
    }, JSON.parse(line));
    console.log(result);
  }
} finally {
  await browser.close();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
