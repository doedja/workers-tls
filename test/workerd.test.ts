import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";
import { nodeTlsServer, type NodeTlsServer } from "./node-tls-server.js";
import { httpProxy, socksProxy, type TestProxy } from "./proxies.js";

// The built package (dist/, workers_tls.wasm) inside workerd, as a Worker runs
// it: wrangler bundles the .wasm as a compiled module and `connect` is the
// real cloudflare:sockets. `wrangler dev` takes a few seconds to start.
setDefaultTimeout(60_000);

const root = fileURLToPath(new URL("..", import.meta.url));
const fixturePath = (name: string) => fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));

let wrangler: ChildProcess;
let base = "";
let log = "";
const servers: NodeTlsServer[] = [];
const proxies: TestProxy[] = [];
let tls12: NodeTlsServer;
let tls13: NodeTlsServer;
let pipe13: NodeTlsServer;

async function freePort(): Promise<number> {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  const { port } = s.address() as { port: number };
  await new Promise<void>((r) => s.close(() => r()));
  return port;
}

beforeAll(async () => {
  tls12 = await nodeTlsServer(fixturePath("server.key"), fixturePath("server.pem"), "http", "TLSv1.2");
  tls13 = await nodeTlsServer(fixturePath("server.key"), fixturePath("server.pem"), "http", "TLSv1.3");
  pipe13 = await nodeTlsServer(fixturePath("server.key"), fixturePath("server.pem"), "pipe", "TLSv1.3");
  servers.push(tls12, tls13, pipe13);
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  wrangler = spawn(
    "bunx",
    ["wrangler", "dev", "--config", "test/workerd/wrangler.toml", "--ip", "127.0.0.1", "--port", String(port), "--inspector-port", "0", "--show-interactive-dev-session=false"],
    { cwd: root, detached: true, env: { ...process.env, WRANGLER_SEND_METRICS: "false", CI: "1" }, stdio: ["ignore", "pipe", "pipe"] },
  );
  wrangler.stdout?.on("data", (d: Buffer) => (log += d.toString()));
  wrangler.stderr?.on("data", (d: Buffer) => (log += d.toString()));
  for (const until = Date.now() + 50_000; ; ) {
    if (wrangler.exitCode !== null) throw new Error(`wrangler dev exited:\n${log}`);
    const up = await fetch(`${base}/ready?port=1`).then(
      () => true,
      () => false,
    );
    if (up) break;
    if (Date.now() > until) throw new Error(`wrangler dev did not start:\n${log}`);
    await Bun.sleep(250);
  }
});

afterAll(() => {
  // The process group: wrangler and the workerd it started.
  if (wrangler?.pid) {
    try {
      process.kill(-wrangler.pid, "SIGTERM");
    } catch {
      // Already gone.
    }
  }
  for (const s of servers) s.close();
  for (const p of proxies) p.close();
});

async function viaWorker(path: string, port: number, proxy?: string, extra: Record<string, string> = {}) {
  const q = new URLSearchParams({ port: String(port), ...(proxy ? { proxy } : {}), ...extra });
  const res = await fetch(`${base}${path}?${q}`);
  return (await res.json()) as unknown;
}

describe("in workerd", () => {
  test("straight to the server over TLS 1.3 and TLS 1.2, with SNI", async () => {
    expect(await viaWorker("/direct13", tls13.port)).toEqual({ version: "TLS1.3", body: { success: true, path: "/direct13" } });
    expect(await viaWorker("/direct12", tls12.port)).toEqual({ version: "TLS1.2", body: { success: true, path: "/direct12" } });
    await tls12.seen(1);
    await tls13.seen(1);
    expect([tls13.conns[0]?.sni, tls12.conns[0]?.sni]).toEqual(["tls.test", "tls.test"]);
  });

  test("through an HTTP CONNECT proxy with credentials", async () => {
    const proxy = await httpProxy(tls12.port, { auth: `Basic ${btoa("user:pass")}` });
    proxies.push(proxy);
    expect(await viaWorker("/connect", 443, `http://user:pass@127.0.0.1:${proxy.port}`)).toEqual({
      version: "TLS1.2",
      body: { success: true, path: "/connect" },
    });
    expect(proxy.seen).toEqual([{ target: "tls.test:443", auth: `Basic ${btoa("user:pass")}` }]);
    await tls12.seen(2);
    expect(tls12.conns.at(-1)?.sni).toBe("tls.test");
  });

  test("through a SOCKS5 proxy with credentials", async () => {
    const proxy = await socksProxy(tls13.port, { user: "user", pass: "pass" });
    proxies.push(proxy);
    expect(await viaWorker("/socks", 443, `socks5://user:pass@127.0.0.1:${proxy.port}`)).toEqual({
      version: "TLS1.3",
      body: { success: true, path: "/socks" },
    });
    expect(proxy.seen).toEqual([{ target: "tls.test:443", type: 3, auth: "user:pass" }]);
    await tls13.seen(2);
    expect(tls13.conns.at(-1)?.sni).toBe("tls.test");
  });

  test("a large write and a read at once, against an echo server with backpressure", async () => {
    expect(await viaWorker("/pipe", pipe13.port, undefined, { mb: "16" })).toEqual({ got: 16 * 1024 * 1024 });
  });

  test("a certificate for another name is refused", async () => {
    const res = await fetch(`${base}/x?${new URLSearchParams({ port: String(tls13.port), name: "other.test" })}`);
    expect(res.status).toBe(500);
    expect(((await res.json()) as { error: string }).error).toMatch(/invalid peer certificate/);
  });
});
