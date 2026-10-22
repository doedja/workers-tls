import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { createServer, type Server, type TLSSocket } from "node:tls";
import { fileURLToPath } from "node:url";
import { connectTls, initTls, openTunnel, pemToDer, socketStream, type ByteStream } from "../ts/index.js";
import { nodeConnect } from "./node-socket.js";
import { nodeTlsServer, type NodeTlsServer } from "./node-tls-server.js";
import { hangUpProxy, httpProxy, silentProxy, socksProxy, type TestProxy } from "./proxies.js";

// Test-only CA and server key, for the name "tls.test" (test/fixtures).
const fixturePath = (name: string) => fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));
const wasm = new WebAssembly.Module(readFileSync(new URL("../workers_tls.wasm", import.meta.url)));
const enc = new TextEncoder();
const dec = new TextDecoder();

/** TLS 1.2 only, one HTTP/1.1 JSON answer per connection, in Node (Bun's node:tls before 1.4 ignores maxVersion). */
let http12: NodeTlsServer;
/** TLS 1.3, echoes upper-cased. */
let echo13 = 0;
const servers: Server[] = [];
const proxies: TestProxy[] = [];
const track = (p: TestProxy) => (proxies.push(p), p);

beforeAll(async () => {
  initTls(wasm, pemToDer(readFileSync(fixturePath("ca.pem"), "utf8")));
  http12 = await nodeTlsServer(fixturePath("server.key"), fixturePath("server.pem"), "http", "TLSv1.2");
  const server = createServer({ key: readFileSync(fixturePath("server.key")), cert: readFileSync(fixturePath("server.pem")), minVersion: "TLSv1.3" }, (s: TLSSocket) =>
    s.on("data", (d: Buffer) => s.write(d.toString().toUpperCase())),
  );
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  echo13 = (server.address() as { port: number }).port;
});

afterAll(() => {
  http12.close();
  for (const s of servers) s.close();
  for (const p of proxies) p.close();
});

/** One GET over TLS to tls.test on `stream`: the version and the JSON answer. */
async function get(stream: ByteStream, path = "/x") {
  const tls = await connectTls("tls.test", stream);
  await tls.write(enc.encode(`GET ${path} HTTP/1.1\r\nHost: tls.test\r\nConnection: close\r\n\r\n`));
  let text = "";
  for (let d; (d = await tls.read()); ) text += dec.decode(d);
  return { version: tls.version, body: JSON.parse(text.slice(text.indexOf("\r\n\r\n") + 4)) as unknown };
}

async function readAll(tls: { read(): Promise<Uint8Array | undefined> }, want: number): Promise<string> {
  let text = "";
  while (text.length < want) {
    const d = await tls.read();
    if (!d) break;
    text += dec.decode(d);
  }
  return text;
}

describe("socketStream", () => {
  test("TLS straight to the server, with SNI", async () => {
    const before = http12.conns.length;
    const stream = socketStream(nodeConnect({ hostname: "127.0.0.1", port: http12.port }));
    expect(await get(stream)).toEqual({ version: "TLS1.2", body: { success: true, path: "/x" } });
    await stream.close();
    await http12.seen(before + 1);
    expect(http12.conns.at(-1)).toEqual({ protocol: "TLSv1.2", reused: false, sni: "tls.test" });
  });
});

describe("HTTP CONNECT", () => {
  test("credentials from the URL, then TLS 1.2 through the tunnel", async () => {
    const proxy = track(await httpProxy(http12.port, { auth: `Basic ${btoa("user:p@ss w")}` }));
    const before = http12.conns.length;
    const tunnel = await openTunnel(nodeConnect, `http://user:p%40ss%20w@127.0.0.1:${proxy.port}`, "tls.test", 443);
    expect(await get(tunnel, "/via-connect")).toEqual({ version: "TLS1.2", body: { success: true, path: "/via-connect" } });
    await tunnel.close();
    expect(proxy.seen).toEqual([{ target: "tls.test:443", auth: `Basic ${btoa("user:p@ss w")}` }]);
    await http12.seen(before + 1);
    expect(http12.conns.at(-1)?.sni).toBe("tls.test");
  });

  test("a refusal names the status and not the credentials, and closes the socket", async () => {
    const proxy = track(await httpProxy(http12.port, { auth: "Basic other" }));
    const err = await openTunnel(nodeConnect, `http://user:hunter2@127.0.0.1:${proxy.port}`, "tls.test", 443).catch((e: Error) => e);
    expect((err as Error).message).toBe("proxy answered CONNECT with 407");
    expect(String(err)).not.toContain("hunter2");
    while (proxy.open()) await Bun.sleep(5);
  });

  test("bytes the proxy sends with its answer are the tunnel's first", async () => {
    const proxy = track(await httpProxy(echo13, { greeting: "early" }));
    const tunnel = await openTunnel(nodeConnect, { protocol: "http", hostname: "127.0.0.1", port: proxy.port }, "tls.test", 443);
    expect(dec.decode(await tunnel.read())).toBe("early");
    await tunnel.close();
  });

  test("an IPv6 target goes in brackets", async () => {
    const proxy = track(await httpProxy(echo13));
    const tunnel = await openTunnel(nodeConnect, `http://127.0.0.1:${proxy.port}`, "2001:db8::1", 8443);
    await tunnel.close();
    expect(proxy.seen).toEqual([{ target: "[2001:db8::1]:8443" }]);
  });
});

describe("SOCKS5", () => {
  test("no authentication, a name for the proxy to resolve, and a 300 KB round trip over TLS 1.3", async () => {
    const proxy = track(await socksProxy(echo13));
    const tunnel = await openTunnel(nodeConnect, `socks5://127.0.0.1:${proxy.port}`, "tls.test", 443);
    const tls = await connectTls("tls.test", tunnel);
    expect(tls.version).toBe("TLS1.3");
    const body = "a".repeat(300_000);
    await tls.write(enc.encode(body));
    expect(await readAll(tls, body.length)).toBe(body.toUpperCase());
    await tls.close();
    await tunnel.close();
    expect(proxy.seen).toEqual([{ target: "tls.test:443", type: 3 }]);
  });

  test("username and password, then TLS 1.2", async () => {
    const proxy = track(await socksProxy(http12.port, { user: "user", pass: "pässword" }));
    const tunnel = await openTunnel(nodeConnect, `socks5h://user:p%C3%A4ssword@127.0.0.1:${proxy.port}`, "tls.test", 443);
    expect(await get(tunnel, "/via-socks")).toEqual({ version: "TLS1.2", body: { success: true, path: "/via-socks" } });
    await tunnel.close();
    expect(proxy.seen).toEqual([{ target: "tls.test:443", type: 3, auth: "user:pässword" }]);
  });

  test("a wrong password and a refused CONNECT are named", async () => {
    const strict = track(await socksProxy(echo13, { user: "user", pass: "right" }));
    await expect(openTunnel(nodeConnect, `socks5://user:wrong@127.0.0.1:${strict.port}`, "tls.test", 443)).rejects.toThrow(
      "proxy refused the username and password",
    );
    // No credentials offered where the proxy needs them.
    await expect(openTunnel(nodeConnect, `socks5://127.0.0.1:${strict.port}`, "tls.test", 443)).rejects.toThrow(
      "proxy accepts none of the offered authentication methods",
    );
    const refusing = track(await socksProxy(echo13, { reply: 5 }));
    await expect(openTunnel(nodeConnect, `socks5://127.0.0.1:${refusing.port}`, "tls.test", 443)).rejects.toThrow(
      "proxy could not connect: connection refused (5)",
    );
  });

  test("IPv4 and IPv6 targets go as addresses", async () => {
    const proxy = track(await socksProxy(echo13));
    for (const host of ["192.0.2.7", "[2001:db8::1]", "::ffff:192.0.2.7"]) {
      const tunnel = await openTunnel(nodeConnect, `socks5://127.0.0.1:${proxy.port}`, host, 443);
      await tunnel.close();
    }
    expect(proxy.seen).toEqual([
      { target: "192.0.2.7:443", type: 1 },
      { target: "[2001:db8:0:0:0:0:0:1]:443", type: 4 },
      { target: "[0:0:0:0:0:ffff:c000:207]:443", type: 4 },
    ]);
  });
});

describe("openTunnel failures", () => {
  test("an abort while the proxy is silent rejects with the signal's reason and closes the socket", async () => {
    const proxy = track(await silentProxy());
    const err = await openTunnel(nodeConnect, `http://127.0.0.1:${proxy.port}`, "tls.test", 443, { signal: AbortSignal.timeout(100) }).catch(
      (e: Error) => e,
    );
    expect((err as Error).name).toBe("TimeoutError");
    while (proxy.open()) await Bun.sleep(5);
  });

  test("a proxy that hangs up before answering", async () => {
    const proxy = track(await hangUpProxy());
    for (const scheme of ["http", "socks5"]) {
      await expect(openTunnel(nodeConnect, `${scheme}://127.0.0.1:${proxy.port}`, "tls.test", 443)).rejects.toThrow("proxy closed the connection");
    }
  });

  test("bad URLs and targets are refused before connecting, without echoing the URL", async () => {
    const never = () => {
      throw new Error("connected");
    };
    const refused = (proxy: string, host = "tls.test", port = 443) => openTunnel(never, proxy, host, port).catch((e: Error) => e.message);
    expect(await refused("http://user:hunter2@")).toBe("proxy URL is not valid");
    expect(await refused("https://proxy.test:443")).toBe("proxy scheme https: is not supported (http:, socks5:)");
    expect(await refused("http://proxy.test", "tls.test\r\nX-Injected: 1")).toBe("target host is not a valid name or address");
    expect(await refused("http://proxy.test", "1::2::3")).toBe("target host is not a valid IPv6 address");
    expect(await refused("http://proxy.test", "tls.test", 0)).toBe("target port 0 is not valid");
  });
});
