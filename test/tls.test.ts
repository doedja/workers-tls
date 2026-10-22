import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { connect as netConnect, type Socket } from "node:net";
import { createServer, type Server, type TLSSocket } from "node:tls";
import { fileURLToPath } from "node:url";
import { connectTls, initTls, type ByteStream } from "../ts/index.js";
import { nodeTlsServer, type NodeTlsServer } from "./node-tls-server.js";

// Test-only CA and server key, for the name "tls.test" (test/fixtures).
const fixturePath = (name: string) => fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));
const fixture = (name: string) => readFileSync(fixturePath(name));
const pemDer = (pem: string) => Uint8Array.from(Buffer.from(pem.replace(/-----[^-]+-----|\s+/g, ""), "base64"));
const caDer = pemDer(fixture("ca.pem").toString());
const wasm = new WebAssembly.Module(readFileSync(new URL("../workers_tls.wasm", import.meta.url)));

/** A TCP socket as the ByteStream a tunnel would hand over. */
function byteStream(sock: Socket): ByteStream {
  const queue: Uint8Array[] = [];
  let ended = false;
  let wake: (() => void) | null = null;
  sock.on("data", (d: Buffer) => {
    queue.push(new Uint8Array(d));
    wake?.();
  });
  sock.on("end", () => {
    ended = true;
    wake?.();
  });
  sock.on("error", () => {
    ended = true;
    wake?.();
  });
  return {
    async read() {
      while (!queue.length && !ended) await new Promise<void>((r) => (wake = r));
      wake = null;
      return queue.shift();
    },
    write: (data) => new Promise<void>((resolve, reject) => sock.write(data, (err) => (err ? reject(err) : resolve()))),
  };
}

const servers: Server[] = [];
const nodeServers: NodeTlsServer[] = [];
/** TLS 1.2-only servers run in Node: Bun's node:tls before 1.4 ignores maxVersion. */
async function nodeServer(mode: "echo" | "ok", maxVersion: string): Promise<NodeTlsServer> {
  const server = await nodeTlsServer(fixturePath("server.key"), fixturePath("server.pem"), mode, maxVersion);
  nodeServers.push(server);
  return server;
}
async function listen(opts: Parameters<typeof createServer>[0], onConn: (s: TLSSocket) => void): Promise<number> {
  const server = createServer({ key: fixture("server.key"), cert: fixture("server.pem"), ...opts }, onConn);
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return (server.address() as { port: number }).port;
}

/** Echo, upper-cased. */
const echo = (s: TLSSocket) => s.on("data", (d: Buffer) => s.write(d.toString().toUpperCase()));

async function open(port: number, name = "tls.test") {
  const sock = netConnect(port, "127.0.0.1");
  await new Promise<void>((r) => sock.once("connect", () => r()));
  return { sock, tls: await connectTls(name, byteStream(sock)) };
}

async function readAll(tls: { read(): Promise<Uint8Array | undefined> }, want: number): Promise<string> {
  let text = "";
  while (text.length < want) {
    const d = await tls.read();
    if (!d) break;
    text += new TextDecoder().decode(d);
  }
  return text;
}

let tls12 = 0;
let tls13 = 0;

beforeAll(async () => {
  initTls(wasm, [caDer]);
  tls12 = (await nodeServer("echo", "TLSv1.2")).port;
  tls13 = await listen({ minVersion: "TLSv1.3" }, echo);
});

afterAll(() => {
  for (const s of servers) s.close();
  for (const s of nodeServers) s.close();
});

describe("workers-tls", () => {
  test("a TLS 1.2-only server: handshake, request, answer", async () => {
    const { sock, tls } = await open(tls12);
    expect(tls.version).toBe("TLS1.2");
    await tls.write(new TextEncoder().encode("hello"));
    expect(await readAll(tls, 5)).toBe("HELLO");
    await tls.close();
    sock.destroy();
  });

  test("a TLS 1.3 server, and a body far larger than one record", async () => {
    const { sock, tls } = await open(tls13);
    expect(tls.version).toBe("TLS1.3");
    const body = "a".repeat(300_000);
    await tls.write(new TextEncoder().encode(body));
    expect(await readAll(tls, body.length)).toBe(body.toUpperCase());
    await tls.close();
    sock.destroy();
  });

  test("a certificate for another name is refused", async () => {
    const sock = netConnect(tls12, "127.0.0.1");
    await new Promise<void>((r) => sock.once("connect", () => r()));
    await expect(connectTls("other.test", byteStream(sock))).rejects.toThrow(/certificate/i);
    sock.destroy();
  });

  test("a certificate from a root that is not trusted is refused", async () => {
    initTls(wasm, []);
    try {
      const sock = netConnect(tls13, "127.0.0.1");
      await new Promise<void>((r) => sock.once("connect", () => r()));
      await expect(connectTls("tls.test", byteStream(sock))).rejects.toThrow(/certificate/i);
      sock.destroy();
    } finally {
      initTls(wasm, [caDer]);
    }
  });

  test("the peer closing ends reads; many connections share one instance", async () => {
    const port = await listen({}, (s) => s.end("bye"));
    for (let i = 0; i < 20; i++) {
      const { sock, tls } = await open(port);
      expect(await readAll(tls, 3)).toBe("bye");
      expect(await tls.read()).toBeUndefined();
      sock.destroy();
    }
  });

  test("a write cut by close never reaches the connection opened after it", async () => {
    const sock = netConnect(tls13, "127.0.0.1");
    await new Promise<void>((r) => sock.once("connect", () => r()));
    const raw = byteStream(sock);
    const held: Array<() => void> = [];
    let holding = false;
    // After the handshake, the stream's writes wait until released.
    const slow: ByteStream = {
      read: raw.read,
      write: (d) => (holding ? new Promise<void>((r) => held.push(() => void raw.write(d).then(r))) : raw.write(d)),
    };
    const a = await connectTls("tls.test", slow);
    holding = true;
    const writing = a.write(new Uint8Array(200_000).fill(0x61));
    const closing = a.close();
    const { sock: sockB, tls: b } = await open(tls13);
    holding = false;
    for (const release of held.splice(0)) release();
    await closing;
    await expect(writing).rejects.toThrow("connection closed");
    await b.write(new TextEncoder().encode("still mine"));
    expect(await readAll(b, 10)).toBe("STILL MINE");
    await b.close();
    sockB.destroy();
    sock.destroy();
  });

  test("closeNotify tells a clean end from a stream that just stopped", async () => {
    const clean = await listen({}, (s) => s.end("bye"));
    const a = await open(clean);
    expect(await readAll(a.tls, 3)).toBe("bye");
    expect(await a.tls.read()).toBeUndefined();
    expect(a.tls.closeNotify).toBe(true);
    a.sock.destroy();
    // The stream ends under a connection whose peer sent no close_notify.
    const open13 = await listen({}, (s) => s.write("partial"));
    const sock = netConnect(open13, "127.0.0.1");
    await new Promise<void>((r) => sock.once("connect", () => r()));
    const raw = byteStream(sock);
    let cut = false;
    const b = await connectTls("tls.test", { read: () => (cut ? Promise.resolve(undefined) : raw.read()), write: raw.write });
    expect(await readAll(b, 7)).toBe("partial");
    cut = true;
    expect(await b.read()).toBeUndefined();
    expect(b.closeNotify).toBe(false);
    sock.destroy();
  });

  test("no session is resumed: connections through different tunnels cannot be linked", async () => {
    for (const maxVersion of ["TLSv1.2", "TLSv1.3"]) {
      const server = await nodeServer("ok", maxVersion);
      for (let i = 0; i < 3; i++) {
        const { sock, tls } = await open(server.port);
        expect(await readAll(tls, 2)).toBe("ok");
        sock.destroy();
      }
      await server.seen(3);
      expect(server.conns).toEqual(Array(3).fill({ protocol: maxVersion, reused: false, sni: "tls.test" }));
    }
  });

  test("a stream that ends during the handshake rejects", async () => {
    const port = await listen({}, () => undefined);
    const raw = netConnect(port, "127.0.0.1");
    await new Promise<void>((r) => raw.once("connect", () => r()));
    const stream = byteStream(raw);
    const p = connectTls("tls.test", { read: async () => undefined, write: stream.write });
    await expect(p).rejects.toThrow("closed during handshake");
    raw.destroy();
  });
});
