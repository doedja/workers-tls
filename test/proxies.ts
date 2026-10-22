import { connect as netConnect, createServer, type Server, type Socket } from "node:net";

/** A tunnel a test proxy was asked for. */
export interface Seen {
  /** `host:port` as the client sent it (`[v6]:port` for IPv6). */
  target: string;
  /** HTTP: the Proxy-Authorization value. SOCKS5: `user:pass`. */
  auth?: string;
  /** SOCKS5 address type: 1 IPv4, 3 name, 4 IPv6. */
  type?: number;
}

export interface TestProxy {
  port: number;
  seen: Seen[];
  /** Client connections still open. */
  open(): number;
  close(): void;
}

/** A socket read to exact lengths, until the handler hands what is left to the tunnel. */
function reader(sock: Socket) {
  let buf = Buffer.alloc(0);
  let wake: (() => void) | null = null;
  let ended = false;
  const onData = (d: Buffer) => {
    buf = Buffer.concat([buf, d]);
    wake?.();
  };
  sock.on("data", onData);
  sock.on("close", () => {
    ended = true;
    wake?.();
  });
  const more = async () => {
    if (ended) throw new Error("client closed");
    await new Promise<void>((r) => (wake = r));
  };
  return {
    async take(n: number): Promise<Buffer> {
      while (buf.length < n) await more();
      const out = buf.subarray(0, n);
      buf = buf.subarray(n);
      return out;
    },
    async until(marker: string): Promise<Buffer> {
      let at: number;
      while ((at = buf.indexOf(marker)) < 0) await more();
      return this.take(at + marker.length);
    },
    rest(): Buffer {
      sock.off("data", onData);
      return buf;
    },
  };
}

type Handler = (client: Socket, r: ReturnType<typeof reader>, seen: Seen[]) => Promise<void>;

async function serve(handler: Handler): Promise<TestProxy> {
  const seen: Seen[] = [];
  const clients = new Set<Socket>();
  const server: Server = createServer((client) => {
    clients.add(client);
    client.on("close", () => clients.delete(client));
    client.on("error", () => undefined);
    handler(client, reader(client), seen).catch(() => client.destroy());
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return {
    port: (server.address() as { port: number }).port,
    seen,
    open: () => clients.size,
    close: () => {
      for (const c of clients) c.destroy();
      server.close();
    },
  };
}

/** Answer the client with `reply`, then join it to the local `upstream` port both ways. */
function join(client: Socket, rest: Buffer, upstream: number, reply: Buffer): Promise<void> {
  return new Promise((resolve) => {
    const up = netConnect(upstream, "127.0.0.1", () => {
      client.write(reply);
      if (rest.length) up.write(rest);
      client.pipe(up).pipe(client);
      resolve();
    });
    up.on("error", () => client.destroy());
    client.on("close", () => up.destroy());
  });
}

/**
 * An HTTP CONNECT proxy that sends every tunnel to `upstream`, whatever the
 * target. With `auth`, any other Proxy-Authorization gets a 407. `greeting`
 * rides in the same write as the 200.
 */
export function httpProxy(upstream: number, opts: { auth?: string; greeting?: string } = {}): Promise<TestProxy> {
  return serve(async (client, r, seen) => {
    const [line = "", ...headers] = (await r.until("\r\n\r\n")).toString().split("\r\n");
    const auth = headers.find((h) => /^proxy-authorization:/i.test(h))?.replace(/^[^:]+:\s*/, "");
    seen.push({ target: line.split(" ")[1] ?? "", ...(auth ? { auth } : {}) });
    if (opts.auth !== undefined && auth !== opts.auth) {
      client.end("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n");
      return;
    }
    await join(client, r.rest(), upstream, Buffer.from(`HTTP/1.1 200 Connection established\r\n\r\n${opts.greeting ?? ""}`));
  });
}

/**
 * A SOCKS5 proxy (RFC 1928, RFC 1929 when `user` is set) that sends every
 * tunnel to `upstream`. A nonzero `reply` refuses the CONNECT with that code.
 */
export function socksProxy(upstream: number, opts: { user?: string; pass?: string; reply?: number } = {}): Promise<TestProxy> {
  return serve(async (client, r, seen) => {
    const [version, n = 0] = await r.take(2);
    const methods = [...(await r.take(n))];
    const want = opts.user !== undefined ? 2 : 0;
    if (version !== 5 || !methods.includes(want)) return void client.end(Buffer.from([5, 0xff]));
    client.write(Buffer.from([5, want]));
    let auth: string | undefined;
    if (want === 2) {
      const [, ulen = 0] = await r.take(2);
      const user = (await r.take(ulen)).toString();
      const [plen = 0] = await r.take(1);
      const pass = (await r.take(plen)).toString();
      auth = `${user}:${pass}`;
      if (user !== opts.user || pass !== opts.pass) {
        seen.push({ target: "", auth });
        return void client.end(Buffer.from([1, 1]));
      }
      client.write(Buffer.from([1, 0]));
    }
    const [, , , type = 0] = await r.take(4);
    let host: string;
    if (type === 1) host = [...(await r.take(4))].join(".");
    else if (type === 3) host = (await r.take((await r.take(1))[0] ?? 0)).toString();
    else {
      const b = await r.take(16);
      host = `[${Array.from({ length: 8 }, (_, i) => b.readUInt16BE(i * 2).toString(16)).join(":")}]`;
    }
    const port = (await r.take(2)).readUInt16BE(0);
    seen.push({ target: `${host}:${port}`, type, ...(auth ? { auth } : {}) });
    const bound = Buffer.from([5, opts.reply ?? 0, 0, 1, 127, 0, 0, 1, 0x1f, 0x90]);
    if (opts.reply) return void client.end(bound);
    await join(client, r.rest(), upstream, bound);
  });
}

/** Accepts connections and never answers. */
export function silentProxy(): Promise<TestProxy> {
  return serve(() => new Promise<void>(() => undefined));
}

/** Hangs up on every connection at once. */
export function hangUpProxy(): Promise<TestProxy> {
  return serve(async (client) => void client.end());
}
