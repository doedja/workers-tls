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
      // Paused until the tunnel's pipe resumes it: a flowing socket with no
      // data listener drops what arrives.
      sock.off("data", onData);
      sock.pause();
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

/** Writes to the client: whole, or with `slow` one byte at a time, so the answer arrives in pieces. */
async function send(client: Socket, data: Buffer, slow?: boolean): Promise<void> {
  if (!slow) return void client.write(data);
  for (const b of data) {
    client.write(Buffer.of(b));
    await new Promise((r) => setTimeout(r, 1));
  }
}

/** Answer the client with `reply`, then join it to the local `upstream` port both ways. */
function join(client: Socket, rest: Buffer, upstream: number, reply: Buffer, slow?: boolean): Promise<void> {
  return new Promise((resolve) => {
    const up = netConnect(upstream, "127.0.0.1", async () => {
      await send(client, reply, slow);
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
 * target. With `auth`, any other Proxy-Authorization gets a 407, and the
 * connection stays open for another try, so only the client closes it.
 * `greeting` rides in the same write as the 200. `slow` sends answers a byte
 * at a time.
 */
export function httpProxy(upstream: number, opts: { auth?: string; greeting?: string; slow?: boolean } = {}): Promise<TestProxy> {
  return serve(async (client, r, seen) => {
    const [line = "", ...headers] = (await r.until("\r\n\r\n")).toString().split("\r\n");
    const auth = headers.find((h) => /^proxy-authorization:/i.test(h))?.replace(/^[^:]+:\s*/, "");
    seen.push({ target: line.split(" ")[1] ?? "", ...(auth ? { auth } : {}) });
    if (opts.auth !== undefined && auth !== opts.auth) {
      return send(client, Buffer.from("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n"), opts.slow);
    }
    await join(client, r.rest(), upstream, Buffer.from(`HTTP/1.1 200 Connection established\r\n\r\n${opts.greeting ?? ""}`), opts.slow);
  });
}

/**
 * A SOCKS5 proxy (RFC 1928, RFC 1929 when `user` is set) that sends every
 * tunnel to `upstream`. A nonzero `reply` refuses the CONNECT with that code.
 * `slow` sends answers a byte at a time; `boundName` answers with a bound
 * address that is a name, which the client has to read past.
 */
export function socksProxy(
  upstream: number,
  opts: { user?: string; pass?: string; reply?: number; slow?: boolean; boundName?: string } = {},
): Promise<TestProxy> {
  return serve(async (client, r, seen) => {
    const [version, n = 0] = await r.take(2);
    const methods = [...(await r.take(n))];
    const want = opts.user !== undefined ? 2 : 0;
    if (version !== 5 || !methods.includes(want)) return void client.end(Buffer.from([5, 0xff]));
    await send(client, Buffer.from([5, want]), opts.slow);
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
      await send(client, Buffer.from([1, 0]), opts.slow);
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
    const name = opts.boundName === undefined ? null : Buffer.from(opts.boundName);
    const bound = Buffer.concat([
      Buffer.from([5, opts.reply ?? 0, 0]),
      name ? Buffer.concat([Buffer.from([3, name.length]), name]) : Buffer.from([1, 127, 0, 0, 1]),
      Buffer.from([0x1f, 0x90]),
    ]);
    if (opts.reply) return void client.end(bound);
    await join(client, r.rest(), upstream, bound, opts.slow);
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
