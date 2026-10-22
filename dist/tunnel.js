const enc = new TextEncoder();
const dec = new TextDecoder();
/** Largest single write to the socket: some proxies drop a connection on one very large write. */
const WRITE_PIECE = 16 * 1024;
const HEAD_MAX = 16 * 1024;
const CRLFCRLF = enc.encode("\r\n\r\n");
/** A socket as a `Tunnel`, with nothing in between: TLS straight to the host, with SNI. */
export function socketStream(socket) {
    const reader = socket.readable.getReader();
    const writer = socket.writable.getWriter();
    let closed = false;
    return {
        async read() {
            if (closed)
                return undefined;
            try {
                const r = await reader.read();
                return r.done ? undefined : r.value;
            }
            catch (err) {
                if (closed)
                    return undefined;
                throw err;
            }
        },
        async write(data) {
            for (let off = 0; off < data.length; off += WRITE_PIECE)
                await writer.write(data.subarray(off, off + WRITE_PIECE));
        },
        async close() {
            if (closed)
                return;
            closed = true;
            reader.cancel().catch(() => undefined);
            await socket.close().catch(() => undefined);
        },
    };
}
/**
 * A tunnel to `host:port` through `proxy` (a URL such as
 * `http://user:pass@proxy:8080` or `socks5://proxy:1080`, or a `ProxyConfig`),
 * once the proxy has opened it. Errors name the step and never the
 * credentials: `proxy closed the connection`, `proxy answered CONNECT with
 * 407`, `proxy refused the username and password`, `proxy could not connect:
 * host unreachable (4)`.
 */
export async function openTunnel(connect, proxy, host, port, options = {}) {
    const p = checkProxy(typeof proxy === "string" ? parseProxy(proxy) : proxy);
    const target = checkTarget(host, port);
    const { signal } = options;
    signal?.throwIfAborted();
    const stream = socketStream(connect({ hostname: p.hostname, port: p.port }));
    const abort = () => void stream.close();
    signal?.addEventListener("abort", abort, { once: true });
    try {
        const answer = new Answer(stream.read);
        if (p.protocol === "http")
            await httpConnect(stream, answer, p, target, port);
        else
            await socks5Connect(stream, answer, p, target, port);
        return withFirst(stream, answer.rest());
    }
    catch (err) {
        await stream.close();
        signal?.throwIfAborted();
        throw err;
    }
    finally {
        signal?.removeEventListener("abort", abort);
    }
}
/** A proxy URL as a `ProxyConfig`. Errors never repeat the URL, which may hold a password. */
function parseProxy(url) {
    let u;
    try {
        u = new URL(url);
    }
    catch {
        throw new Error("proxy URL is not valid");
    }
    const protocol = u.protocol === "http:" ? "http" : u.protocol === "socks5:" || u.protocol === "socks5h:" ? "socks5" : null;
    if (!protocol)
        throw new Error(`proxy scheme ${u.protocol} is not supported (http:, socks5:)`);
    const config = {
        protocol,
        hostname: u.hostname.replace(/^\[(.*)\]$/, "$1"),
        // http: drops its default port from the URL; socks5: has none, so 1080 as curl.
        port: u.port ? Number(u.port) : protocol === "http" ? 80 : 1080,
    };
    if (u.username || u.password) {
        try {
            config.username = decodeURIComponent(u.username);
            config.password = decodeURIComponent(u.password);
        }
        catch {
            throw new Error("proxy URL is not valid");
        }
    }
    return config;
}
/** A config checked before anything connects. */
function checkProxy(p) {
    if (p.protocol !== "http" && p.protocol !== "socks5")
        throw new Error(`proxy protocol ${String(p.protocol)} is not supported (http, socks5)`);
    if (!p.hostname)
        throw new Error("proxy has no host");
    if (!Number.isInteger(p.port) || p.port < 1 || p.port > 65535)
        throw new Error(`proxy port ${p.port} is not valid`);
    return p;
}
/** The target as it goes on the wire: a name, an IPv4 address or an IPv6 address without brackets. */
function checkTarget(host, port) {
    if (!Number.isInteger(port) || port < 1 || port > 65535)
        throw new Error(`target port ${port} is not valid`);
    const bare = host.replace(/^\[(.*)\]$/, "$1");
    if (/^[0-9a-f:.]*:[0-9a-f:.]*$/i.test(bare)) {
        ipv6Bytes(bare);
        return bare;
    }
    // A dotted number that is not plain IPv4 (`010.0.0.1`, `1.2.3`) is refused:
    // proxies differ on whether such a name is octal, so it could reach different hosts.
    if (!/^[A-Za-z0-9._-]{1,253}$/.test(host) || (/^[0-9.]+$/.test(host) && !ipv4Bytes(host))) {
        throw new Error("target host is not a valid name or address");
    }
    return host;
}
async function httpConnect(stream, answer, p, host, port) {
    const authority = host.includes(":") ? `[${host}]:${port}` : `${host}:${port}`;
    let req = `CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n`;
    if (p.username !== undefined)
        req += `Proxy-Authorization: Basic ${base64(enc.encode(`${p.username}:${p.password ?? ""}`))}\r\n`;
    await stream.write(enc.encode(`${req}\r\n`));
    const status = /^HTTP\/1\.[01] (\d{3})/.exec(dec.decode(await answer.head()))?.[1];
    if (!status)
        throw new Error("proxy answered CONNECT with something other than HTTP");
    if (!status.startsWith("2"))
        throw new Error(`proxy answered CONNECT with ${status}`);
}
const SOCKS_REPLIES = {
    1: "general failure",
    2: "not allowed by the proxy's rules",
    3: "network unreachable",
    4: "host unreachable",
    5: "connection refused",
    6: "TTL expired",
    7: "command not supported",
    8: "address type not supported",
};
/** RFC 1928, with RFC 1929 username and password when the config has them. */
async function socks5Connect(stream, answer, p, host, port) {
    const auth = p.username !== undefined;
    await stream.write(auth ? Uint8Array.of(5, 2, 0, 2) : Uint8Array.of(5, 1, 0));
    const [version, method] = await answer.take(2);
    if (version !== 5)
        throw new Error("proxy is not a SOCKS5 proxy");
    if (method === 2 && auth) {
        const user = enc.encode(p.username);
        const pass = enc.encode(p.password ?? "");
        if (user.length < 1 || user.length > 255 || pass.length > 255)
            throw new Error("SOCKS5 username and password must be 1-255 and 0-255 bytes");
        await stream.write(concat(Uint8Array.of(1, user.length), user, Uint8Array.of(pass.length), pass));
        const [, status] = await answer.take(2);
        if (status !== 0)
            throw new Error("proxy refused the username and password");
    }
    else if (method !== 0) {
        throw new Error("proxy accepts none of the offered authentication methods");
    }
    await stream.write(concat(Uint8Array.of(5, 1, 0), socksAddress(host), Uint8Array.of(port >> 8, port & 255)));
    const [v, reply, , type] = await answer.take(4);
    if (v !== 5)
        throw new Error("proxy sent a malformed SOCKS5 reply");
    if (reply !== 0)
        throw new Error(`proxy could not connect: ${SOCKS_REPLIES[reply] ?? "error"} (${reply})`);
    // The address the proxy bound, which nothing here needs.
    const len = type === 1 ? 4 : type === 4 ? 16 : type === 3 ? (await answer.take(1))[0] : -1;
    if (len < 0)
        throw new Error("proxy sent a malformed SOCKS5 reply");
    await answer.take(len + 2);
}
/** ATYP and address: IPv4 (1), a name for the proxy to resolve (3), IPv6 (4). */
function socksAddress(host) {
    const v4 = ipv4Bytes(host);
    if (v4)
        return concat(Uint8Array.of(1), v4);
    if (host.includes(":"))
        return concat(Uint8Array.of(4), ipv6Bytes(host));
    const name = enc.encode(host);
    if (name.length > 255)
        throw new Error("target host is too long for SOCKS5");
    return concat(Uint8Array.of(3, name.length), name);
}
const IPV4_PART = "(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
/** Plain dotted-decimal IPv4 only: four parts of 0-255, no leading zeros. */
const IPV4 = new RegExp(`^${IPV4_PART}\\.${IPV4_PART}\\.${IPV4_PART}\\.${IPV4_PART}$`);
function ipv4Bytes(s) {
    const parts = IPV4.exec(s)?.slice(1).map(Number);
    return parts ? Uint8Array.from(parts) : null;
}
function ipv6Bytes(s) {
    const bad = () => new Error("target host is not a valid IPv6 address");
    const halves = s.split("::");
    if (halves.length > 2)
        throw bad();
    // An IPv4 tail (`::ffff:192.0.2.7`) only ends the whole address.
    const groups = (part, last) => {
        if (!part)
            return [];
        return part.split(":").flatMap((g, i, all) => {
            const v4 = last && i === all.length - 1 ? ipv4Bytes(g) : null;
            if (v4)
                return [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
            if (!/^[0-9a-f]{1,4}$/i.test(g))
                throw bad();
            return [parseInt(g, 16)];
        });
    };
    const head = groups(halves[0], halves.length === 1);
    const tail = halves.length === 2 ? groups(halves[1], true) : [];
    const fill = 8 - head.length - tail.length;
    if (halves.length === 2 ? fill < 1 : fill !== 0)
        throw bad();
    const out = new Uint8Array(16);
    [...head, ...Array(fill).fill(0), ...tail].forEach((g, i) => {
        out[i * 2] = g >> 8;
        out[i * 2 + 1] = g & 255;
    });
    return out;
}
/** The proxy's answer as it arrives, read to exact lengths; what follows it belongs to the tunnel. */
class Answer {
    read;
    buf = new Uint8Array(0);
    constructor(read) {
        this.read = read;
    }
    async take(n) {
        while (this.buf.length < n)
            await this.more();
        const out = this.buf.subarray(0, n);
        this.buf = this.buf.subarray(n);
        return out;
    }
    /** Up to and including the blank line that ends an HTTP head. */
    async head() {
        for (let from = 0;;) {
            const at = indexOf(this.buf, CRLFCRLF, from);
            if (at >= 0)
                return this.take(at + CRLFCRLF.length);
            if (this.buf.length > HEAD_MAX)
                throw new Error("proxy answer is too long");
            from = Math.max(0, this.buf.length - CRLFCRLF.length + 1);
            await this.more();
        }
    }
    rest() {
        return this.buf;
    }
    async more() {
        const data = await this.read();
        if (!data)
            throw new Error("proxy closed the connection");
        this.buf = concat(this.buf, data);
    }
}
/** `stream`, with `first` read before anything else from it. */
function withFirst(stream, first) {
    if (!first.length)
        return stream;
    let pending = first.slice();
    return {
        read() {
            const data = pending;
            pending = null;
            return data ? Promise.resolve(data) : stream.read();
        },
        write: (data) => stream.write(data),
        close: () => {
            pending = null;
            return stream.close();
        },
    };
}
function indexOf(hay, needle, from) {
    outer: for (let i = from; i + needle.length <= hay.length; i++) {
        for (let j = 0; j < needle.length; j++)
            if (hay[i + j] !== needle[j])
                continue outer;
        return i;
    }
    return -1;
}
function concat(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let off = 0;
    for (const p of parts) {
        out.set(p, off);
        off += p.length;
    }
    return out;
}
function base64(bytes) {
    let s = "";
    for (const b of bytes)
        s += String.fromCharCode(b);
    return btoa(s);
}
