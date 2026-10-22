# workers-tls

TLS 1.2 and 1.3 for Cloudflare Workers sockets, straight to a host or
through an HTTP CONNECT or SOCKS5 proxy. It is
[rustls](https://github.com/rustls/rustls) compiled to WebAssembly, with a
small TypeScript wrapper. It sends SNI, and it trusts only the roots you give
it.

## Why

Workers can open raw TCP sockets (`cloudflare:sockets`) and upgrade one with
`socket.startTls()`, but:

- On the production edge `startTls()` ignores `expectedServerHostname` and
  sends no SNI ([workerd#6903](https://github.com/cloudflare/workerd/issues/6903)).
  Servers behind a shared front end (most CDNs and cloud load balancers) refuse
  the handshake or present the wrong certificate.
- `fetch()` can't go through a proxy. A socket can reach the proxy, but then
  the TLS session to the real host has to run inside the tunnel, in the
  Worker.
- You can't choose what `startTls()` trusts.

[subtls](https://github.com/jawj/subtls) runs TLS in JavaScript over
WebCrypto and is good, but it speaks only TLS 1.3 with P-256. Servers that
only do TLS 1.2, or that ask for another key-share group, refuse its
ClientHello. This package reaches those as well.

## Install

From GitHub (it isn't on npm):

```sh
npm install github:doedja/workers-tls#v0.1.0
bun add github:doedja/workers-tls#v0.1.0
```

## Use

```ts
import { connect } from "cloudflare:sockets";
import tlsModule from "workers-tls/workers_tls.wasm";
import { connectTls, initTls, openTunnel, pemToDer } from "workers-tls";
import rootsPem from "./roots.pem";

// Once per isolate. No roots are built in: give the ones your hosts chain to.
initTls(tlsModule, pemToDer(rootsPem));

export default {
  async fetch(request: Request, env: { PROXY_URL: string }): Promise<Response> {
    const tunnel = await openTunnel(connect, env.PROXY_URL, "example.com", 443, {
      signal: AbortSignal.timeout(10_000),
    });
    try {
      const tls = await connectTls("example.com", tunnel);
      await tls.write(new TextEncoder().encode("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"));
      let text = "";
      for (let chunk; (chunk = await tls.read()); ) text += new TextDecoder().decode(chunk);
      return new Response(text);
    } finally {
      await tunnel.close();
    }
  },
};
```

`PROXY_URL` is something like `http://user:pass@203.0.113.7:8080` or
`socks5://user:pass@203.0.113.7:1080`. Without a proxy, use
`socketStream(connect({ hostname: "example.com", port: 443 }))` in place of
`openTunnel(...)`.

Wrangler bundles a `.wasm` import as a compiled `WebAssembly.Module` by
default. A `.pem` import needs a text rule in `wrangler.toml`, or paste the PEM
into a string instead:

```toml
[[rules]]
type = "Text"
globs = ["**/*.pem"]
fallthrough = true
```

For roots, take the ones your hosts chain to from Mozilla's list (curl
publishes it as `cacert.pem`). Each root is 1–2 KB.

## API

### `initTls(module, roots)`

The compiled module (`workers-tls/workers_tls.wasm`) and the roots (DER) every
connection trusts. Call it before `connectTls`. Calling it again replaces both
for connections made after.

### `connectTls(serverName, stream)`

A TLS session to `serverName` over `stream`, resolved once the handshake is
done. `serverName` is both the SNI and the name the certificate must carry.
`stream` is any `{ read(), write(bytes) }`: a tunnel, a socket, or your own.

- It rejects with the rustls error, for example `invalid peer certificate: ...`
  or `received fatal alert: ...`, or with `closed during handshake`.
- `tls.version` is `"TLS1.2"` or `"TLS1.3"`.
- `tls.read()` returns `undefined` at the end of the stream or after the
  peer's `close_notify`.
- Call `read()` one at a time, and `write()` one at a time. A write may run
  while a read waits, and a read never waits for writes to go out, so an
  upload and its answer can stream at once.
- A failed write fails every write after it. Reads go on, because the peer
  may have answered before it stopped reading, for example an early error
  status during an upload. A failed read keeps failing; it never looks like
  the end.
- Many servers end a connection without `close_notify`. When a body has no
  other framing (no Content-Length or chunking), check `tls.closeNotify`:
  only when it is true do you know the body arrived whole.
- A connection frees itself when reading reaches the end or fails.
  `tls.close()` frees it, then sends `close_notify`. It doesn't close the
  stream.
- `stream.write` is called one call at a time, in the order the bytes must go
  out.

### `openTunnel(connect, proxy, host, port, { signal }?)`

A `Tunnel` to `host:port` through `proxy`, resolved once the proxy has opened
it. `connect` is the one from `cloudflare:sockets`.

- `proxy` is a URL or a `ProxyConfig` (`{ protocol, hostname, port, username?, password? }`):
  - `http://[user:pass@]host[:port]` is HTTP CONNECT. The port defaults to 80.
  - `socks5://` or `socks5h://`, with `[user:pass@]host[:port]`, is SOCKS5,
    with RFC 1929 username and password. The port defaults to 1080.
  - Credentials in a URL are percent-decoded.
  - Both protocols send the target's name, so the proxy resolves it. IPv4
    and IPv6 targets go as addresses. A dotted number that isn't plain IPv4,
    such as `010.0.0.1`, is refused, because proxies disagree on whether it
    is octal.
  - HTTPS proxies (TLS to the proxy itself) aren't supported.
- Errors name the step, never the URL or credentials:
  - `proxy closed the connection`
  - `proxy answered CONNECT with 407`
  - `proxy refused the username and password`
  - `proxy accepts none of the offered authentication methods`
  - `proxy could not connect: connection refused (5)`
- Aborting `signal` before the tunnel is open closes the socket and rejects
  with the signal's reason. To bound the TLS handshake as well, close the
  tunnel on a timer: a pending `read()` then ends and `connectTls` rejects.

### `socketStream(socket)`

A `Tunnel` over a socket, with nothing in between.

### Tunnels

A tunnel has `read()`, `write(bytes)` and `close()`. Closing it closes the
socket. Writes go out in 16 KB pieces, each after the last was accepted,
because some proxies drop a connection on one very large write.

### `pemToDer(pem)`

The DER of each certificate in a PEM bundle.

## Security

- rustls verifies certificates with webpki against your roots only, and
  checks the name. It offers TLS 1.3, and TLS 1.2 with ECDHE and AEAD suites
  only.
- Session resumption is off: every connection is a full handshake.
  Connections through different tunnels can't be linked to each other by a
  session ticket.
- No ALPN is offered, so servers answer HTTP/1.1. There are no client
  certificates and no 0-RTT.
- One WebAssembly instance per isolate holds every connection. Connection
  handles are never reused, so a call on a closed connection can't reach a
  newer one.
- A trap inside the module means a bug, not a TLS error. After one, the
  instance is dropped and the next connection starts a fresh one.
- The committed `workers_tls.wasm` is rebuilt and compared byte for byte in
  CI, so it matches the source.

This package hasn't been independently audited. To report a vulnerability,
see [SECURITY.md](SECURITY.md).

## Cost

Measured in Bun on x86-64. Workers runs the same V8, so expect similar numbers.

| | |
|---|---|
| Module | 604 KB (233 KB gzipped) |
| Compile | about 10–35 ms, once per isolate |
| Handshake, warm | about 1 ms (TLS 1.2, ECDHE-RSA), about 3 ms (TLS 1.3) |
| Bulk data | about 30 MB/s of AES-GCM: a 5 MB upload costs about 170 ms of CPU |

WebAssembly has no AES instructions, so bulk encryption is far slower than
WebCrypto. For TLS 1.3 servers that accept it, subtls is cheaper on large
bodies. Use this package for the servers that don't, or where you need its
guarantees.

## What's inside

- **TLS:** rustls 0.23 with the `ring` provider, using rustls's default cipher
  suites and key exchange.
- **Target:** `wasm32-wasip1`. The wrapper supplies the six WASI calls that
  rustls and ring need:
  - the clock, for certificate validity;
  - randomness, from `crypto.getRandomValues`;
  - no-op stubs for the environment, stderr and exit.
- **No I/O in the module.** The host feeds in network bytes, takes out the
  bytes to send, and moves application data through the C ABI in
  `src/lib.rs`.
- **TypeScript:** the wrapper and the tunnels are in `ts/`, built to `dist/`.
  `dist/` is committed, because installs from GitHub don't build.

## Build

```sh
./build.sh      # workers_tls.wasm: rustup (rust-toolchain.toml pins Rust) and clang 18
bun run build   # dist/
```

The build remaps paths, so the module comes out byte for byte the same on
any machine with the same toolchain. CI checks both builds against what's
committed.

## Tests

```sh
bun install
bun test
```

The tests run against local TLS servers, through local HTTP CONNECT and SOCKS5
proxies, and inside workerd via `wrangler dev` (`test/workerd.test.ts`), with
the real `cloudflare:sockets`. `cargo test` covers the Rust side's handles.

The TLS 1.2-only servers run in Node (`test/node-tls-server.mjs`), because
Bun's `node:tls` before 1.4 ignores `maxVersion`. So `node` must be on the
PATH.

## License

MIT or Apache-2.0, at your option.

The built module includes these crates, and their licenses apply to it:

- rustls (Apache-2.0, ISC or MIT)
- rustls-webpki (ISC)
- ring (Apache-2.0 and ISC, with BoringSSL and OpenSSL notices)
- untrusted (ISC)
- subtle (BSD-3-Clause)
- rustls-pki-types, zeroize, once_cell, getrandom, cfg-if and wasi (MIT or Apache-2.0)
