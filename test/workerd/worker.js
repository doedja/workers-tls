// The end-to-end test's Worker (`test/workerd.test.ts`): the built package in
// workerd, with `connect` from cloudflare:sockets. GET /<path>?port=<n>
// [&proxy=<url>][&name=<sni>] fetches /<path> over TLS to <sni> (tls.test),
// straight to 127.0.0.1:<n> or through the proxy, and answers what it got.
// GET /pipe?port=<n>&mb=<m> writes m MB to an echo server while reading the
// echo back, and answers how much came back.
import { connect } from "cloudflare:sockets";
import tlsModule from "../../workers_tls.wasm";
import { connectTls, initTls, openTunnel, pemToDer, socketStream } from "../../dist/index.js";
import caPem from "../fixtures/ca.pem";

initTls(tlsModule, pemToDer(caPem));

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const port = Number(url.searchParams.get("port"));
    const proxy = url.searchParams.get("proxy");
    const name = url.searchParams.get("name") ?? "tls.test";
    let stream;
    try {
      stream = proxy ? await openTunnel(connect, proxy, name, port) : socketStream(connect({ hostname: "127.0.0.1", port }));
      const tls = await connectTls(name, stream);
      if (url.pathname === "/pipe") {
        const total = Number(url.searchParams.get("mb")) * 1024 * 1024;
        const piece = new Uint8Array(1024 * 1024).fill(0x61);
        const writing = (async () => {
          for (let sent = 0; sent < total; sent += piece.length) await tls.write(piece);
        })();
        let got = 0;
        while (got < total) {
          const d = await tls.read();
          if (!d) break;
          got += d.length;
        }
        await writing;
        return Response.json({ got });
      }
      await tls.write(new TextEncoder().encode(`GET ${url.pathname} HTTP/1.1\r\nHost: ${name}\r\nConnection: close\r\n\r\n`));
      let text = "";
      for (let d; (d = await tls.read()); ) text += new TextDecoder().decode(d);
      return Response.json({ version: tls.version, body: JSON.parse(text.slice(text.indexOf("\r\n\r\n") + 4)) });
    } catch (err) {
      return Response.json({ error: String(err) }, { status: 500 });
    } finally {
      await stream?.close();
    }
  },
};
