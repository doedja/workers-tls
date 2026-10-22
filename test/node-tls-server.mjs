// A TLS server run by Node, for the tests that need what Bun's node:tls before
// 1.4 does not do: it ignores maxVersion, so it cannot serve TLS 1.2 only.
//
//   node node-tls-server.mjs <key.pem> <cert.pem> <echo|http|ok> [maxVersion]
//
// Prints `port <n>`, then `conn <protocol> <reused> <sni>` for each connection.
// echo: upper-cases what it reads. http: one HTTP/1.1 JSON answer naming the
// request path. ok: sends "ok" and closes. It exits when its stdin closes.
import { readFileSync } from "node:fs";
import { createServer } from "node:tls";

const [key, cert, mode, maxVersion = "TLSv1.3"] = process.argv.slice(2);
const server = createServer({ key: readFileSync(key), cert: readFileSync(cert), maxVersion }, (s) => {
  console.log(`conn ${s.getProtocol()} ${s.isSessionReused()} ${s.servername || "-"}`);
  s.on("error", () => undefined);
  if (mode === "ok") return void s.end("ok");
  let req = "";
  s.on("data", (d) => {
    if (mode === "echo") return void s.write(d.toString().toUpperCase());
    req += d.toString();
    if (!req.includes("\r\n\r\n")) return;
    const body = JSON.stringify({ success: true, path: req.split(" ")[1] });
    s.end(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`);
  });
});
server.listen(0, "127.0.0.1", () => console.log(`port ${server.address().port}`));
process.stdin.on("end", () => process.exit(0));
process.stdin.resume();
