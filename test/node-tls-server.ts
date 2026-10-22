import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

/** A `node-tls-server.mjs` child: its port, and each connection's protocol, whether it resumed a session, and its SNI. */
export interface NodeTlsServer {
  port: number;
  conns: Array<{ protocol: string; reused: boolean; sni: string }>;
  /** Resolves once `n` connections were seen. */
  seen(n: number): Promise<void>;
  close(): void;
}

const script = fileURLToPath(new URL("./node-tls-server.mjs", import.meta.url));

export async function nodeTlsServer(key: string, cert: string, mode: "echo" | "http" | "ok", maxVersion?: string): Promise<NodeTlsServer> {
  const child = spawn("node", [script, key, cert, mode, ...(maxVersion ? [maxVersion] : [])], { stdio: ["pipe", "pipe", "inherit"] });
  const conns: NodeTlsServer["conns"] = [];
  const waiters: Array<() => void> = [];
  let buf = "";
  const port = await new Promise<number>((resolve, reject) => {
    child.on("error", reject);
    child.on("exit", (code) => reject(new Error(`node TLS server exited (${code})`)));
    child.stdout.on("data", (d: Buffer) => {
      buf += d.toString();
      for (let i = buf.indexOf("\n"); i >= 0; i = buf.indexOf("\n")) {
        const [kind, a, b, c] = buf.slice(0, i).split(" ");
        buf = buf.slice(i + 1);
        if (kind === "port") resolve(Number(a));
        if (kind === "conn") {
          conns.push({ protocol: a!, reused: b === "true", sni: c! });
          for (const wake of waiters.splice(0)) wake();
        }
      }
    });
  });
  return {
    port,
    conns,
    async seen(n) {
      while (conns.length < n) await new Promise<void>((r) => waiters.push(r));
    },
    close: () => void child.stdin.end(),
  };
}
