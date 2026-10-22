import { connect as netConnect } from "node:net";
import type { Connect } from "../ts/index.js";

/**
 * `connect` from `cloudflare:sockets`, over node:net: a TCP socket as a Worker
 * sees one. Bytes leave node's buffer only when the reader pulls, so a reader
 * that stops pulling stops the peer, as on workerd.
 */
export const nodeConnect: Connect = ({ hostname, port }) => {
  const sock = netConnect(port, hostname);
  sock.pause();
  let ended = false;
  let failed: Error | null = null;
  let wake: (() => void) | null = null;
  const poke = () => {
    const w = wake;
    wake = null;
    w?.();
  };
  sock.on("readable", poke);
  sock.on("end", () => ((ended = true), poke()));
  sock.on("close", () => ((ended = true), poke()));
  sock.on("error", (e) => ((failed = e), poke()));
  return {
    readable: new ReadableStream<Uint8Array>(
      {
        async pull(c) {
          for (;;) {
            const d = sock.read() as Buffer | null;
            if (d) return c.enqueue(new Uint8Array(d));
            if (failed) return c.error(failed);
            if (ended) return c.close();
            await new Promise<void>((r) => (wake = r));
          }
        },
        cancel() {
          sock.destroy();
        },
      },
      { highWaterMark: 0 },
    ),
    writable: new WritableStream<Uint8Array>({
      write: (d) => new Promise<void>((resolve, reject) => sock.write(d, (e) => (e ? reject(e) : resolve()))),
    }),
    close: async () => void sock.destroy(),
  };
};
