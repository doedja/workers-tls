import { connect as netConnect } from "node:net";
import type { Connect } from "../ts/index.js";

/** `connect` from `cloudflare:sockets`, over node:net: a TCP socket as a Worker sees one. */
export const nodeConnect: Connect = ({ hostname, port }) => {
  const sock = netConnect(port, hostname);
  let done = false;
  const end = (fn: () => void) => {
    if (done) return;
    done = true;
    try {
      fn();
    } catch {
      // Already cancelled.
    }
  };
  return {
    readable: new ReadableStream<Uint8Array>({
      start(c) {
        sock.on("data", (d: Buffer) => !done && c.enqueue(new Uint8Array(d)));
        sock.on("end", () => end(() => c.close()));
        sock.on("error", (e) => end(() => c.error(e)));
      },
      cancel() {
        done = true;
        sock.destroy();
      },
    }),
    writable: new WritableStream<Uint8Array>({
      write: (d) => new Promise<void>((resolve, reject) => sock.write(d, (e) => (e ? reject(e) : resolve()))),
    }),
    close: async () => void sock.destroy(),
  };
};
