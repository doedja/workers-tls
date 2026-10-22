/**
 * A TLS 1.2/1.3 client (rustls, compiled to wasm32-wasip1) over any byte
 * stream. `socket.startTls()` sends no SNI on the Workers production edge
 * (workerd#6903), so servers behind a shared front end refuse it, directly or
 * through a proxy tunnel; this runs the TLS session in the Worker instead,
 * with the trust anchors the caller picks.
 *
 *   initTls(module, roots)                       once per isolate
 *   const tls = await connectTls(name, stream)   stream: { read, write }
 *   await tls.write(bytes); await tls.read(); await tls.close()
 *
 * One WebAssembly instance per isolate holds every connection. A trap inside
 * it (a bug, not a TLS error) drops the instance; the next connection makes a
 * new one. The caller gives the trust anchors (DER), so the module carries no
 * root store.
 */

/** The raw bytes of a connection: what came from the network, what to send to it. */
export interface ByteStream {
  /** The next bytes from the peer, or undefined at end of stream. */
  read(): Promise<Uint8Array | undefined>;
  /** Called one at a time, in the order the bytes must go out. */
  write(data: Uint8Array): Promise<void>;
}

export interface TlsConnection {
  /** Decrypted bytes, or undefined at the end: the peer's close_notify, or the stream ending. */
  read(): Promise<Uint8Array | undefined>;
  write(data: Uint8Array): Promise<void>;
  /**
   * Frees the connection, then sends close_notify after anything still being
   * sent; the stream itself is the caller's to close. The end of the stream,
   * the peer's close_notify and an error free it too, so a connection read to
   * its end needs no close.
   */
  close(): Promise<void>;
  /** "TLS1.2" or "TLS1.3". */
  readonly version: string;
  /**
   * True once the peer sent close_notify. Many servers end a connection
   * without it, so `read()` ends the same either way; a body that only the end
   * of the stream frames (no Content-Length or chunking) is complete only when
   * this is true.
   */
  readonly closeNotify: boolean;
}

interface Exports {
  memory: WebAssembly.Memory;
  wt_alloc(len: number): number;
  wt_free(ptr: number, len: number): void;
  wt_out_ptr(): number;
  wt_error_ptr(): number;
  wt_error_len(): number;
  wt_add_root(ptr: number, len: number): number;
  wt_connect(ptr: number, len: number): number;
  wt_feed(h: number, ptr: number, len: number): number;
  wt_send(h: number, ptr: number, len: number): number;
  wt_take_tls(h: number): number;
  wt_take_plain(h: number): number;
  wt_state(h: number): number;
  wt_version(h: number): number;
  wt_close(h: number): number;
  wt_drop(h: number): number;
}

const HANDSHAKING = 1;
const PEER_CLOSED = 2;
/**
 * Bytes handed to rustls per call, either way: a large write or network read
 * never sits whole in the module's memory, which never shrinks.
 */
const CHUNK = 64 * 1024;
const enc = new TextEncoder();
const dec = new TextDecoder();

let wasmModule: WebAssembly.Module | null = null;
let trustRoots: Uint8Array[] = [];
let live: Exports | null = null;

/**
 * The compiled module (`workers-tls/workers_tls.wasm`) and the DER roots every
 * connection trusts. Call before `connectTls`; calling again replaces both for
 * the connections made after.
 */
export function initTls(module: WebAssembly.Module, roots: Uint8Array[]): void {
  wasmModule = module;
  trustRoots = roots;
  live = null;
}

/** The DER of each certificate in a PEM bundle, for `initTls`. */
export function pemToDer(pem: string): Uint8Array[] {
  return [...pem.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)].map((m) =>
    Uint8Array.from(atob(m[1]!.replace(/\s+/g, "")), (c) => c.charCodeAt(0)),
  );
}

/** The six WASI calls rustls's std needs: a clock, randomness, and no-ops for the rest. */
function wasi(memory: () => WebAssembly.Memory) {
  const view = () => new DataView(memory().buffer);
  return {
    clock_time_get(_id: number, _precision: bigint, out: number): number {
      view().setBigUint64(out, BigInt(Date.now()) * 1_000_000n, true);
      return 0;
    },
    random_get(ptr: number, len: number): number {
      const buf = new Uint8Array(memory().buffer, ptr, len);
      // getRandomValues takes at most 64 KB at a time.
      for (let off = 0; off < len; off += 65536) crypto.getRandomValues(buf.subarray(off, Math.min(len, off + 65536)));
      return 0;
    },
    environ_sizes_get(count: number, size: number): number {
      view().setUint32(count, 0, true);
      view().setUint32(size, 0, true);
      return 0;
    },
    environ_get(): number {
      return 0;
    },
    // A panic message: nothing reads stderr in a Worker.
    fd_write(_fd: number, iovs: number, iovsLen: number, written: number): number {
      let n = 0;
      for (let i = 0; i < iovsLen; i++) n += view().getUint32(iovs + i * 8 + 4, true);
      view().setUint32(written, n, true);
      return 0;
    },
    // As fatal as a trap: the instance is dropped.
    proc_exit(code: number): never {
      throw new WebAssembly.RuntimeError(`workers-tls exited (${code})`);
    },
  };
}

/**
 * The instance's exports, each call guarded: a trap leaves rustls's state
 * unknown (a RefCell borrow stays held, so every later call traps too), so
 * the instance stops being the live one and the next connection gets a new
 * one. Connections still on it fail on their next call.
 */
function guarded(raw: Exports): Exports {
  const x = { memory: raw.memory } as Exports;
  for (const [name, fn] of Object.entries(raw)) {
    if (typeof fn !== "function") continue;
    (x as unknown as Record<string, unknown>)[name] = (...args: number[]) => {
      try {
        return (fn as (...a: number[]) => number)(...args);
      } catch (err) {
        if (err instanceof WebAssembly.RuntimeError && live === x) live = null;
        throw err;
      }
    };
  }
  return x;
}

function instance(): Exports {
  if (live) return live;
  if (!wasmModule) throw new Error("workers-tls: initTls was not called");
  let exp: Exports | null = null;
  const inst = new WebAssembly.Instance(wasmModule, { wasi_snapshot_preview1: wasi(() => exp!.memory) });
  exp = guarded(inst.exports as unknown as Exports);
  for (const der of trustRoots) {
    const status = withBytes(exp, der, (p, n) => exp!.wt_add_root(p, n));
    if (status < 0) throw new Error(`workers-tls: ${lastError(exp)}`);
  }
  live = exp;
  return exp;
}

function withBytes<T>(x: Exports, data: Uint8Array, fn: (ptr: number, len: number) => T): T {
  const ptr = x.wt_alloc(data.length);
  try {
    new Uint8Array(x.memory.buffer, ptr, data.length).set(data);
    return fn(ptr, data.length);
  } finally {
    x.wt_free(ptr, data.length);
  }
}

function lastError(x: Exports): string {
  return dec.decode(new Uint8Array(x.memory.buffer, x.wt_error_ptr(), x.wt_error_len()));
}

/** Copy the `len` bytes the last call left at wt_out_ptr. */
function taken(x: Exports, len: number): Uint8Array {
  if (len < 0) throw new Error(lastError(x));
  return new Uint8Array(x.memory.buffer, x.wt_out_ptr(), len).slice();
}

/**
 * A TLS client session to `serverName` (SNI and certificate name) over
 * `stream`, after the handshake. Rejects with the TLS error (`invalid peer
 * certificate: ...`, `received fatal alert: ...`) or `closed during handshake`.
 * One `read()` at a time; writes may overlap reads.
 */
export async function connectTls(serverName: string, stream: ByteStream): Promise<TlsConnection> {
  const x = instance();
  const h = withBytes(x, enc.encode(serverName), (p, n) => x.wt_connect(p, n));
  if (h <= 0) throw new Error(lastError(x));
  // Handles are never reused, so a call after the drop fails ("no such
  // connection"); `dropped` makes it fail as "connection closed" first.
  let dropped = false;
  let closeNotify = false;
  const drop = () => {
    if (dropped) return;
    dropped = true;
    if (live === x) x.wt_drop(h);
  };
  // What goes to the network, in the order rustls produced it, whichever of
  // read(), write() and close() took it.
  let sent: Promise<void> = Promise.resolve();
  const send = (out: Uint8Array): Promise<void> => {
    if (out.length) sent = sent.then(() => stream.write(out));
    return sent;
  };
  const flush = () => send(taken(x, x.wt_take_tls(h)));
  /** Network bytes not yet handed to rustls. */
  let pending: Uint8Array | null = null;
  /** Hand rustls the next piece of network bytes; false at the end of the stream. A TLS error sends its alert, then rejects. */
  const pump = async (): Promise<boolean> => {
    if (!pending) {
      const data = await stream.read();
      // Closed while the read waited: the handle is gone.
      if (!data || dropped) return false;
      pending = data;
    }
    const piece: Uint8Array = pending.subarray(0, CHUNK);
    pending = pending.length > CHUNK ? pending.subarray(CHUNK) : null;
    const status = withBytes(x, piece, (p, n) => x.wt_feed(h, p, n));
    if (status < 0) {
      const msg = lastError(x);
      await flush().catch(() => undefined);
      throw new Error(msg);
    }
    await flush();
    return true;
  };
  try {
    await flush();
    while (x.wt_state(h) & HANDSHAKING) {
      if (!(await pump())) throw new Error("closed during handshake");
    }
  } catch (err) {
    drop();
    throw err;
  }
  const v = x.wt_version(h);
  const version = v === 0x0304 ? "TLS1.3" : v === 0x0303 ? "TLS1.2" : "TLS";
  return {
    version,
    get closeNotify() {
      return closeNotify;
    },
    async read() {
      try {
        while (!dropped) {
          const plain = taken(x, x.wt_take_plain(h));
          if (plain.length) return plain;
          if (x.wt_state(h) & PEER_CLOSED) {
            closeNotify = true;
            break;
          }
          if (!(await pump())) break;
        }
      } catch (err) {
        drop();
        throw err;
      }
      // The end frees the connection; nothing more can arrive.
      drop();
      return undefined;
    },
    async write(data) {
      try {
        for (let off = 0; off < data.length; off += CHUNK) {
          if (dropped) throw new Error("connection closed");
          const status = withBytes(x, data.subarray(off, off + CHUNK), (p, n) => x.wt_send(h, p, n));
          if (status < 0) throw new Error(lastError(x));
          await flush();
        }
      } catch (err) {
        drop();
        throw err;
      }
    },
    async close() {
      if (dropped) return;
      // Freed before close_notify goes out, so a stream that never takes it
      // (already closed, or stuck) holds nothing.
      let notify: Uint8Array = new Uint8Array(0);
      try {
        x.wt_close(h);
        notify = taken(x, x.wt_take_tls(h));
      } finally {
        drop();
      }
      await send(notify);
    },
  };
}
