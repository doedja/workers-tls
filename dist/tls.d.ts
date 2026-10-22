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
/**
 * The compiled module (`workers-tls/workers_tls.wasm`) and the DER roots every
 * connection trusts. Call before `connectTls`; calling again replaces both for
 * the connections made after.
 */
export declare function initTls(module: WebAssembly.Module, roots: Uint8Array[]): void;
/** The DER of each certificate in a PEM bundle, for `initTls`. */
export declare function pemToDer(pem: string): Uint8Array[];
/**
 * A TLS client session to `serverName` (SNI and certificate name) over
 * `stream`, after the handshake. Rejects with the TLS error (`invalid peer
 * certificate: ...`, `received fatal alert: ...`) or `closed during handshake`.
 * One `read()` at a time; writes may overlap reads.
 */
export declare function connectTls(serverName: string, stream: ByteStream): Promise<TlsConnection>;
