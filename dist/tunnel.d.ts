/**
 * Byte streams for `connectTls`: a socket as it is, or a tunnel through an
 * HTTP CONNECT or SOCKS5 proxy. They take a `connect` function (the one from
 * `cloudflare:sockets`) instead of importing it, so they run anywhere a socket
 * of that shape can be made.
 *
 *   const tunnel = await openTunnel(connect, "socks5://user:pass@proxy:1080", "example.com", 443)
 *   const tls = await connectTls("example.com", tunnel)
 */
import type { ByteStream } from "./tls.js";
/** What `connect()` from `cloudflare:sockets` returns, as far as a tunnel uses it. */
export interface Socket {
    readonly readable: ReadableStream<Uint8Array>;
    readonly writable: WritableStream<Uint8Array>;
    close(): Promise<void>;
}
/** `connect` from `cloudflare:sockets`, or anything that opens a TCP connection the same way. */
export type Connect = (address: {
    hostname: string;
    port: number;
}) => Socket;
/** A byte stream over a socket. Closing it is the caller's, after the TLS connection on it is done. */
export interface Tunnel extends ByteStream {
    /** Closes the socket. A `read()` waiting on it returns undefined. */
    close(): Promise<void>;
}
export interface ProxyConfig {
    /** "http" is HTTP CONNECT. "socks5" sends the target's name, so the proxy resolves it. */
    protocol: "http" | "socks5";
    hostname: string;
    port: number;
    username?: string;
    password?: string;
}
export interface TunnelOptions {
    /** Aborting before the proxy has opened the tunnel closes the socket and rejects with the signal's reason. */
    signal?: AbortSignal;
}
/** A socket as a `Tunnel`, with nothing in between: TLS straight to the host, with SNI. */
export declare function socketStream(socket: Socket): Tunnel;
/**
 * A tunnel to `host:port` through `proxy` (a URL such as
 * `http://user:pass@proxy:8080` or `socks5://proxy:1080`, or a `ProxyConfig`),
 * once the proxy has opened it. Errors name the step and never the
 * credentials: `proxy closed the connection`, `proxy answered CONNECT with
 * 407`, `proxy refused the username and password`, `proxy could not connect:
 * host unreachable (4)`.
 */
export declare function openTunnel(connect: Connect, proxy: string | ProxyConfig, host: string, port: number, options?: TunnelOptions): Promise<Tunnel>;
