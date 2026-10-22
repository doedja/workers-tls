//! A TLS client (rustls, TLS 1.2 and 1.3) as a byte-stream state machine for
//! WebAssembly hosts with no TLS of their own over an arbitrary socket. On
//! Cloudflare Workers `socket.startTls()` sends no SNI on the production edge
//! (workerd#6903), so TLS through an HTTP CONNECT or SOCKS tunnel has to be done
//! in the Worker; this is that, for servers a TLS-1.3-only client cannot reach.
//!
//! The host moves bytes: what arrives from the network goes in with `wt_feed`,
//! what the connection has to send comes out of `wt_take_tls`; the application
//! writes with `wt_send` and reads with `wt_take_plain`. Nothing here does I/O.
//! Time and randomness come from the host through WASI (`clock_time_get`,
//! `random_get`), and the trust anchors too (`wt_add_root`, DER), so no root
//! store is built in.
//!
//! ABI: every function returns a status (>= 0 ok, < 0 error, message from
//! `wt_error_ptr`/`wt_error_len`) or a length whose bytes sit at `wt_out_ptr`
//! until the next call. A connection is a handle > 0, never reused, so a call
//! the host makes on a connection already dropped fails instead of reaching
//! another one.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::Arc;

use rustls::client::ClientConnection;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::time_provider::TimeProvider;
use rustls::{ClientConfig, RootCertStore};

// Built for wasm32-wasip1: the host's WASI shim gives the clock
// (`clock_time_get`) and randomness (`random_get`), so std and ring work as on
// any platform.
#[derive(Debug)]
struct HostTime;

impl TimeProvider for HostTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::now())
    }
}

struct Conn {
    tls: ClientConnection,
    /// Decrypted application data not yet taken.
    plain: Vec<u8>,
    /// The peer sent close_notify.
    peer_closed: bool,
}

struct State {
    roots: RootCertStore,
    config: Option<Arc<ClientConfig>>,
    conns: BTreeMap<u32, Conn>,
    /// The last handle given out.
    last: u32,
    out: Vec<u8>,
    error: String,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State {
        roots: RootCertStore::empty(),
        config: None,
        conns: BTreeMap::new(),
        last: 0,
        out: Vec::new(),
        error: String::new(),
    });
}

fn fail(st: &mut State, msg: String) -> i32 {
    st.error = msg;
    -1
}

fn config(st: &mut State) -> Result<Arc<ClientConfig>, String> {
    if let Some(c) = &st.config {
        return Ok(c.clone());
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ClientConfig::builder_with_details(provider, Arc::new(HostTime))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| e.to_string())?
        .with_root_certificates(st.roots.clone())
        .with_no_client_auth();
    // One config serves every connection of the host, whatever tunnel each
    // takes: a resumed session would let the server link them.
    cfg.resumption = rustls::client::Resumption::disabled();
    let cfg = Arc::new(cfg);
    st.config = Some(cfg.clone());
    Ok(cfg)
}

fn conn_mut(st: &mut State, h: u32) -> Option<&mut Conn> {
    st.conns.get_mut(&h)
}

/// Pull everything the connection wants to send into `out`.
fn drain_tls(tls: &mut ClientConnection, out: &mut Vec<u8>) -> Result<(), String> {
    while tls.wants_write() {
        tls.write_tls(out).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Move decrypted data out of rustls so its received-plaintext buffer never fills.
fn drain_plain(c: &mut Conn) -> Result<(), String> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match c.tls.reader().read(&mut buf) {
            Ok(0) => {
                c.peer_closed = true;
                return Ok(());
            }
            Ok(n) => c.plain.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            // The peer closed the TCP stream without close_notify; the host sees EOF itself.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.to_string()),
        }
    }
}

unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ptr, len)
    }
}

#[no_mangle]
pub extern "C" fn wt_alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len.max(1));
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}

#[no_mangle]
pub unsafe extern "C" fn wt_free(ptr: *mut u8, len: usize) {
    drop(Vec::from_raw_parts(ptr, 0, len.max(1)));
}

#[no_mangle]
pub extern "C" fn wt_out_ptr() -> *const u8 {
    STATE.with(|s| s.borrow().out.as_ptr())
}

#[no_mangle]
pub extern "C" fn wt_error_ptr() -> *const u8 {
    STATE.with(|s| s.borrow().error.as_ptr())
}

#[no_mangle]
pub extern "C" fn wt_error_len() -> usize {
    STATE.with(|s| s.borrow().error.len())
}

/// Trust one root certificate (DER). New connections use the updated set.
#[no_mangle]
pub unsafe extern "C" fn wt_add_root(ptr: *const u8, len: usize) -> i32 {
    let der = bytes(ptr, len).to_vec();
    STATE.with(|s| {
        let st = &mut *s.borrow_mut();
        match st.roots.add(CertificateDer::from(der)) {
            Ok(()) => {
                st.config = None;
                0
            }
            Err(e) => fail(st, format!("bad root certificate: {e}")),
        }
    })
}

/// A client connection to `name` (the SNI and the certificate name); its ClientHello is ready in `wt_take_tls`.
#[no_mangle]
pub unsafe extern "C" fn wt_connect(name_ptr: *const u8, name_len: usize) -> i32 {
    let name = String::from_utf8_lossy(bytes(name_ptr, name_len)).into_owned();
    STATE.with(|s| {
        let st = &mut *s.borrow_mut();
        let cfg = match config(st) {
            Ok(c) => c,
            Err(e) => return fail(st, e),
        };
        let server = match ServerName::try_from(name) {
            Ok(n) => n,
            Err(e) => return fail(st, format!("bad server name: {e}")),
        };
        let mut tls = match ClientConnection::new(cfg, server) {
            Ok(t) => t,
            Err(e) => return fail(st, e.to_string()),
        };
        // The host drains output after every call, so nothing waits in rustls.
        tls.set_buffer_limit(None);
        // Handles count up and are positive i32s; none is ever given out twice.
        if st.last >= i32::MAX as u32 {
            return fail(st, "connection handles exhausted".into());
        }
        st.last += 1;
        let h = st.last;
        st.conns.insert(h, Conn { tls, plain: Vec::new(), peer_closed: false });
        h as i32
    })
}

/// Bytes that arrived from the network.
#[no_mangle]
pub unsafe extern "C" fn wt_feed(h: u32, ptr: *const u8, len: usize) -> i32 {
    let mut data = bytes(ptr, len);
    STATE.with(|s| {
        let st = &mut *s.borrow_mut();
        let Some(c) = conn_mut(st, h) else { return fail(st, "no such connection".into()) };
        let mut err = None;
        while !data.is_empty() {
            match c.tls.read_tls(&mut data) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) => {
                    err = Some(e.to_string());
                    break;
                }
            }
            if let Err(e) = c.tls.process_new_packets() {
                err = Some(e.to_string());
                break;
            }
            if let Err(e) = drain_plain(c) {
                err = Some(e);
                break;
            }
        }
        // A fatal error leaves an alert to send; the host takes it like any output.
        match err {
            Some(e) => fail(st, e),
            None => 0,
        }
    })
}

/// Application data to encrypt and send.
#[no_mangle]
pub unsafe extern "C" fn wt_send(h: u32, ptr: *const u8, len: usize) -> i32 {
    let data = bytes(ptr, len);
    STATE.with(|s| {
        let st = &mut *s.borrow_mut();
        let Some(c) = conn_mut(st, h) else { return fail(st, "no such connection".into()) };
        match c.tls.writer().write_all(data) {
            Ok(()) => 0,
            Err(e) => fail(st, e.to_string()),
        }
    })
}

/// What the connection has to send (handshake, records, alerts), at `wt_out_ptr`.
#[no_mangle]
pub extern "C" fn wt_take_tls(h: u32) -> i32 {
    STATE.with(|s| {
        let st = &mut *s.borrow_mut();
        let mut out = std::mem::take(&mut st.out);
        out.clear();
        let r = match conn_mut(st, h) {
            Some(c) => drain_tls(&mut c.tls, &mut out),
            None => Err("no such connection".into()),
        };
        st.out = out;
        match r {
            Ok(()) => st.out.len() as i32,
            Err(e) => fail(st, e),
        }
    })
}

/// Decrypted application data received so far, at `wt_out_ptr`.
#[no_mangle]
pub extern "C" fn wt_take_plain(h: u32) -> i32 {
    STATE.with(|s| {
        let st = &mut *s.borrow_mut();
        let plain = match conn_mut(st, h) {
            Some(c) => std::mem::take(&mut c.plain),
            None => return fail(st, "no such connection".into()),
        };
        st.out = plain;
        st.out.len() as i32
    })
}

/// Bit 1: handshaking. Bit 2: the peer sent close_notify. Bit 4: output waiting.
#[no_mangle]
pub extern "C" fn wt_state(h: u32) -> i32 {
    STATE.with(|s| {
        let st = &mut *s.borrow_mut();
        match conn_mut(st, h) {
            Some(c) => (c.tls.is_handshaking() as i32) | ((c.peer_closed as i32) << 1) | ((c.tls.wants_write() as i32) << 2),
            None => fail(st, "no such connection".into()),
        }
    })
}

/// The negotiated protocol: 0x0303 (TLS 1.2), 0x0304 (TLS 1.3), 0 before the handshake.
#[no_mangle]
pub extern "C" fn wt_version(h: u32) -> i32 {
    STATE.with(|s| {
        let st = &mut *s.borrow_mut();
        match conn_mut(st, h) {
            Some(c) => c.tls.protocol_version().map(|v| u16::from(v) as i32).unwrap_or(0),
            None => fail(st, "no such connection".into()),
        }
    })
}

/// Queue close_notify (taken with `wt_take_tls`).
#[no_mangle]
pub extern "C" fn wt_close(h: u32) -> i32 {
    STATE.with(|s| {
        let st = &mut *s.borrow_mut();
        match conn_mut(st, h) {
            Some(c) => {
                c.tls.send_close_notify();
                0
            }
            None => fail(st, "no such connection".into()),
        }
    })
}

/// Forget the connection.
#[no_mangle]
pub extern "C" fn wt_drop(h: u32) -> i32 {
    STATE.with(|s| {
        let st = &mut *s.borrow_mut();
        st.conns.remove(&h);
        0
    })
}
