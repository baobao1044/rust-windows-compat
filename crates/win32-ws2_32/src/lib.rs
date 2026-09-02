//! Winsock2 (`ws2_32.dll`) reimplementation — the Windows Sockets API that
//! networked applications and userland anti-cheat DLLs (EAC, BattlEye) use for
//! telemetry communication.
//!
//! Each Windows socket function delegates to the equivalent POSIX socket
//! function via `libc`. The key translation is the Windows `SOCKET` type
//! (a `usize`/`u64` handle, `INVALID_SOCKET = !0`) vs the POSIX `c_int` fd.
//! We keep a simple mapping: the Windows SOCKET IS the fd (cast), since both
//! are non-negative integers on Linux.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use libc::{sockaddr, socklen_t};
use std::os::raw::{c_int, c_long, c_void};

/// `INVALID_SOCKET` — the Windows sentinel for "no socket" (`(SOCKET)-1`).
pub const INVALID_SOCKET: usize = !0usize;

/// `SOCKET_ERROR` — the Windows sentinel for a failed socket call (`-1`).
pub const SOCKET_ERROR: c_int = -1;

/// `WSADESCRIPTION_LEN` = 256, `WSASYS_STATUS_LEN` = 128. Together they
/// fill the `WSADATA` struct the PE passes to `WSAStartup`.
const WSADESCRIPTION_LEN: usize = 256;
const WSASYS_STATUS_LEN: usize = 128;

/// `WSADATA` — the struct `WSAStartup` fills. On Windows x64 it is 400 bytes
/// (version + description[257] + system_status[129] + max sockets + max
/// datagram + vendor info + ... ). We zero the whole thing and set the
/// version field.
#[repr(C)]
pub struct WsaData {
    pub w_version: u16,
    pub w_high_version: u16,
    pub i_max_sockets: u16,
    pub i_max_udp_dg: u16,
    pub lp_vendor_info: *mut c_void,
    pub sz_description: [u8; WSADESCRIPTION_LEN + 1],
    pub sz_system_status: [u8; WSASYS_STATUS_LEN + 1],
}

impl Default for WsaData {
    fn default() -> Self {
        Self {
            w_version: 0x0202, // version 2.2
            w_high_version: 0x0202,
            i_max_sockets: 0,
            i_max_udp_dg: 0,
            lp_vendor_info: std::ptr::null_mut(),
            sz_description: [0; WSADESCRIPTION_LEN + 1],
            sz_system_status: [0; WSASYS_STATUS_LEN + 1],
        }
    }
}

// ---------------------------------------------------------------------------
// WSAStartup / WSACleanup
// ---------------------------------------------------------------------------

/// `ws2_32!WSAStartup(wVersionRequested, lpWSAData) -> int`. On Linux we don't
/// need to initialize anything — sockets work directly via the kernel. We fill
/// the `WSADATA` struct with version 2.2 and return 0 (success).
pub extern "C" fn wsa_startup(_version_requested: u16, lp_wsa_data: *mut WsaData) -> c_int {
    if lp_wsa_data.is_null() {
        return SOCKET_ERROR;
    }
    // SAFETY: the caller provides a valid writable WSADATA per the Windows API.
    unsafe {
        *lp_wsa_data = WsaData::default();
    }
    0 // success
}

/// `ws2_32!WSACleanup() -> int`. No-op (no global state to clean up).
pub extern "C" fn wsa_cleanup() -> c_int {
    0
}

/// `ws2_32!WSAGetLastError() -> int`. Returns the last socket error, mapped
/// from errno.
pub extern "C" fn wsa_get_last_error() -> c_int {
    // SAFETY: `__errno_location` is thread-safe and always returns a valid
    // pointer.
    let e = unsafe { *libc::__errno_location() };
    map_errno_to_wsa(e)
}

// ---------------------------------------------------------------------------
// Socket creation
// ---------------------------------------------------------------------------

/// `ws2_32!socket(af, type, protocol) -> SOCKET`.
pub extern "C" fn socket(af: c_int, sock_type: c_int, protocol: c_int) -> usize {
    let fd = unsafe { libc::socket(af, sock_type, protocol) };
    if fd < 0 {
        return INVALID_SOCKET;
    }
    fd as usize
}

/// `ws2_32!closesocket(s) -> int`.
pub extern "C" fn closesocket(s: usize) -> c_int {
    if s == INVALID_SOCKET {
        return SOCKET_ERROR;
    }
    let rc = unsafe { libc::close(s as c_int) };
    if rc < 0 {
        SOCKET_ERROR
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

/// `ws2_32!connect(s, name, namelen) -> int`.
pub extern "C" fn connect(s: usize, name: *const sockaddr, namelen: c_int) -> c_int {
    if s == INVALID_SOCKET {
        return SOCKET_ERROR;
    }
    let rc = unsafe { libc::connect(s as c_int, name, namelen as socklen_t) };
    if rc < 0 {
        SOCKET_ERROR
    } else {
        0
    }
}

/// `ws2_32!bind(s, name, namelen) -> int`.
pub extern "C" fn bind(s: usize, name: *const sockaddr, namelen: c_int) -> c_int {
    if s == INVALID_SOCKET {
        return SOCKET_ERROR;
    }
    let rc = unsafe { libc::bind(s as c_int, name, namelen as socklen_t) };
    if rc < 0 {
        SOCKET_ERROR
    } else {
        0
    }
}

/// `ws2_32!listen(s, backlog) -> int`.
pub extern "C" fn listen(s: usize, backlog: c_int) -> c_int {
    if s == INVALID_SOCKET {
        return SOCKET_ERROR;
    }
    let rc = unsafe { libc::listen(s as c_int, backlog) };
    if rc < 0 {
        SOCKET_ERROR
    } else {
        0
    }
}

/// `ws2_32!accept(s, addr, addrlen) -> SOCKET`.
pub extern "C" fn accept(s: usize, addr: *mut sockaddr, addrlen: *mut socklen_t) -> usize {
    if s == INVALID_SOCKET {
        return INVALID_SOCKET;
    }
    let fd = unsafe { libc::accept(s as c_int, addr, addrlen) };
    if fd < 0 {
        INVALID_SOCKET
    } else {
        fd as usize
    }
}

// ---------------------------------------------------------------------------
// Data transfer
// ---------------------------------------------------------------------------

/// `ws2_32!send(s, buf, len, flags) -> int`.
pub extern "C" fn send(s: usize, buf: *const u8, len: c_int, flags: c_int) -> c_int {
    if s == INVALID_SOCKET || buf.is_null() {
        return SOCKET_ERROR;
    }
    let rc = unsafe { libc::send(s as c_int, buf as *const c_void, len as libc::size_t, flags) };
    if rc < 0 {
        SOCKET_ERROR
    } else {
        rc as c_int
    }
}

/// `ws2_32!recv(s, buf, len, flags) -> int`.
pub extern "C" fn recv(s: usize, buf: *mut u8, len: c_int, flags: c_int) -> c_int {
    if s == INVALID_SOCKET || buf.is_null() {
        return SOCKET_ERROR;
    }
    let rc = unsafe { libc::recv(s as c_int, buf as *mut c_void, len as libc::size_t, flags) };
    if rc < 0 {
        SOCKET_ERROR
    } else {
        rc as c_int
    }
}

/// `ws2_32!sendto(s, buf, len, flags, to, tolen) -> int`.
pub extern "C" fn sendto(
    s: usize,
    buf: *const u8,
    len: c_int,
    flags: c_int,
    to: *const sockaddr,
    tolen: c_int,
) -> c_int {
    if s == INVALID_SOCKET || buf.is_null() {
        return SOCKET_ERROR;
    }
    let rc = unsafe {
        libc::sendto(
            s as c_int,
            buf as *const c_void,
            len as libc::size_t,
            flags,
            to,
            tolen as socklen_t,
        )
    };
    if rc < 0 {
        SOCKET_ERROR
    } else {
        rc as c_int
    }
}

/// `ws2_32!recvfrom(s, buf, len, flags, from, fromlen) -> int`.
pub extern "C" fn recvfrom(
    s: usize,
    buf: *mut u8,
    len: c_int,
    flags: c_int,
    from: *mut sockaddr,
    fromlen: *mut socklen_t,
) -> c_int {
    if s == INVALID_SOCKET || buf.is_null() {
        return SOCKET_ERROR;
    }
    let rc = unsafe {
        libc::recvfrom(
            s as c_int,
            buf as *mut c_void,
            len as libc::size_t,
            flags,
            from,
            fromlen,
        )
    };
    if rc < 0 {
        SOCKET_ERROR
    } else {
        rc as c_int
    }
}

// ---------------------------------------------------------------------------
// Socket options
// ---------------------------------------------------------------------------

/// `ws2_32!setsockopt(s, level, name, val, len) -> int`.
pub extern "C" fn setsockopt(
    s: usize,
    level: c_int,
    optname: c_int,
    optval: *const c_void,
    optlen: c_int,
) -> c_int {
    if s == INVALID_SOCKET {
        return SOCKET_ERROR;
    }
    let rc = unsafe { libc::setsockopt(s as c_int, level, optname, optval, optlen as socklen_t) };
    if rc < 0 {
        SOCKET_ERROR
    } else {
        0
    }
}

/// `ws2_32!getsockopt(s, level, name, val, len) -> int`.
pub extern "C" fn getsockopt(
    s: usize,
    level: c_int,
    optname: c_int,
    optval: *mut c_void,
    optlen: *mut socklen_t,
) -> c_int {
    if s == INVALID_SOCKET {
        return SOCKET_ERROR;
    }
    let rc = unsafe { libc::getsockopt(s as c_int, level, optname, optval, optlen) };
    if rc < 0 {
        SOCKET_ERROR
    } else {
        0
    }
}

/// `ws2_32!ioctlsocket(s, cmd, argp) -> int`.
pub extern "C" fn ioctlsocket(s: usize, cmd: c_long, argp: *mut c_void) -> c_int {
    if s == INVALID_SOCKET {
        return SOCKET_ERROR;
    }
    // Map FIONBIO (Windows) to FIONBIO (Linux — same value 0x5421 = 21505).
    let rc = unsafe { libc::ioctl(s as c_int, cmd as _, argp) };
    if rc < 0 {
        SOCKET_ERROR
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// Name resolution
// ---------------------------------------------------------------------------

/// `ws2_32!gethostname(name, namelen) -> int`.
pub extern "C" fn gethostname(name: *mut u8, namelen: c_int) -> c_int {
    if name.is_null() {
        return SOCKET_ERROR;
    }
    let rc = unsafe { libc::gethostname(name as *mut libc::c_char, namelen as libc::size_t) };
    if rc < 0 {
        SOCKET_ERROR
    } else {
        0
    }
}

/// `ws2_32!inet_addr(cp) -> u32`. Parse an IPv4 dotted-quad string.
pub extern "C" fn inet_addr(cp: *const u8) -> u32 {
    if cp.is_null() {
        return 0xFFFF_FFFF; // INADDR_NONE
    }
    // Read the C string and parse manually.
    let mut bytes = Vec::new();
    let mut i = 0usize;
    // SAFETY: `cp` is a NUL-terminated C string per the API contract.
    unsafe {
        while *cp.add(i) != 0 && i < 256 {
            bytes.push(*cp.add(i));
            i += 1;
        }
    }
    let s = match std::str::from_utf8(&bytes) {
        Ok(s) => s,
        Err(_) => return 0xFFFF_FFFF,
    };
    match s.parse::<std::net::Ipv4Addr>() {
        Ok(addr) => u32::from(addr).to_be(),
        Err(_) => 0xFFFF_FFFF,
    }
}

/// `ws2_32!htons(hostshort) -> u16`.
pub extern "C" fn htons(hostshort: u16) -> u16 {
    hostshort.to_be()
}

/// `ws2_32!htonl(hostlong) -> u32`.
pub extern "C" fn htonl(hostlong: u32) -> u32 {
    hostlong.to_be()
}

/// `ws2_32!ntohs(netshort) -> u16`.
pub extern "C" fn ntohs(netshort: u16) -> u16 {
    u16::from_be(netshort)
}

/// `ws2_32!ntohl(netlong) -> u32`.
pub extern "C" fn ntohl(netlong: u32) -> u32 {
    u32::from_be(netlong)
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

/// `ws2_32!shutdown(s, how) -> int`.
pub extern "C" fn shutdown(s: usize, how: c_int) -> c_int {
    if s == INVALID_SOCKET {
        return SOCKET_ERROR;
    }
    let rc = unsafe { libc::shutdown(s as c_int, how) };
    if rc < 0 {
        SOCKET_ERROR
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// Select
// ---------------------------------------------------------------------------

/// `ws2_32!select(nfds, readfds, writefds, exceptfds, timeout) -> int`.
pub extern "C" fn select(
    nfds: c_int,
    readfds: *mut libc::fd_set,
    writefds: *mut libc::fd_set,
    exceptfds: *mut libc::fd_set,
    timeout: *mut libc::timeval,
) -> c_int {
    let rc = unsafe { libc::select(nfds, readfds, writefds, exceptfds, timeout) };
    if rc < 0 {
        SOCKET_ERROR
    } else {
        rc
    }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

fn map_errno_to_wsa(e: c_int) -> c_int {
    match e {
        libc::ECONNREFUSED => 10061,  // WSAECONNREFUSED
        libc::ETIMEDOUT => 10060,     // WSAETIMEDOUT
        libc::ECONNRESET => 10054,    // WSAECONNRESET
        libc::ECONNABORTED => 10053,  // WSAECONNABORTED
        libc::ENOTCONN => 10057,      // WSAENOTCONN
        libc::EADDRINUSE => 10048,    // WSAEADDRINUSE
        libc::EADDRNOTAVAIL => 10049, // WSAEADDRNOTAVAIL
        libc::ENETUNREACH => 10051,   // WSAENETUNREACH
        libc::EHOSTUNREACH => 10065,  // WSAEHOSTUNREACH
        libc::EWOULDBLOCK => 10035,   // WSAEWOULDBLOCK
        libc::EINPROGRESS => 10036,   // WSAEINPROGRESS
        _ => e,                       // pass through for unknown errors
    }
}

// ---------------------------------------------------------------------------
// Export spec
// ---------------------------------------------------------------------------

/// Export spec entry for the PE loader's import resolution.
#[repr(C)]
pub struct ExportSpec {
    pub dll: &'static str,
    pub sym: &'static str,
    pub ptr: *const c_void,
    pub n_args: u8,
    pub noreturn: bool,
}

/// All ws2_32.dll exports.
pub fn ws2_32_exports() -> Vec<ExportSpec> {
    macro_rules! w {
        ($sym:literal, $f:expr, $n:literal) => {
            ExportSpec {
                dll: "ws2_32.dll",
                sym: $sym,
                ptr: $f as *const c_void,
                n_args: $n,
                noreturn: false,
            }
        };
    }

    vec![
        w!("WSAStartup", wsa_startup, 2),
        w!("WSACleanup", wsa_cleanup, 0),
        w!("WSAGetLastError", wsa_get_last_error, 0),
        w!("socket", socket, 3),
        w!("closesocket", closesocket, 1),
        w!("connect", connect, 3),
        w!("bind", bind, 3),
        w!("listen", listen, 2),
        w!("accept", accept, 3),
        w!("send", send, 4),
        w!("recv", recv, 4),
        w!("sendto", sendto, 6),
        w!("recvfrom", recvfrom, 6),
        w!("setsockopt", setsockopt, 5),
        w!("getsockopt", getsockopt, 5),
        w!("ioctlsocket", ioctlsocket, 3),
        w!("gethostname", gethostname, 2),
        w!("inet_addr", inet_addr, 1),
        w!("htons", htons, 1),
        w!("htonl", htonl, 1),
        w!("ntohs", ntohs, 1),
        w!("ntohl", ntohl, 1),
        w!("shutdown", shutdown, 2),
        w!("select", select, 5),
    ]
}
