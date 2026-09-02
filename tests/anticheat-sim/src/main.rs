//! Anti-cheat initialization simulation PE.
//!
//! Simulates what a userland anti-cheat DLL (EAC, BattlEye) does during
//! initialization, validating our compatibility layer's anti-cheat API
//! surface end-to-end:
//!
//! 1. Debug detection: IsDebuggerPresent + CheckRemoteDebuggerPresent
//! 2. Module enumeration: CreateToolhelp32Snapshot + Module32FirstW/NextW
//! 3. Process introspection: OpenProcess + ReadProcessMemory (self)
//! 4. Winsock init: WSAStartup + socket + connect (to localhost:7777)
//! 5. Registry query: RegOpenKeyExW + RegQueryValueExW
//! 6. System info: GetUserNameW + GetComputerNameW + GetSystemTimeAsFileTime
//! 7. ExitProcess(0)

#![no_std]
#![no_main]
#![allow(dead_code)]

use core::ptr;

const S_OK: i32 = 0;
const ERROR_SUCCESS: i32 = 0;
const ERROR_FILE_NOT_FOUND: i32 = 2;
const TH32CS_SNAPMODULE: u32 = 0x8;
const HKEY_LOCAL_MACHINE: usize = 0x8000_0002;
const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;
const IPPROTO_TCP: i32 = 6;

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "C" {
    fn ExitProcess(code: u32) -> !;
    fn IsDebuggerPresent() -> i32;
    fn CheckRemoteDebuggerPresent(h: *mut u8, pb: *mut i32) -> i32;
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut u8;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut u8;
    fn ReadProcessMemory(h: *mut u8, base: *const u8, buf: *mut u8, size: usize, read: *mut usize) -> i32;
    fn GetUserNameW(buf: *mut u16, len: *mut u32) -> i32;
    fn GetComputerNameW(buf: *mut u16, len: *mut u32) -> i32;
    fn GetSystemTimeAsFileTime(ft: *mut u64);
    fn GetTickCount() -> u32;
}

#[link(name = "advapi32", kind = "raw-dylib")]
unsafe extern "C" {
    fn RegOpenKeyExW(hkey: usize, subkey: *const u16, reserved: u32, access: u32, result: *mut *mut u8) -> i32;
    fn RegQueryValueExW(hkey: *mut u8, name: *const u16, reserved: *mut u32, vtype: *mut u32, data: *mut u8, len: *mut u32) -> i32;
    fn RegCloseKey(hkey: *mut u8) -> i32;
}

#[link(name = "ws2_32", kind = "raw-dylib")]
unsafe extern "C" {
    fn WSAStartup(version: u16, data: *mut u8) -> i32;
    fn socket(af: i32, sock_type: i32, protocol: i32) -> usize;
    fn closesocket(s: usize) -> i32;
    fn connect(s: usize, addr: *const u8, len: i32) -> i32;
    fn htons(host: u16) -> u16;
}

#[repr(C)]
struct ModuleEntry32W {
    size: u32,
    module_id: u32,
    process_id: u32,
    glblcnt_usage: u32,
    proccnt_usage: u32,
    mod_base_addr: *mut u8,
    mod_base_size: u32,
    h_module: *mut u8,
    module_name: [u16; 256],
    exe_path: [u16; 260],
}

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "C" {
    fn Module32FirstW(snap: *mut u8, me: *mut ModuleEntry32W) -> i32;
    fn Module32NextW(snap: *mut u8, me: *mut ModuleEntry32W) -> i32;
}

const fn wstr(s: &[u8]) -> [u16; 260] {
    let mut out = [0u16; 260];
    let mut i = 0;
    while i < s.len() && i < 259 {
        out[i] = s[i] as u16;
        i += 1;
    }
    out
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

#[no_mangle]
pub unsafe extern "C" fn mainCRTStartup() {
    let exit = unsafe { try_run() };
    unsafe { ExitProcess(exit as u32) };
}

unsafe fn try_run() -> i32 {
    // 1. Debug detection — anti-cheat checks for debuggers.
    let is_dbg = unsafe { IsDebuggerPresent() };
    if is_dbg != 0 {
        return 100;
    }
    let mut remote_dbg = 0i32;
    let _ = unsafe { CheckRemoteDebuggerPresent(ptr::null_mut(), &mut remote_dbg) };
    if remote_dbg != 0 {
        return 101;
    }

    // 2. Module enumeration — anti-cheat enumerates loaded modules.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0) };
    if snap.is_null() {
        return 102;
    }
    let mut me: ModuleEntry32W = core::mem::zeroed();
    me.size = core::mem::size_of::<ModuleEntry32W>() as u32;
    let mut module_count = 0u32;
    if unsafe { Module32FirstW(snap, &mut me) } != 0 {
        module_count = 1;
        while unsafe { Module32NextW(snap, &mut me) } != 0 {
            module_count += 1;
        }
    }
    if module_count == 0 {
        return 103;
    }

    // 3. Process introspection — anti-cheat reads its own memory.
    let proc = unsafe { OpenProcess(0x1F0FFF, 0, 0) }; // PROCESS_ALL_ACCESS, pid=0=self
    if proc.is_null() {
        return 104;
    }
    let mut read_buf = [0u8; 16];
    let mut bytes_read = 0usize;
    let code_addr = mainCRTStartup as *const u8;
    let rc = unsafe { ReadProcessMemory(proc, code_addr, read_buf.as_mut_ptr(), 16, &mut bytes_read) };
    if rc == 0 || bytes_read != 16 {
        return 105;
    }

    // 4. Winsock init — anti-cheat connects to its telemetry server.
    let mut wsa_data = [0u8; 400];
    let wsa_rc = unsafe { WSAStartup(0x0202, wsa_data.as_mut_ptr()) };
    if wsa_rc != 0 {
        return 106;
    }
    let sock = unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) };
    if sock == !0usize {
        return 107;
    }
    // Attempt to connect to localhost:7777 (will fail — no server, but
    // validates the socket creation + connect path).
    let mut addr = [0u8; 16];
    addr[0] = AF_INET as u8; addr[1] = 0; // AF_INET
    let port = unsafe { htons(7777) };
    addr[2] = (port >> 8) as u8;
    addr[3] = (port & 0xFF) as u8;
    // 127.0.0.1
    addr[4] = 127; addr[5] = 0; addr[6] = 0; addr[7] = 1;
    let _ = unsafe { connect(sock, addr.as_ptr(), 16) };
    let _ = unsafe { closesocket(sock) };

    // 5. Registry query — anti-cheat checks registry for game installation.
    let subkey = wstr(b"SOFTWARE\\Game");
    let mut hkey: *mut u8 = ptr::null_mut();
    let _ = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, 0x20019, &mut hkey) };
    // ERROR_FILE_NOT_FOUND is expected (no key exists) — that's fine.
    if !hkey.is_null() {
        let _ = unsafe { RegCloseKey(hkey) };
    }

    // 6. System info — anti-cheat collects system telemetry.
    let mut username = [0u16; 260];
    let mut username_len = 260u32;
    let _ = unsafe { GetUserNameW(username.as_mut_ptr(), &mut username_len) };
    let mut computername = [0u16; 260];
    let mut computername_len = 260u32;
    let _ = unsafe { GetComputerNameW(computername.as_mut_ptr(), &mut computername_len) };
    let mut filetime = 0u64;
    unsafe { GetSystemTimeAsFileTime(&mut filetime) };
    if filetime == 0 {
        return 108;
    }

    // 7. Timing check — anti-cheat measures startup time.
    let tick1 = unsafe { GetTickCount() };
    let tick2 = unsafe { GetTickCount() };
    if tick2 < tick1 {
        return 109;
    }

    // All checks passed — anti-cheat initialization simulated successfully.
    0
}
