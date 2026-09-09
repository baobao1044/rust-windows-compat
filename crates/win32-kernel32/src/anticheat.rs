//! Anti-cheat support APIs — the process/module enumeration, debug detection,
//! and memory introspection functions that userland anti-cheat DLLs
//! (EAC, BattlEye) call during initialization.
//!
//! These are all safe, legitimate implementations:
//! - Debug detection returns FALSE (no debugger present — we are not one).
//! - Process/module enumeration returns information about the current process.
//! - ReadProcessMemory/WriteProcessMemory for self-process delegate to memcpy.
//!
//! See `docs/anti-cheat.md` for the full design and honest assessment.

#![allow(clippy::missing_safety_doc)]
#![allow(dead_code)]

use std::os::raw::{c_int, c_void};
use std::sync::atomic::{AtomicU32, Ordering};

use crate::dllload;
use crate::ExportSpec;

/// `ERROR_SUCCESS` = 0.
const ERROR_SUCCESS: u32 = 0;
/// `ERROR_NO_MORE_FILES` = 18.
const ERROR_NO_MORE_FILES: u32 = 18;
/// `ERROR_INVALID_HANDLE` = 6.
const ERROR_INVALID_HANDLE: u32 = 6;

/// `TH32CS_SNAPPROCESS` = 0x2.
const TH32CS_SNAPPROCESS: u32 = 0x2;
/// `TH32CS_SNAPMODULE` = 0x8.
const TH32CS_SNAPMODULE: u32 = 0x8;
/// `TH32CS_SNAPMODULE32` = 0x10.
const TH32CS_SNAPMODULE32: u32 = 0x10;

static NEXT_FAKE_HANDLE: AtomicU32 = AtomicU32::new(0x10_0000);

fn make_fake_handle() -> *mut c_void {
    let id = NEXT_FAKE_HANDLE.fetch_add(1, Ordering::Relaxed);
    (id as usize) as *mut c_void
}

// ---------------------------------------------------------------------------
// Debug detection — anti-cheat checks for debuggers
// ---------------------------------------------------------------------------

/// `kernel32!IsDebuggerPresent() -> BOOL`. Returns FALSE — we are not a debugger.
pub extern "C" fn is_debugger_present() -> c_int {
    0
}

/// `kernel32!CheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent) -> BOOL`.
/// Sets the output to FALSE (no remote debugger) and returns TRUE (success).
pub extern "C" fn check_remote_debugger_present(
    _h_process: *mut c_void,
    pb_present: *mut c_int,
) -> c_int {
    if !pb_present.is_null() {
        // SAFETY: the caller provides a valid writable BOOL pointer per the
        // Windows API contract.
        unsafe { *pb_present = 0 };
    }
    1 // TRUE — the call succeeded
}

/// `kernel32!OutputDebugStringA(lpData)`. No-op (no debug output receiver).
pub extern "C" fn output_debug_string_a(_data: *const u8) {}

/// `kernel32!OutputDebugStringW(lpData)`. No-op (no debug output receiver).
pub extern "C" fn output_debug_string_w(_data: *const u16) {}

// ---------------------------------------------------------------------------
// Process/module enumeration — anti-cheat enumerates loaded modules
// ---------------------------------------------------------------------------

/// `PROCESSENTRY32W` layout (Windows x64).
#[repr(C)]
pub struct ProcessEntry32W {
    pub size: u32,
    pub cnt_usage: u32,
    pub process_id: u32,
    pub default_heap_id: usize,
    pub module_id: u32,
    pub cnt_threads: u32,
    pub parent_process_id: u32,
    pub pri_class_base: i32,
    pub flags: u32,
    pub exe_file: [u16; 260],
}

/// `MODULEENTRY32W` layout (Windows x64).
#[repr(C)]
pub struct ModuleEntry32W {
    pub size: u32,
    pub module_id: u32,
    pub process_id: u32,
    pub glblcnt_usage: u32,
    pub proccnt_usage: u32,
    pub mod_base_addr: *mut u8,
    pub mod_base_size: u32,
    pub h_module: *mut c_void,
    pub module_name: [u16; 256],
    pub exe_path: [u16; 260],
}

/// Track which snapshot we returned so First/Next know what to enumerate.
static SNAPSHOT_TYPE: std::sync::OnceLock<std::sync::Mutex<u32>> = std::sync::OnceLock::new();
static SNAPSHOT_INDEX: std::sync::OnceLock<std::sync::Mutex<u32>> = std::sync::OnceLock::new();

fn snapshot_type() -> &'static std::sync::Mutex<u32> {
    SNAPSHOT_TYPE.get_or_init(|| std::sync::Mutex::new(0))
}

fn snapshot_index() -> &'static std::sync::Mutex<u32> {
    SNAPSHOT_INDEX.get_or_init(|| std::sync::Mutex::new(0))
}

/// `kernel32!CreateToolhelp32Snapshot(flags, process_id) -> HANDLE`.
/// Returns a fake handle. The flags determine what Process32First/Next or
/// Module32First/Next will enumerate.
pub extern "C" fn create_toolhelp32_snapshot(flags: u32, _process_id: u32) -> *mut c_void {
    // Record the snapshot type so First/Next know what to enumerate.
    let snap_type = if flags & TH32CS_SNAPPROCESS != 0 {
        TH32CS_SNAPPROCESS
    } else if flags & (TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32) != 0 {
        TH32CS_SNAPMODULE
    } else {
        0
    };
    *snapshot_type().lock().unwrap() = snap_type;
    *snapshot_index().lock().unwrap() = 0;
    make_fake_handle()
}

/// `kernel32!Process32FirstW(hSnapshot, lppe) -> BOOL`. Returns info about the
/// current process (the only one we model).
pub extern "C" fn process32_first_w(_h_snapshot: *mut c_void, lppe: *mut ProcessEntry32W) -> c_int {
    if lppe.is_null() {
        return 0;
    }
    *snapshot_index().lock().unwrap() = 1;
    // SAFETY: the caller provides a valid writable ProcessEntry32W per the
    // Windows API contract.
    unsafe {
        (*lppe).process_id = std::process::id();
        (*lppe).parent_process_id = std::process::id(); // approximate
        (*lppe).cnt_threads = 1;
        // Fill exe_file with "nigg-loader.exe" (ASCII-as-UTF16)
        let name = b"nigg-loader.exe";
        for (i, &b) in name.iter().enumerate() {
            if i >= 259 {
                break;
            }
            (*lppe).exe_file[i] = b as u16;
        }
        (*lppe).exe_file[name.len().min(259)] = 0;
    }
    1 // TRUE
}

/// `kernel32!Process32NextW(hSnapshot, lppe) -> BOOL`. Returns FALSE (no more
/// processes).
pub extern "C" fn process32_next_w(_h_snapshot: *mut c_void, _lppe: *mut ProcessEntry32W) -> c_int {
    0 // FALSE — no more processes
}

/// `kernel32!Module32FirstW(hSnapshot, lpme) -> BOOL`. Returns info about the
/// loaded image (the PE we loaded).
pub extern "C" fn module32_first_w(_h_snapshot: *mut c_void, lpme: *mut ModuleEntry32W) -> c_int {
    if lpme.is_null() {
        return 0;
    }
    *snapshot_index().lock().unwrap() = 1;
    // SAFETY: the caller provides a valid writable ModuleEntry32W.
    unsafe {
        (*lpme).process_id = std::process::id();
        (*lpme).mod_base_addr = 0x1_4000_0000 as *mut u8; // PE image base
        (*lpme).mod_base_size = 0x1000;
        let name = b"nigg-loader.exe";
        for (i, &b) in name.iter().enumerate() {
            if i >= 255 {
                break;
            }
            (*lpme).module_name[i] = b as u16;
        }
        (*lpme).module_name[name.len().min(255)] = 0;
    }
    1
}

/// `kernel32!Module32NextW(hSnapshot, lpme) -> BOOL`. Returns FALSE (no more).
pub extern "C" fn module32_next_w(_h_snapshot: *mut c_void, _lpme: *mut ModuleEntry32W) -> c_int {
    0
}

// ---------------------------------------------------------------------------
// Process memory — anti-cheat reads its own process memory for integrity checks
// ---------------------------------------------------------------------------

/// `kernel32!OpenProcess(access, inherit, pid) -> HANDLE`. For the current
/// process (pid == 0 or current pid), return a pseudo-handle. For others, return
/// NULL (we do not allow cross-process access).
pub extern "C" fn open_process(_access: u32, _inherit: c_int, pid: u32) -> *mut c_void {
    if pid == 0 || pid == std::process::id() {
        // Pseudo-handle for the current process on Windows is -1 (0xFFFFFFFF).
        0xFFFF_FFFF_FFFF_FFFF as *mut c_void
    } else {
        std::ptr::null_mut()
    }
}

/// `kernel32!ReadProcessMemory(hProcess, base, buf, size, read) -> BOOL`.
/// For the current process (pseudo-handle or current pid), delegate to memcpy.
/// For other processes, return FALSE.
pub extern "C" fn read_process_memory(
    h_process: *mut c_void,
    base: *const c_void,
    buf: *mut c_void,
    size: usize,
    read: *mut usize,
) -> c_int {
    // Only allow self-process reads (pseudo-handle -1).
    if h_process as usize != 0xFFFF_FFFF_FFFF_FFFF && !h_process.is_null() {
        return 0;
    }
    if base.is_null() || buf.is_null() {
        return 0;
    }
    // SAFETY: the caller guarantees `base` and `buf` are valid for `size`
    // bytes within the current process's address space.
    unsafe {
        std::ptr::copy_nonoverlapping(base, buf, size);
        if !read.is_null() {
            *read = size;
        }
    }
    1
}

/// `kernel32!WriteProcessMemory(hProcess, base, buf, size, written) -> BOOL`.
/// For the current process, delegate to memcpy.
pub extern "C" fn write_process_memory(
    h_process: *mut c_void,
    base: *mut c_void,
    buf: *const c_void,
    size: usize,
    written: *mut usize,
) -> c_int {
    if h_process as usize != 0xFFFF_FFFF_FFFF_FFFF && !h_process.is_null() {
        return 0;
    }
    if base.is_null() || buf.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees both pointers are valid in the current process.
    unsafe {
        std::ptr::copy_nonoverlapping(buf, base, size);
        if !written.is_null() {
            *written = size;
        }
    }
    1
}

// ---------------------------------------------------------------------------
// File mapping — anti-cheat maps its own DLL to checksum it
// ---------------------------------------------------------------------------

/// `kernel32!GetFileAttributesW(path) -> DWORD`. Returns
/// `FILE_ATTRIBUTE_NORMAL` (0x80) for any path (we don't have a real FS model
/// for the Windows C: drive).
pub extern "C" fn get_file_attributes_w(_path: *const u16) -> u32 {
    0x80 // FILE_ATTRIBUTE_NORMAL
}

/// `kernel32!MulDiv(n, d, d2) -> i32`. Computes `(n * d) / d2` with rounding.
pub extern "C" fn mul_div(n: i32, d: i32, d2: i32) -> i32 {
    if d2 == 0 {
        return -1;
    }
    let result = (n as i64 * d as i64) / (d2 as i64);
    result as i32
}

/// `kernel32!lstrcmpW(s1, s2) -> i32`. Case-sensitive wide-string comparison.
pub extern "C" fn lstrcmp_w(s1: *const u16, s2: *const u16) -> c_int {
    if s1.is_null() || s2.is_null() {
        return 0;
    }
    let mut i = 0usize;
    // SAFETY: both pointers are NUL-terminated wide strings per the Windows
    // API contract.
    unsafe {
        loop {
            let a = *s1.add(i);
            let b = *s2.add(i);
            if a == 0 && b == 0 {
                return 0;
            }
            if a != b {
                return if a < b { -1 } else { 1 };
            }
            i += 1;
        }
    }
}

/// `kernel32!lstrcmpiW(s1, s2) -> i32`. Case-insensitive wide-string comparison.
pub extern "C" fn lstrcmpi_w(s1: *const u16, s2: *const u16) -> c_int {
    if s1.is_null() || s2.is_null() {
        return 0;
    }
    let mut i = 0usize;
    // SAFETY: both pointers are NUL-terminated wide strings.
    unsafe {
        loop {
            let mut a = *s1.add(i);
            let mut b = *s2.add(i);
            if a == 0 && b == 0 {
                return 0;
            }
            // Simple lowercase: A-Z → a-z
            if (b'A' as u16..=b'Z' as u16).contains(&a) {
                a += 32;
            }
            if (b'A' as u16..=b'Z' as u16).contains(&b) {
                b += 32;
            }
            if a != b {
                return if a < b { -1 } else { 1 };
            }
            i += 1;
        }
    }
}

/// `kernel32!FindFirstFileW(path, find_data) -> HANDLE`. We don't implement file
/// enumeration; return `INVALID_HANDLE_VALUE` (-1) to signal "no files found".
pub extern "C" fn find_first_file_w(_path: *const u16, _find_data: *mut c_void) -> *mut c_void {
    // INVALID_HANDLE_VALUE = -1
    !0usize as *mut c_void
}

/// `kernel32!FindClose(hFind) -> BOOL`. No-op (we never returned a valid handle).
pub extern "C" fn find_close(_h_find: *mut c_void) -> c_int {
    1
}

/// `kernel32!GetLocalTime(lpSystemTime)`. Fills a `SYSTEMTIME` struct.
pub extern "C" fn get_local_time(lp_system_time: *mut u16) {
    if lp_system_time.is_null() {
        return;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    // Approximate decomposition (not calendar-accurate, but good enough for
    // apps that just read the fields).
    let days = secs / 86400;
    let rem_secs = secs % 86400;
    let hour = (rem_secs / 3600) as u16;
    let minute = ((rem_secs % 3600) / 60) as u16;
    let second = (rem_secs % 60) as u16;
    let year = 1970 + (days / 365) as u16; // approximate
    let day_of_year = (days % 365) as u16;
    let month = (day_of_year / 30 + 1).min(12);
    let day = day_of_year % 30 + 1;
    // SAFETY: the caller provides a valid 16-element u16 array (SYSTEMTIME).
    unsafe {
        *lp_system_time.add(0) = year;
        *lp_system_time.add(1) = month;
        *lp_system_time.add(2) = 0; // day of week
        *lp_system_time.add(3) = day;
        *lp_system_time.add(4) = hour;
        *lp_system_time.add(5) = minute;
        *lp_system_time.add(6) = second;
        *lp_system_time.add(7) = (now.subsec_millis()) as u16;
    }
}

/// `kernel32!GetStartupInfoA(lpStartupInfo)`. Fills a `STARTUPINFOA` with zeros.
pub extern "C" fn get_startup_info_a(lp_startup_info: *mut c_void) {
    if lp_startup_info.is_null() {
        return;
    }
    // SAFETY: STARTUPINFOA is 68 bytes on x64; zero it.
    unsafe {
        std::ptr::write_bytes(lp_startup_info as *mut u8, 0, 68);
    }
}

/// `kernel32!GetStartupInfoW(lpStartupInfo)`. Fills a `STARTUPINFOW` with zeros.
pub extern "C" fn get_startup_info_w(lp_startup_info: *mut c_void) {
    if lp_startup_info.is_null() {
        return;
    }
    // SAFETY: STARTUPINFOW is 112 bytes on x64; zero it.
    unsafe {
        std::ptr::write_bytes(lp_startup_info as *mut u8, 0, 112);
    }
}

/// `kernel32!LocalFree(h) -> HLOCAL`. Frees a local memory handle. No-op
/// (we don't track local allocations separately from heap).
pub extern "C" fn local_free(_h: *mut c_void) -> *mut c_void {
    std::ptr::null_mut()
}

/// `kernel32!SetEndOfFile(hFile) -> BOOL`. Truncates at current position.
/// For stdout/stderr, no-op; for other handles, return TRUE.
pub extern "C" fn set_end_of_file(_h_file: *mut c_void) -> c_int {
    1
}

/// `kernel32!GetCPInfoExW(code, flags, lpCPInfoEx) -> BOOL`. Returns codepage
/// info for UTF-8 (65001).
pub extern "C" fn get_cp_info_ex_w(_code: u32, _flags: u32, lp_info: *mut c_void) -> c_int {
    if lp_info.is_null() {
        return 0;
    }
    // SAFETY: CPINFOEXW is 28 bytes; zero it and set maxCharSize = 4 (UTF-8).
    unsafe {
        std::ptr::write_bytes(lp_info as *mut u8, 0, 28);
        *(lp_info as *mut u32) = 4; // maxCharSize
    }
    1
}

// ---------------------------------------------------------------------------
// advapi32 security descriptors (no-ops — enough for import resolution)
// ---------------------------------------------------------------------------

/// `advapi32!GetFileSecurityW(path, info, sd, len, needed) -> BOOL`. No-op.
pub extern "C" fn get_file_security_w(
    _path: *const u16,
    _info: u32,
    _sd: *mut c_void,
    _len: u32,
    _needed: *mut u32,
) -> c_int {
    0
}

/// `advapi32!GetSecurityDescriptorOwner(sd, owner, defaulted) -> BOOL`. No-op.
pub extern "C" fn get_security_descriptor_owner(
    _sd: *const c_void,
    _owner: *mut *mut c_void,
    _defaulted: *mut c_int,
) -> c_int {
    0
}

/// `advapi32!LookupAccountSidW(system, sid, name, name_len, domain, domain_len, use) -> BOOL`.
pub extern "C" fn lookup_account_sid_w(
    _system: *const u16,
    _sid: *const c_void,
    _name: *mut u16,
    _name_len: *mut u32,
    _domain: *mut u16,
    _domain_len: *mut u32,
    _use: *mut u32,
) -> c_int {
    0
}

/// `advapi32!RegDeleteValueW(hkey, name) -> LONG`. Returns ERROR_FILE_NOT_FOUND.
pub extern "C" fn reg_delete_value_w(_hkey: *mut c_void, _name: *const u16) -> c_int {
    2 // ERROR_FILE_NOT_FOUND
}

/// `advapi32!RegEnumKeyExW(hkey, index, name, name_len, reserved, class, class_len, ft) -> LONG`.
pub extern "C" fn reg_enum_key_ex_w(
    _hkey: *mut c_void,
    _index: u32,
    _name: *mut u16,
    _name_len: *mut u32,
    _reserved: *mut u32,
    _class: *mut u16,
    _class_len: *mut u32,
    _ft: *mut u64,
) -> c_int {
    259 // ERROR_NO_MORE_ITEMS
}

// ---------------------------------------------------------------------------
// shell32 file operations (no-ops)
// ---------------------------------------------------------------------------

/// `shell32!FindExecutableW(file, dir, result) -> HINSTANCE`. Returns NULL.
pub extern "C" fn find_executable_w(
    _file: *const u16,
    _dir: *const u16,
    _result: *mut u16,
) -> *mut c_void {
    std::ptr::null_mut()
}

/// `shell32!SHFileOperationW(lpFileOp) -> int`. Returns 0 (success).
pub extern "C" fn sh_file_operation_w(_lp_file_op: *mut c_void) -> c_int {
    0
}

/// `shell32!SHGetFileInfoW(path, attrs, psfi, cb, flags) -> DWORD`. Returns 0.
pub extern "C" fn sh_get_file_info_w(
    _path: *const u16,
    _attrs: u32,
    _psfi: *mut c_void,
    _cb: u32,
    _flags: u32,
) -> u32 {
    0
}

/// `shell32!ShellExecuteExW(lpExecInfo) -> BOOL`. Returns FALSE.
pub extern "C" fn shell_execute_ex_w(_lp_exec_info: *mut c_void) -> c_int {
    0
}

// ---------------------------------------------------------------------------
// user32 character functions
// ---------------------------------------------------------------------------

/// `user32!IsCharAlphaW(ch) -> BOOL`. Returns TRUE if a-z or A-Z.
pub extern "C" fn is_char_alpha_w(ch: u16) -> c_int {
    if (b'A' as u16..=b'Z' as u16).contains(&ch) || (b'a' as u16..=b'z' as u16).contains(&ch) {
        1
    } else {
        0
    }
}

/// `user32!CharUpperBuffW(buf, len) -> DWORD`. Uppercases in place.
pub extern "C" fn char_upper_buff_w(buf: *mut u16, len: u32) -> u32 {
    if buf.is_null() {
        return 0;
    }
    // SAFETY: the caller provides a valid buffer of `len` u16 elements.
    unsafe {
        for i in 0..len {
            let c = *buf.add(i as usize);
            if (b'a' as u16..=b'z' as u16).contains(&c) {
                *buf.add(i as usize) = c - 32;
            }
        }
    }
    len
}

/// `user32!CharNextExA(codepage, ptr, flags) -> LPCSTR`. Returns ptr+1 (or ptr if NUL).
pub extern "C" fn char_next_ex_a(_codepage: u16, ptr: *const u8, _flags: u32) -> *const u8 {
    if ptr.is_null() {
        return ptr;
    }
    // SAFETY: the caller provides a NUL-terminated C string.
    unsafe {
        if *ptr == 0 {
            ptr
        } else {
            ptr.add(1)
        }
    }
}

/// The anti-cheat + misc kernel32 exports.
pub fn anticheat_exports() -> Vec<ExportSpec> {
    macro_rules! k {
        ($sym:literal, $f:expr, $n:literal) => {
            ExportSpec {
                dll: "kernel32.dll",
                sym: $sym,
                ptr: $f as *const c_void,
                n_args: $n,
                noreturn: false,
            }
        };
    }

    vec![
        k!("IsDebuggerPresent", is_debugger_present, 0),
        k!(
            "CheckRemoteDebuggerPresent",
            check_remote_debugger_present,
            2
        ),
        k!("OutputDebugStringA", output_debug_string_a, 1),
        k!("OutputDebugStringW", output_debug_string_w, 1),
        k!("CreateToolhelp32Snapshot", create_toolhelp32_snapshot, 2),
        k!("Process32FirstW", process32_first_w, 2),
        k!("Process32NextW", process32_next_w, 2),
        k!("Module32FirstW", module32_first_w, 2),
        k!("Module32NextW", module32_next_w, 2),
        k!("OpenProcess", open_process, 3),
        k!("ReadProcessMemory", read_process_memory, 5),
        k!("WriteProcessMemory", write_process_memory, 5),
        k!("GetFileAttributesW", get_file_attributes_w, 1),
        k!("MulDiv", mul_div, 3),
        k!("lstrcmpW", lstrcmp_w, 2),
        k!("lstrcmpiW", lstrcmpi_w, 2),
        k!("FindFirstFileW", find_first_file_w, 2),
        k!("FindClose", find_close, 1),
        k!("GetLocalTime", get_local_time, 1),
        k!("GetStartupInfoA", get_startup_info_a, 1),
        k!("GetStartupInfoW", get_startup_info_w, 1),
        k!("LocalFree", local_free, 1),
        k!("SetEndOfFile", set_end_of_file, 1),
        k!("GetCPInfoExW", get_cp_info_ex_w, 3),
        // advapi32 security stubs
        ExportSpec {
            dll: "advapi32.dll",
            sym: "GetFileSecurityW",
            ptr: get_file_security_w as *const c_void,
            n_args: 5,
            noreturn: false,
        },
        ExportSpec {
            dll: "advapi32.dll",
            sym: "GetSecurityDescriptorOwner",
            ptr: get_security_descriptor_owner as *const c_void,
            n_args: 3,
            noreturn: false,
        },
        ExportSpec {
            dll: "advapi32.dll",
            sym: "LookupAccountSidW",
            ptr: lookup_account_sid_w as *const c_void,
            n_args: 7,
            noreturn: false,
        },
        ExportSpec {
            dll: "advapi32.dll",
            sym: "RegDeleteValueW",
            ptr: reg_delete_value_w as *const c_void,
            n_args: 2,
            noreturn: false,
        },
        ExportSpec {
            dll: "advapi32.dll",
            sym: "RegEnumKeyExW",
            ptr: reg_enum_key_ex_w as *const c_void,
            n_args: 8,
            noreturn: false,
        },
        // shell32 file operation stubs
        ExportSpec {
            dll: "shell32.dll",
            sym: "FindExecutableW",
            ptr: find_executable_w as *const c_void,
            n_args: 3,
            noreturn: false,
        },
        ExportSpec {
            dll: "shell32.dll",
            sym: "SHFileOperationW",
            ptr: sh_file_operation_w as *const c_void,
            n_args: 1,
            noreturn: false,
        },
        ExportSpec {
            dll: "shell32.dll",
            sym: "SHGetFileInfoW",
            ptr: sh_get_file_info_w as *const c_void,
            n_args: 5,
            noreturn: false,
        },
        ExportSpec {
            dll: "shell32.dll",
            sym: "ShellExecuteExW",
            ptr: shell_execute_ex_w as *const c_void,
            n_args: 1,
            noreturn: false,
        },
        // user32 character functions
        ExportSpec {
            dll: "user32.dll",
            sym: "IsCharAlphaW",
            ptr: is_char_alpha_w as *const c_void,
            n_args: 1,
            noreturn: false,
        },
        ExportSpec {
            dll: "user32.dll",
            sym: "CharUpperBuffW",
            ptr: char_upper_buff_w as *const c_void,
            n_args: 2,
            noreturn: false,
        },
        ExportSpec {
            dll: "user32.dll",
            sym: "CharNextExA",
            ptr: char_next_ex_a as *const c_void,
            n_args: 3,
            noreturn: false,
        },
        // System-security probes (Windows 11-era games check the platform
        // looks like a real UEFI/TPM 2.0 machine before trusting it). The
        // implementations live in `tpm` / `registry`; only the kernel32-facing
        // views are registered here as well.
        ExportSpec {
            dll: "kernel32.dll",
            sym: "GetFirmwareType",
            ptr: crate::tpm::get_firmware_type as *const c_void,
            n_args: 1,
            noreturn: false,
        },
        ExportSpec {
            dll: "advapi32.dll",
            sym: "IsSecureBootEnabled",
            ptr: crate::tpm::is_secure_boot_enabled as *const c_void,
            n_args: 0,
            noreturn: false,
        },
        ExportSpec {
            dll: "kernel32.dll",
            sym: "IsTextUnicode",
            ptr: crate::registry::is_text_unicode as *const c_void,
            n_args: 3,
            noreturn: false,
        },
        // Spotify.exe + complex app stubs
        k!("EncodePointer", encode_pointer, 1),
        // The module-loading surface delegates to `dllload` (the real loader is
        // registered there by `nigg-pe-loader` via a function-pointer bridge — kernel32
        // cannot depend on the loader crate).
        k!("LoadLibraryA", dllload::load_library_a, 1),
        k!("LoadLibraryW", dllload::load_library_w, 1),
        k!("LoadLibraryExA", dllload::load_library_ex_a, 3),
        k!("LoadLibraryExW", dllload::load_library_ex_w, 3),
        k!(
            "DisableThreadLibraryCalls",
            dllload::disable_thread_library_calls,
            1
        ),
        k!("GetProcAddress", dllload::get_proc_address, 2),
        k!("FreeLibrary", dllload::free_library, 1),
        k!("GetSystemTimeAsFileTime", get_system_time_as_file_time, 1),
        k!("CreateFileMappingW", create_file_mapping_w, 6),
        k!("MapViewOfFile", map_view_of_file, 5),
        k!("UnmapViewOfFile", unmap_view_of_file, 1),
        k!("GetUserNameW", get_user_name_w, 2),
        k!("GetComputerNameW", get_computer_name_w, 2),
        ExportSpec {
            dll: "ntdll.dll",
            sym: "RtlLookupFunctionEntry",
            ptr: rtl_lookup_function_entry as *const c_void,
            n_args: 3,
            noreturn: false,
        },
        ExportSpec {
            dll: "bcrypt.dll",
            sym: "BCryptGenRandom",
            ptr: bcrypt_gen_random as *const c_void,
            n_args: 4,
            noreturn: false,
        },
        ExportSpec {
            dll: "crypt32.dll",
            sym: "CertAddCertificateContextToStore",
            ptr: cert_add_certificate_context_to_store as *const c_void,
            n_args: 4,
            noreturn: false,
        },
        ExportSpec {
            dll: "advapi32.dll",
            sym: "CryptEncrypt",
            ptr: crypt_encrypt as *const c_void,
            n_args: 7,
            noreturn: false,
        },
        ExportSpec {
            dll: "ncrypt.dll",
            sym: "NCryptGetProperty",
            ptr: ncrypt_get_property as *const c_void,
            n_args: 6,
            noreturn: false,
        },
        ExportSpec {
            dll: "iphlpapi.dll",
            sym: "GetAdaptersInfo",
            ptr: get_adapters_info as *const c_void,
            n_args: 2,
            noreturn: false,
        },
        ExportSpec {
            dll: "gdiplus.dll",
            sym: "GdipGetImageEncoders",
            ptr: gdip_get_image_encoders as *const c_void,
            n_args: 3,
            noreturn: false,
        },
        ExportSpec {
            dll: "user32.dll",
            sym: "ReleaseDC",
            ptr: release_dc as *const c_void,
            n_args: 2,
            noreturn: false,
        },
        ExportSpec {
            dll: "gdi32.dll",
            sym: "CreateCompatibleBitmap",
            ptr: create_compatible_bitmap as *const c_void,
            n_args: 3,
            noreturn: false,
        },
        // MSVC CRT critical kernel32 functions
        k!("FlsAlloc", fls_alloc, 1),
        k!("FlsGetValue", fls_get_value, 1),
        k!("FlsSetValue", fls_set_value, 2),
        k!("FlsFree", fls_free, 1),
        k!("InitializeSListHead", initialize_slist_head, 1),
        k!("InterlockedPushEntrySList", interlocked_push_entry_slist, 2),
        k!("InterlockedPopEntrySList", interlocked_pop_entry_slist, 1),
        k!("InterlockedFlushSList", interlocked_flush_slist, 1),
        k!(
            "InitializeCriticalSectionAndSpinCount",
            initialize_critical_section_and_spin_count,
            2
        ),
        k!("GetModuleHandleExW", get_module_handle_ex_w, 3),
        k!("UnhandledExceptionFilter", unhandled_exception_filter, 1),
        k!("IsProcessorFeaturePresent", is_processor_feature_present, 1),
        k!("RtlPcToFileHeader", rtl_pc_to_file_header, 2),
        k!("RtlUnwind", rtl_unwind, 4),
        k!("GetACP", get_acp, 0),
        k!("GetCPInfo", get_cp_info, 2),
        k!("IsValidCodePage", is_valid_code_page, 1),
        k!("LCMapStringW", lc_map_string_w, 6),
        k!("IsValidLocale", is_valid_locale, 2),
        k!("GetUserDefaultLCID", get_user_default_lcid, 0),
        k!("EnumSystemLocalesW", enum_system_locales_w, 2),
        k!("GetStringTypeW", get_string_type_w, 4),
        k!("HeapSize", heap_size, 3),
        k!("TryEnterCriticalSection", try_enter_critical_section, 1),
        k!("VerSetConditionMask", ver_set_condition_mask, 3),
        k!("VerifyVersionInfoW", verify_version_info_w, 3),
        k!("FindFirstFileExW", find_first_file_ex_w, 6),
    ]
}

// ---------------------------------------------------------------------------
// Spotify.exe + complex app stubs
// ---------------------------------------------------------------------------

/// `kernel32!EncodePointer(ptr) -> PTR`. Returns ptr unchanged (no ASLR cookie).
pub extern "C" fn encode_pointer(ptr: *mut c_void) -> *mut c_void {
    ptr
}

// The `LoadLibrary*`/`GetProcAddress`/`FreeLibrary` exports now live in
// `crate::dllload` (referenced from the export table above); real DLL loading —
// map a PE, run `DllMain(DLL_PROCESS_ATTACH)`, resolve exports — is implemented
// by `nigg-pe-loader` and bridged through the function pointers in `dllload`.

/// `kernel32!GetSystemTimeAsFileTime(lpFT)`. Fills with current time.
pub extern "C" fn get_system_time_as_file_time(lp_ft: *mut u64) {
    if lp_ft.is_null() {
        return;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    // FILETIME = 100ns intervals since 1601-01-01
    let filetime = (now.as_nanos() as u64 / 100) + 116_444_736_000_000_000;
    // SAFETY: caller provides a valid u64 pointer.
    unsafe { *lp_ft = filetime };
}

/// `ntdll!RtlLookupFunctionEntry(pc, entry, base) -> PRUNTIME_FUNCTION`.
/// Walks the image's `.pdata` to find the RUNTIME_FUNCTION covering `pc`.
/// Returns NULL when no function contains the PC (e.g. it's in a jump table
/// or a non-function data region).
pub extern "C" fn rtl_lookup_function_entry(
    pc: u64,
    _entry: *mut u64,
    _base: *mut u64,
) -> *mut c_void {
    crate::dllload::call_lookup_function_entry(pc) as *mut c_void
}

/// `bcrypt!BCryptGenRandom(h, buf, len, flags) -> NTSTATUS`. Fills with random.
pub extern "C" fn bcrypt_gen_random(_h: *mut c_void, buf: *mut u8, len: u32, _flags: u32) -> i32 {
    if buf.is_null() || len == 0 {
        return 0; // STATUS_SUCCESS
    }
    // SAFETY: caller provides a valid buffer of `len` bytes.
    unsafe {
        let mut seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
        for i in 0..len as usize {
            // Simple xorshift64 PRNG
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *buf.add(i) = (seed & 0xFF) as u8;
        }
    }
    0 // STATUS_SUCCESS
}

/// `crypt32!CertAddCertificateContextToStore(...) -> BOOL`. Returns FALSE.
pub extern "C" fn cert_add_certificate_context_to_store(
    _h: *mut c_void,
    _ctx: *const c_void,
    _type: u32,
    _pp: *mut *mut c_void,
) -> c_int {
    0
}

/// `advapi32!CryptEncrypt(...) -> BOOL`. Returns FALSE.
pub extern "C" fn crypt_encrypt(
    _hkey: *mut c_void,
    _hhash: *mut c_void,
    _final: c_int,
    _flags: u32,
    _data: *mut u8,
    _len: *mut u32,
    _buf: *mut u8,
    _bufsize: u32,
) -> c_int {
    0
}

/// `ncrypt!NCryptGetProperty(...) -> NTSTATUS`. Returns error.
pub extern "C" fn ncrypt_get_property(
    _h: *mut c_void,
    _name: *const u16,
    _buf: *mut u8,
    _bufsize: u32,
    _result: *mut u32,
    _flags: u32,
) -> i32 {
    -2147483647 // NTE_BAD_HANDLE as i32
}

/// `iphlpapi!GetAdaptersInfo(buf, size) -> DWORD`. Returns ERROR_BUFFER_OVERFLOW.
pub extern "C" fn get_adapters_info(_buf: *mut u8, size: *mut u32) -> u32 {
    if !size.is_null() {
        // SAFETY: caller provides a valid u32 pointer.
        unsafe {
            *size = 0;
        }
    }
    111 // ERROR_BUFFER_OVERFLOW
}

/// `gdiplus!GdipGetImageEncoders(size, count, encoders) -> Status`. Returns error.
pub extern "C" fn gdip_get_image_encoders(
    _size: u32,
    _count: *mut u32,
    _encoders: *mut c_void,
) -> i32 {
    1 // GdiplusNotImplemented
}

/// `user32!ReleaseDC(hwnd, hdc) -> int`. Returns 1.
pub extern "C" fn release_dc(_hwnd: *mut c_void, _hdc: *mut c_void) -> c_int {
    1
}

/// `gdi32!CreateCompatibleBitmap(hdc, w, h) -> HBITMAP`. Returns fake handle.
pub extern "C" fn create_compatible_bitmap(_hdc: *mut c_void, w: c_int, h: c_int) -> *mut c_void {
    if w <= 0 || h <= 0 {
        return std::ptr::null_mut();
    }
    0x1000 as *mut c_void // fake bitmap handle
}

/// `kernel32!CreateFileMappingW(hFile, sa, protect, max_hi, max_lo, name) -> HANDLE`.
/// Returns a fake handle (we don't implement memory-mapped files).
pub extern "C" fn create_file_mapping_w(
    _h_file: *mut c_void,
    _sa: *const c_void,
    _protect: u32,
    _max_hi: u32,
    _max_lo: u32,
    _name: *const u16,
) -> *mut c_void {
    make_fake_handle()
}

/// `kernel32!MapViewOfFile(hMapping, access, off_hi, off_lo, size) -> PTR`. Returns NULL.
pub extern "C" fn map_view_of_file(
    _h_mapping: *mut c_void,
    _access: u32,
    _off_hi: u32,
    _off_lo: u32,
    _size: usize,
) -> *mut c_void {
    std::ptr::null_mut()
}

/// `kernel32!UnmapViewOfFile(base) -> BOOL`. Returns TRUE.
pub extern "C" fn unmap_view_of_file(_base: *const c_void) -> c_int {
    1
}

/// `kernel32!GetUserNameW(buf, len) -> BOOL`. Fills with "nigg".
pub extern "C" fn get_user_name_w(buf: *mut u16, len: *mut u32) -> c_int {
    if buf.is_null() || len.is_null() {
        return 0;
    }
    let name = b"nigg\0";
    let needed = name.len() as u32;
    // SAFETY: caller provides valid buffer and length pointer.
    unsafe {
        if *len < needed {
            *len = needed;
            return 0;
        }
        for (i, &b) in name.iter().enumerate() {
            *buf.add(i) = b as u16;
        }
        *len = needed - 1; // length without NUL
    }
    1
}

/// `kernel32!GetComputerNameW(buf, len) -> BOOL`. Fills with "nigg-pc".
pub extern "C" fn get_computer_name_w(buf: *mut u16, len: *mut u32) -> c_int {
    if buf.is_null() || len.is_null() {
        return 0;
    }
    let name = b"nigg-pc\0";
    let needed = name.len() as u32;
    // SAFETY: caller provides valid buffer and length pointer.
    unsafe {
        if *len < needed {
            *len = needed;
            return 0;
        }
        for (i, &b) in name.iter().enumerate() {
            *buf.add(i) = b as u16;
        }
        *len = needed - 1;
    }
    1
}

// ---------------------------------------------------------------------------
// MSVC CRT critical kernel32 functions
// ---------------------------------------------------------------------------

/// `kernel32!FlsAlloc(callback) -> DWORD`. Fiber Local Storage — like TLS for fibers.
pub extern "C" fn fls_alloc(_callback: *mut c_void) -> u32 {
    // Return a fake FLS index (0 is valid on Windows).
    0
}

/// `kernel32!FlsGetValue(index) -> PVOID`. Returns NULL (no fiber-local value).
pub extern "C" fn fls_get_value(_index: u32) -> *mut c_void {
    std::ptr::null_mut()
}

/// `kernel32!FlsSetValue(index, value) -> BOOL`. Returns TRUE.
pub extern "C" fn fls_set_value(_index: u32, _value: *const c_void) -> c_int {
    1
}

/// `kernel32!FlsFree(index) -> BOOL`. Returns TRUE.
pub extern "C" fn fls_free(_index: u32) -> c_int {
    1
}

/// `kernel32!InitializeSListHead(list) -> void`. Zero the SLIST_HEADER (8 bytes).
pub extern "C" fn initialize_slist_head(list: *mut c_void) {
    if list.is_null() {
        return;
    }
    // SAFETY: caller provides 8-byte aligned SLIST_HEADER.
    unsafe {
        std::ptr::write_bytes(list as *mut u8, 0, 16);
    }
}

/// `kernel32!InterlockedPushEntrySList(list, entry) -> PSLIST_ENTRY`. Return NULL (empty).
pub extern "C" fn interlocked_push_entry_slist(
    _list: *mut c_void,
    _entry: *mut c_void,
) -> *mut c_void {
    std::ptr::null_mut()
}

/// `kernel32!InterlockedPopEntrySList(list) -> PSLIST_ENTRY`. Return NULL (empty).
pub extern "C" fn interlocked_pop_entry_slist(_list: *mut c_void) -> *mut c_void {
    std::ptr::null_mut()
}

/// `kernel32!InterlockedFlushSList(list) -> PSLIST_ENTRY`. Return NULL (empty).
pub extern "C" fn interlocked_flush_slist(_list: *mut c_void) -> *mut c_void {
    std::ptr::null_mut()
}

/// `kernel32!InitializeCriticalSectionAndSpinCount(cs, spin) -> BOOL`. Returns TRUE.
pub extern "C" fn initialize_critical_section_and_spin_count(
    _cs: *mut c_void,
    _spin: u32,
) -> c_int {
    1
}

/// `kernel32!GetModuleHandleExW(flags, name, module) -> BOOL`. Return NULL module.
pub extern "C" fn get_module_handle_ex_w(
    _flags: u32,
    _name: *const u16,
    module: *mut *mut c_void,
) -> c_int {
    if !module.is_null() {
        unsafe {
            *module = std::ptr::null_mut();
        }
    }
    0 // FALSE — module not found
}

/// `kernel32!UnhandledExceptionFilter(exception) -> LONG`. Return EXCEPTION_CONTINUE_SEARCH (0).
pub extern "C" fn unhandled_exception_filter(_exception: *mut c_void) -> i32 {
    0 // EXCEPTION_CONTINUE_SEARCH
}

/// `kernel32!IsProcessorFeaturePresent(feature) -> BOOL`. Return TRUE for all features.
pub extern "C" fn is_processor_feature_present(_feature: u32) -> c_int {
    1
}

/// `kernel32!RtlPcToFileHeader(pc) -> PVOID`. Return NULL (we don't track module headers).
pub extern "C" fn rtl_pc_to_file_header(_pc: *const c_void, _header_size: *mut u32) -> *mut c_void {
    std::ptr::null_mut()
}

/// `kernel32!RtlUnwind(frame, target, record, value) -> void`. No-op.
pub extern "C" fn rtl_unwind(
    _frame: *mut c_void,
    _target: *mut c_void,
    _record: *mut c_void,
    _value: *mut c_void,
) {
}

/// `kernel32!GetACP() -> UINT`. Return 1252 (Western European).
pub extern "C" fn get_acp() -> u32 {
    1252
}

/// `kernel32!GetCPInfo(codepage, info) -> BOOL`. Fill CPINFO for 1252.
pub extern "C" fn get_cp_info(_codepage: u32, info: *mut c_void) -> c_int {
    if info.is_null() {
        return 0;
    }
    // CPINFO is 18 bytes: maxCharSize(4) + defaultChar(2) + leadBytes(12)
    unsafe {
        std::ptr::write_bytes(info as *mut u8, 0, 18);
    }
    // maxCharSize = 1 for single-byte codepage
    unsafe {
        *(info as *mut u32) = 1;
    }
    1 // TRUE
}

/// `kernel32!IsValidCodePage(codepage) -> BOOL`. Return TRUE.
pub extern "C" fn is_valid_code_page(_codepage: u32) -> c_int {
    1
}

/// `kernel32!LCMapStringW(locale, flags, src, src_len, dst, dst_len) -> int`. Return 0.
pub extern "C" fn lc_map_string_w(
    _locale: u32,
    _flags: u32,
    _src: *const u16,
    _src_len: c_int,
    _dst: *mut u16,
    _dst_len: c_int,
) -> c_int {
    0
}

/// `kernel32!IsValidLocale(locale, flags) -> BOOL`. Return TRUE.
pub extern "C" fn is_valid_locale(_locale: u32, _flags: u32) -> c_int {
    1
}

/// `kernel32!GetUserDefaultLCID() -> LCID`. Return 0x0409 (US English).
pub extern "C" fn get_user_default_lcid() -> u32 {
    0x0409
}

/// `kernel32!EnumSystemLocalesW(callback, flags) -> BOOL`. Return TRUE (no locales).
pub extern "C" fn enum_system_locales_w(_callback: *mut c_void, _flags: u32) -> c_int {
    1
}

/// `kernel32!GetStringTypeW(type, src, count, type_table) -> BOOL`. Return FALSE.
pub extern "C" fn get_string_type_w(
    _type: u32,
    _src: *const u16,
    _count: c_int,
    _type_table: *mut u16,
) -> c_int {
    0
}

/// `kernel32!HeapSize(heap, flags, ptr) -> SIZE_T`. Return malloc_usable_size.
pub extern "C" fn heap_size(_heap: *mut c_void, _flags: u32, ptr: *const c_void) -> usize {
    if ptr.is_null() {
        return 0;
    }
    // SAFETY: malloc_usable_size is safe with a valid pointer.
    unsafe { libc::malloc_usable_size(ptr as *mut c_void) }
}

/// `kernel32!TryEnterCriticalSection(cs) -> BOOL`. Return TRUE (acquired).
pub extern "C" fn try_enter_critical_section(_cs: *mut c_void) -> c_int {
    1
}

/// `kernel32!VerSetConditionMask(condition, type, mask) -> ULONGLONG`. Return 0.
pub extern "C" fn ver_set_condition_mask(_condition: u64, _type: u32, _mask: u8) -> u64 {
    0
}

/// `kernel32!VerifyVersionInfoW(info, type, mask) -> BOOL`. Return TRUE (matches).
pub extern "C" fn verify_version_info_w(_info: *mut c_void, _type: u32, _mask: u64) -> c_int {
    1
}

/// `kernel32!FindFirstFileExW(path, info_level, find_data, search_op, filter, flags) -> HANDLE`.
pub extern "C" fn find_first_file_ex_w(
    _path: *const u16,
    _info_level: u32,
    _find_data: *mut c_void,
    _search_op: u32,
    _filter: *mut c_void,
    _flags: u32,
) -> *mut c_void {
    // INVALID_HANDLE_VALUE
    !0usize as *mut c_void
}
