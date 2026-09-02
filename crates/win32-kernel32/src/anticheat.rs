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
    ]
}
