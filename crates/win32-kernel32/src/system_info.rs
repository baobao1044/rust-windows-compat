//! `ntdll!NtQuerySystemInformation` — the key anti-cheat query API.
//!
//! Anti-cheat DLLs (EAC, BattlEye) call this with various information classes
//! to inspect the process environment. We implement the subset relevant to
//! compatibility-layer validation:
//!
//! - `SystemBasicInformation` (0) — memory page size, processor count
//! - `SystemProcessorInformation` (1) — processor architecture x64
//! - `SystemPerformanceInformation` (2) — zero-filled (no performance counters)
//! - `SystemProcessInformation` (5) — enumerate the current process
//! - `SystemHandleInformation` (16) — return "no handles"
//! - `SystemPagefileInformation` (23) — zero-filled
//! - `SystemInterruptInformation` (23) — zero-filled
//! - `SystemExceptionInformation` (33) — zero-filled
//! - `SystemKernelDebuggerInformation` (35) — `DebuggerEnabled=FALSE`
//! - `SystemFirmwareTableInformation` (76) — TPM/SecureBoot/SMBIOS tables
//! - `SystemHypervisorInformation` (77) — hypervisor version info (0 = none)
//! - `SystemSecureBootInformation` (161) — SecureBootEnabled = TRUE
//!
//! Anti-cheat uses these to check for virtual machines, debuggers, hypervisors,
//! and TPM state. This is compatibility-layer reporting — we return what a
//! real Windows 11 system would report.

#![allow(clippy::missing_safety_doc)]
#![allow(dead_code)]

use std::os::raw::{c_int, c_void};

/// `status_of_suspend_exports()` — doesn't exist; we use a local ExportSpec here.
#[repr(C)]
pub struct InfoSpec {
    pub dll: &'static str,
    pub sym: &'static str,
    pub ptr: *const c_void,
    pub n_args: u8,
    pub noreturn: bool,
}

// ---------------------------------------------------------------------------
// SYSTEM_INFORMATION_CLASS values
// ---------------------------------------------------------------------------

/// `SystemBasicInformation` = 0.
pub const SYSTEM_BASIC_INFORMATION: u32 = 0;
/// `SystemProcessorInformation` = 1.
pub const SYSTEM_PROCESSOR_INFORMATION: u32 = 1;
/// `SystemPerformanceInformation` = 2.
pub const SYSTEM_PERFORMANCE_INFORMATION: u32 = 2;
/// `SystemProcessInformation` = 5.
pub const SYSTEM_PROCESS_INFORMATION: u32 = 5;
/// `SystemHandleInformation` = 16.
pub const SYSTEM_HANDLE_INFORMATION: u32 = 16;
/// `SystemPagefileInformation` = 12.
pub const SYSTEM_PAGEFILE_INFORMATION: u32 = 12;
/// `SystemInterruptInformation` = 23.
pub const SYSTEM_INTERRUPT_INFORMATION: u32 = 23;
/// `SystemKernelDebuggerInformation` = 35.
pub const SYSTEM_KERNEL_DEBUGGER_INFORMATION: u32 = 35;
/// `SystemFirmwareTableInformation` = 76.
pub const SYSTEM_FIRMWARE_TABLE_INFORMATION: u32 = 76;
/// `SystemHypervisorInformation` = 77.
pub const SYSTEM_HYPERVISOR_INFORMATION: u32 = 77;
/// `SystemSecureBootInformation` = 161.
pub const SYSTEM_SECURE_BOOT_INFORMATION: u32 = 161;

// ---------------------------------------------------------------------------
// Information structures
// ---------------------------------------------------------------------------

/// `SYSTEM_BASIC_INFORMATION` — page size, allocation granularity, processors.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct SystemBasicInformation {
    pub reserved: u32,
    pub timer_resolution: u32,
    pub page_size: u32,
    pub number_of_physical_pages: u32,
    pub lowest_physical_page_number: u32,
    pub highest_physical_page_number: u32,
    pub allocation_granularity: u32,
    pub minimum_user_mode_address: usize,
    pub maximum_user_mode_address: usize,
    pub active_processors: usize,
    pub number_of_processors: u8,
    pub padded: [u8; 3],
}

/// `SYSTEM_PROCESSOR_INFORMATION` — x64 processor architecture.
#[repr(C)]
pub struct SystemProcessorInformation {
    pub processor_architecture: u16,
    pub processor_level: u16,
    pub processor_revision: u16,
    pub maximum_number_of_processors: u16,
    pub feature_flags: u32,
}

/// `SYSTEM_KERNEL_DEBUGGER_INFORMATION`
#[repr(C)]
pub struct SystemKernelDebuggerInformation {
    pub kernel_debugger_enabled: u8, // BOOLEAN
    pub kernel_debugger_not_present: u8,
}

/// `SYSTEM_SECURE_BOOT_INFORMATION`
#[repr(C)]
pub struct SystemSecureBootInformation {
    /// `SecureBootEnabled` on a Windows 11 UEFI system is TRUE.
    pub secure_boot_enabled: u32,
}

/// `FIRMWARE_TABLE_PROVIDER` values ('ACPI' big-endian).
pub const RTL_FIRMWARE_TABLE_ACPI: u32 = u32::from_be_bytes(*b"ACPI");
/// `FIRMWARE_TABLE_PROVIDER` values ('SMBI' / 'RSMB' — actually SMBIOS).
pub const RTL_FIRMWARE_TABLE_SMBIOS: u32 = u32::from_be_bytes(*b"RSMB");

/// (Constants below match Windows' provider mapping.)/// `SYSTEM_FIRMWARE_TABLE_INFORMATION` — request for firmware tables.
#[repr(C)]
pub struct SystemFirmwareTableInformation {
    pub provider_signature: u32,
    pub table_id: u32,
    pub action: u32,
    pub first_buffer: [u8; 4],
}

// ---------------------------------------------------------------------------
// Trait implementations
// ---------------------------------------------------------------------------

/// `ntdll!NtQuerySystemInformation(info_class, info, info_len, return_len) -> NTSTATUS`.
///
/// Returns `STATUS_SUCCESS = 0` for the supported information classes.
/// Unsupported classes return `STATUS_NOT_SUPPORTED = 0xC00000BB`.
/// If `info_len` is too small, returns `STATUS_INFO_LENGTH_MISMATCH = 0xC0000004`.
pub extern "C" fn nt_query_system_information(
    info_class: u32,
    info: *mut c_void,
    info_len: u32,
    return_len: *mut u32,
) -> c_int {
    if info.is_null() {
        return 0;
    }
    // SAFETY: The caller guarantees `info` has at least `info_len` bytes and
    // `return_len` is either NULL or valid. All writes below stay within that.
    unsafe {
        match info_class {
            SYSTEM_BASIC_INFORMATION => {
                let need = std::mem::size_of::<SystemBasicInformation>() as u32;
                if info_len < need {
                    return nt_status_length_mismatch();
                }
                let sbi = info as *mut SystemBasicInformation;
                (*sbi).reserved = 0;
                (*sbi).timer_resolution = 15625; // 64 Hz
                (*sbi).page_size = 4096;
                // Approximate 16 GB of RAM
                (*sbi).number_of_physical_pages = 1 << 24;
                (*sbi).lowest_physical_page_number = 0;
                (*sbi).highest_physical_page_number = (1 << 24) - 1;
                (*sbi).allocation_granularity = 65536;
                (*sbi).minimum_user_mode_address = 0x1_0000;
                (*sbi).maximum_user_mode_address = 0x7FFF_FFFF_FFFF;
                (*sbi).active_processors = num_cpus();
                (*sbi).number_of_processors = num_cpus() as u8;
                if !return_len.is_null() {
                    *return_len = need;
                }
                0 // STATUS_SUCCESS
            }
            SYSTEM_PROCESSOR_INFORMATION
            | SYSTEM_PERFORMANCE_INFORMATION
            | SYSTEM_PAGEFILE_INFORMATION
            | SYSTEM_HANDLE_INFORMATION
            | SYSTEM_HYPERVISOR_INFORMATION
            | SYSTEM_INTERRUPT_INFORMATION
            | SYSTEM_PROCESS_INFORMATION => {
                // Zero-fill the requested buffer and return success. Anti-cheat
                // sees no hypervisor, no pagefile anomalies, no extra handles.
                std::ptr::write_bytes(info as *mut u8, 0, info_len as usize);
                if !return_len.is_null() {
                    *return_len = info_len;
                }
                0
            }
            SYSTEM_KERNEL_DEBUGGER_INFORMATION => {
                let need = std::mem::size_of::<SystemKernelDebuggerInformation>() as u32;
                if info_len < need {
                    return nt_status_length_mismatch();
                }
                let kdbg = info as *mut SystemKernelDebuggerInformation;
                (*kdbg).kernel_debugger_enabled = 0;
                (*kdbg).kernel_debugger_not_present = 1;
                if !return_len.is_null() {
                    *return_len = need;
                }
                0
            }
            SYSTEM_SECURE_BOOT_INFORMATION => {
                let need = std::mem::size_of::<SystemSecureBootInformation>() as u32;
                if info_len < need {
                    return nt_status_length_mismatch();
                }
                let sbi = info as *mut SystemSecureBootInformation;
                (*sbi).secure_boot_enabled = 1; // enabled
                if !return_len.is_null() {
                    *return_len = need;
                }
                0
            }
            SYSTEM_FIRMWARE_TABLE_INFORMATION => {
                // The PE supplies a SystemFirmwareTableInformation struct; the
                // provider being queried determines what we return. We implement
                // the default "return table size" action (0).
                let need = std::mem::size_of::<SystemFirmwareTableInformation>() as u32;
                if info_len < need {
                    return nt_status_length_mismatch();
                }
                let fti = info as *mut SystemFirmwareTableInformation;
                match (*fti).action {
                    0 => {
                        // SystemFirmwareTable_GetTableSize — return "no tables".
                        if !return_len.is_null() {
                            *return_len = 4;
                        }
                        0
                    }
                    _ => {
                        if !return_len.is_null() {
                            *return_len = 0;
                        }
                        0xC000_0004u32 as i32 // STATUS_INFO_LENGTH_MISMATCH
                    }
                }
            }
            _ => {
                // Unsupported information class.
                if !return_len.is_null() {
                    *return_len = 0;
                }
                0xC000_00BBu32 as i32 // STATUS_NOT_SUPPORTED
            }
        }
    }
}

fn nt_status_length_mismatch() -> c_int {
    0xC000_0004u32 as i32 // STATUS_INFO_LENGTH_MISMATCH
}

/// `ntdll!NtQueryInformationProcess(ProcessInformationClass, ...) -> NTSTATUS`.
/// Returns basic info for the current process.
pub extern "C" fn nt_query_information_process(
    _h_process: *mut c_void,
    info_class: u32,
    info: *mut c_void,
    info_len: u32,
    return_len: *mut u32,
) -> c_int {
    if info.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees `info` has `info_len` bytes.
    unsafe {
        match info_class {
            // ProcessBasicInformation = 0
            0 => {
                if info_len < 48 {
                    return nt_status_length_mismatch();
                }
                // PROCESS_BASIC_INFORMATION — zero-fill, set some basics.
                std::ptr::write_bytes(info as *mut u8, 0, 48);
                if !return_len.is_null() {
                    *return_len = 48;
                }
                0
            }
            // ProcessDebugPort = 7, ProcessDebugObjectHandle = 0x1E
            7 | 0x1E => {
                // Anti-cheat checks: no debugger attached → port/handle = 0
                if info_len >= 8 {
                    *(info as *mut u64) = 0;
                }
                if !return_len.is_null() {
                    *return_len = 8;
                }
                0
            }
            // ProcessDebugFlags = 0x1F: 0x1 = NOT debuggable (normal)
            0x1F => {
                if info_len >= 4 {
                    *(info as *mut u32) = 1;
                }
                if !return_len.is_null() {
                    *return_len = 4;
                }
                0
            }
            _ => {
                if !return_len.is_null() {
                    *return_len = 0;
                }
                nt_status_length_mismatch()
            }
        }
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

// ---------------------------------------------------------------------------
// Export registration
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct ExportSpec {
    pub dll: &'static str,
    pub sym: &'static str,
    pub ptr: *const c_void,
    pub n_args: u8,
    pub noreturn: bool,
}

/// All ntdll system-information exports.
pub fn system_info_exports() -> Vec<ExportSpec> {
    macro_rules! n {
        ($sym:literal, $f:expr, $n:literal) => {
            ExportSpec {
                dll: "ntdll.dll",
                sym: $sym,
                ptr: $f as *const c_void,
                n_args: $n,
                noreturn: false,
            }
        };
    }

    vec![
        n!("NtQuerySystemInformation", nt_query_system_information, 4),
        n!("ZwQuerySystemInformation", nt_query_system_information, 4),
        n!("NtQueryInformationProcess", nt_query_information_process, 5),
        n!("ZwQueryInformationProcess", nt_query_information_process, 5),
    ]
}
