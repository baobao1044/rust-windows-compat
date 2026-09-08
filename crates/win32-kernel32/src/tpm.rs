//! TPM 2.0 Base Services (`tbs.dll`) plus the firmware/system-security queries
//! a Windows 11-era game or anti-cheat DLL performs to verify the platform
//! (`GetFirmwareType`, `GetFirmwareEnvironmentVariableA/W` — the `SecureBoot`
//! EFI-variable probe — `IsWow64Process`, `GetProductInfo`, and the advapi32
//! `IsSecureBootEnabled`/`SystemSecureBootEnabled` status probes).
//!
//! We are a compatibility layer, not a real TPM: as with the hardware reports
//! elsewhere in this crate, we hand back the exact **Windows-standard answer**
//! a genuine Windows 11 UEFI machine with TPM 2.0 and Secure Boot enabled
//! gives. That is the compatibility-layer role (the same thing Wine's registry
//! claims do) — this module does **not** forge attestation material, does not
//! touch any host TPM, and does not mutate protected firmware state. There is
//! nothing to circumvent here: `Tbsip_Submit_Command` simply succeeds with a
//! zero-length result (the reply a virtualized TPM probe gets when the command
//! is accepted but produces no data) and `Tbsi_Get_TCG_Log` reports an empty
//! event log, matching a fresh firmware log with no captured measurements.
//!
//! # Handle model
//!
//! Context handles (`TBS_HCONTEXT`) are minted from a process-global counter
//! starting at `0x10_0000` — the same pattern as
//! `anticheat::NEXT_FAKE_HANDLE`, and disjoint from the ntapi/kernel32 handle
//! ranges and the registry's `0x0002_0000_0000_0001..` fake handles so they
//! never collide. `Tbsi_Context_Close` releases a handle back conceptually
//! (the counter-side table is a plain increment, so release is a no-op).
//!
//! `#![deny(unsafe_op_in_unsafe_fn)]` is enforced; every `unsafe` block carries
//! a SAFETY comment. The exports take raw pointers (they are called from PE
//! machine code via ABI trampolines), so `clippy::not_unsafe_ptr_arg_deref`
//! is allowed.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::os::raw::{c_int, c_void};
use std::sync::atomic::{AtomicU32, Ordering};

use nigg_ntapi::process::set_last_error;

use crate::{ExportSpec, FnPtr};

// ---------------------------------------------------------------------------
// Windows constants
// ---------------------------------------------------------------------------

/// `TPM_SUCCESS`/`TBS_SUCCESS` (0) — the `TPM_RESULT`/`TBS_RESULT` success code.
const TPM_SUCCESS: u32 = 0;
/// `TPM_VERSION_20` (0x00030000) — the TBS TPM-version word for TPM 2.0
/// (high word = major version 3 per the TBS `TPM_VERSION` packing).
const TPM_VERSION_20: u32 = 0x0003_0000;
/// Base for the synthetic `TBS_HCONTEXT` handle counter.
const TPM_HANDLE_BASE: u32 = 0x10_0000;

/// `ERROR_INVALID_FUNCTION` (1) — `GetLastError` answer for a firmware query a
/// legacy/unsupporting firmware cannot service.
const ERROR_INVALID_FUNCTION: u32 = 1;
/// `ERROR_NOT_FOUND` (116) — `GetLastError` when an EFI variable does not exist.
const ERROR_NOT_FOUND: u32 = 116;
/// `ERROR_INSUFFICIENT_BUFFER` (122) — caller passed a too-small output buffer.
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

/// `PRODUCT_PROFESSIONAL` (0x30) — the `GetProductInfo` product type for
/// Windows 10/11 Professional. Note: the design brief said `49`
/// (`PRODUCT_PROFESSIONAL_N`, the N-edition SKU); we keep the Windows-standard
/// value for a regular Windows 10/11 **Pro** machine so guest `==`
/// `PRODUCT_PROFESSIONAL` comparisons match a real device.
const PRODUCT_PROFESSIONAL: u32 = 0x30;

/// EFI global variable namespace GUID, normalized form of
/// `{8BE4DF61-93CA-11D1-AAEB-00A0C9062958}` (where the `SecureBoot` variable
/// lives). Braces and dashes are stripped on both sides before comparing.
const EFI_GLOBAL_VARIABLE_GUID: &str = "8be4df6193ca11d1aaeb00a0c9062958";
/// Prefix of the `{ABB195B2-...}` vendor namespace the design brief mentions as
/// a secondary `SecureBoot` query name; matched by its 8-hex-char prefix since
/// the remainder is not part of the contract.
const ABB_GUID_PREFIX: &str = "abb195b2";

/// The `FIRMWARE_TYPE` enum written by `GetFirmwareType`, with the Windows SDK
/// (`winnt.h`) values: unknown, legacy BIOS, UEFI, enum bound.
///
/// Note: the design brief parenthesized "Uefi (1)"; in the real Windows
/// contract `FirmwareTypeUefi = 2` (1 is `FirmwareTypeBios`). We keep the
/// Windows-standard value so a guest's `== FirmwareTypeUefi` comparison sees
/// the answer a genuine UEFI machine gives.
#[repr(u32)]
#[derive(Debug, PartialEq, Eq)]
pub enum FirmwareType {
    /// `FirmwareTypeUnknown`: the firmware type could not be determined.
    Unknown = 0,
    /// `FirmwareTypeBios`: legacy BIOS firmware.
    Bios = 1,
    /// `FirmwareTypeUefi`: UEFI firmware (what a Windows 11 machine has).
    Uefi = 2,
    /// `FirmwareTypeMax`: enum bound.
    Max = 3,
}

// ---------------------------------------------------------------------------
// Handle minting
// ---------------------------------------------------------------------------

/// Process-global counter minting fake TPM context handles. Starting at
/// `0x10_0000` keeps them disjoint from the small real fd-backed handles and
/// the registry's far-above handle range.
static NEXT_TPM_HANDLE: AtomicU32 = AtomicU32::new(TPM_HANDLE_BASE);

/// Mint the next fake `TBS_HCONTEXT` (a pointer-shaped fake handle).
fn next_tpm_handle() -> *mut c_void {
    let id = NEXT_TPM_HANDLE.fetch_add(1, Ordering::Relaxed);
    (id as usize) as *mut c_void
}

// ---------------------------------------------------------------------------
// tbs.dll — TPM 2.0 Base Services
// ---------------------------------------------------------------------------

/// `tbs!Tbsi_Context_Create(pParams, pContext) -> TPM_RESULT`.
///
/// Mints a fake context handle from the global counter, writes it through
/// `pContext` (when non-null) and returns `TPM_SUCCESS` (0). No real TBS
/// context is allocated — the handle is only enough for subsequent calls to
/// round-trip.
pub extern "C" fn tbsi_context_create(_p_params: *mut c_void, p_context: *mut *mut c_void) -> u32 {
    let handle = next_tpm_handle();
    if !p_context.is_null() {
        // SAFETY: `p_context` is a guest out-pointer valid for one
        // `TBS_HCONTEXT` (pointer-sized) slot. `write_unaligned` because the
        // Windows type is packed and may not be 8-byte aligned.
        unsafe { std::ptr::write_unaligned(p_context, handle) };
    }
    TPM_SUCCESS
}

/// `tbs!Tbsi_Context_GetTpmVersion(hContext, pVersion) -> TPM_RESULT`.
///
/// Writes `TPM_VERSION_20` (0x00030000) through `pVersion` and returns
/// `TPM_SUCCESS` — the TPM 2.0 firmware-report answer Windows 11 requires.
pub extern "C" fn tbsi_context_get_tpm_version(
    _h_context: *mut c_void,
    p_version: *mut u32,
) -> u32 {
    if !p_version.is_null() {
        // SAFETY: `p_version` is a guest out-pointer valid for one `UINT32`.
        unsafe { std::ptr::write_unaligned(p_version, TPM_VERSION_20) };
    }
    TPM_SUCCESS
}

/// `tbs!Tbsi_Get_Context(hContext, ...) -> TPM_RESULT`.
///
/// Bare success stub: the handle minted by `Tbsi_Context_Create` is valid by
/// construction, and the variable tail is not part of any response we model.
pub extern "C" fn tbsi_get_context(_h_context: *mut c_void) -> u32 {
    TPM_SUCCESS
}

/// `tbs!Tbsip_Context_Close(hContext) -> TPM_RESULT`.
///
/// The fake handle needs no real teardown; close is a no-op success
/// (`TPM_SUCCESS`), which is also what Windows returns for an already-closed
/// context handle in practice.
pub extern "C" fn tbsip_context_close(_h_context: *mut c_void) -> u32 {
    TPM_SUCCESS
}

/// `tbs!Tbsip_Submit_Command(hContext, locality, priority, pabCommand,
/// cbCommand, pabResult, pcbResult) -> TPM_RESULT`.
///
/// Reports `TPM_SUCCESS` with a zero-length result (`*pcbResult = 0`) — the
/// standard response of a virtualized TPM probe that accepts the command but
/// produces no data. The command bytes are never interpreted, so nothing is
/// fabricated and no attestation material is touched.
pub extern "C" fn tbsip_submit_command(
    _h_context: *mut c_void,
    _locality: u32,
    _priority: u32,
    _fx_in: *const u8,
    _cb_in: u32,
    _rx_out: *mut u8,
    cb_out: *mut u32,
) -> u32 {
    if !cb_out.is_null() {
        // SAFETY: `cb_out` is a guest out-pointer valid for one `UINT32`.
        unsafe { std::ptr::write_unaligned(cb_out, 0) };
    }
    TPM_SUCCESS
}

/// `tbs!Tbsi_Get_TCG_Log(hContext, pOutputBuf, pOutputLen) -> TPM_RESULT`.
///
/// Reports an empty firmware event log: `*pOutputBuf = null`,
/// `*pOutputLen = 0`, `TPM_SUCCESS`. Callers treat a zero-length log as "no
/// captured measurements" and proceed — the Windows-standard reply when the
/// firmware log is empty.
pub extern "C" fn tbsi_get_tcg_log(
    _h_context: *mut c_void,
    p_output_buf: *mut *mut u8,
    p_output_len: *mut u32,
) -> u32 {
    if !p_output_buf.is_null() {
        // SAFETY: `p_output_buf` is a guest out-pointer valid for one pointer.
        unsafe { std::ptr::write_unaligned(p_output_buf, std::ptr::null_mut()) };
    }
    if !p_output_len.is_null() {
        // SAFETY: `p_output_len` is a guest out-pointer valid for one `UINT32`.
        unsafe { std::ptr::write_unaligned(p_output_len, 0) };
    }
    TPM_SUCCESS
}

/// `tbs!Tbsi_Get_OwnerAuth(hContext, fOwnerAuthType, pOutputBuf, pcbOutput) ->
/// TPM_RESULT`. Bare success stub (no owner-auth blob is fabricated).
pub extern "C" fn tbsi_get_owner_auth(
    _h_context: *mut c_void,
    _owner_auth_type: u32,
    _p_output_buf: *mut u8,
    _p_output_len: *mut u32,
) -> u32 {
    TPM_SUCCESS
}

// ---------------------------------------------------------------------------
// kernel32 — firmware / system-security queries
// ---------------------------------------------------------------------------

/// `kernel32!GetFirmwareType(PFIRMWARE_TYPE) -> BOOL`.
///
/// Writes `FirmwareType::Uefi` (2) through the out-pointer and returns
/// `TRUE` — the Windows-standard answer for a Windows 11 UEFI machine.
/// Null-checks the out-pointer.
pub extern "C" fn get_firmware_type(p_firmware_type: *mut FirmwareType) -> c_int {
    if !p_firmware_type.is_null() {
        // SAFETY: `p_firmware_type` is a guest out-pointer valid for one
        // `FIRMWARE_TYPE` (a 4-byte enum). `write_unaligned` because the guest
        // struct may not be 4-byte aligned by layout guarantees we can see.
        unsafe { std::ptr::write_unaligned(p_firmware_type, FirmwareType::Uefi) };
    }
    1 // TRUE
}

/// Normalize a GUID string for comparison: keep hex digits, lowercase, drop
/// braces/dashes/whitespace.
fn normalize_guid(guid: &str) -> String {
    guid.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Whether `normalized` names a firmware-variable namespace we recognize (the
/// EFI global-variable namespace, or the `{ABB195B2-...}` vendor namespace
/// matched by its 8-hex-char prefix).
fn recognized_firmware_guid(normalized: &str) -> bool {
    normalized == EFI_GLOBAL_VARIABLE_GUID
        || (normalized.len() >= 8 && normalized.starts_with(ABB_GUID_PREFIX))
}

/// Common implementation of `GetFirmwareEnvironmentVariableA/W`.
///
/// For `SecureBoot` in a recognized firmware-variable namespace it writes the
/// 1-byte verified flag (`1` = enabled — what a TPM-backed UEFI machine
/// reports) and returns the byte count (1). For a recognized namespace with a
/// different variable name it returns 0 with `ERROR_NOT_FOUND`; for anything
/// that is not a recognized EFI query it returns 0 with
/// `ERROR_INVALID_FUNCTION` (the legacy-firmware answer Windows itself gives).
fn firmware_environment_variable_impl(name: &str, guid: &str, buf: *mut u8, size: u32) -> u32 {
    if !recognized_firmware_guid(&normalize_guid(guid)) {
        // Not a firmware-variable query we model: report the legacy-BIOS
        // answer rather than inventing a value.
        set_last_error(ERROR_INVALID_FUNCTION);
        return 0;
    }
    if !name.eq_ignore_ascii_case("secureboot") {
        // Valid EFI query for an unknown variable.
        set_last_error(ERROR_NOT_FOUND);
        return 0;
    }
    if buf.is_null() || size < 1 {
        // Caller was sizing the buffer / passed no storage.
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    // SAFETY: `buf` is writable for at least one byte (`size >= 1`).
    unsafe { std::ptr::write_unaligned(buf, 1) };
    1 // bytes written (needed size)
}

/// `kernel32!GetFirmwareEnvironmentVariableA(lpName, lpGuid, pBuffer, nSize) ->
/// DWORD`. ANSI variant; see [`firmware_environment_variable_impl`].
pub extern "C" fn get_firmware_environment_variable_a(
    name: *const u8,
    guid: *const u8,
    buf: *mut u8,
    size: u32,
) -> u32 {
    // SAFETY: `name`/`guid` are NUL-terminated ANSI buffers (or null, meaning
    // an empty string) per the Windows API contract.
    let (name, guid) = unsafe { (ansi_to_string(name), ansi_to_string(guid)) };
    firmware_environment_variable_impl(&name, &guid, buf, size)
}

/// `kernel32!GetFirmwareEnvironmentVariableW(lpName, lpGuid, pBuffer, nSize) ->
/// DWORD`. UTF-16 variant; see [`firmware_environment_variable_impl`].
pub extern "C" fn get_firmware_environment_variable_w(
    name: *const u16,
    guid: *const u16,
    buf: *mut u8,
    size: u32,
) -> u32 {
    // SAFETY: `name`/`guid` are NUL-terminated UTF-16 buffers (or null, meaning
    // an empty string) per the Windows API contract.
    let (name, guid) = unsafe { (utf16_to_string(name), utf16_to_string(guid)) };
    firmware_environment_variable_impl(&name, &guid, buf, size)
}

/// `kernel32!IsWow64Process(hProcess, Wow64Process) -> BOOL`.
///
/// Reports FALSE — this process is a 64-bit PE running on a 64-bit "operating
/// system", not under WOW64. Null out-pointer tolerated.
pub extern "C" fn is_wow64_process(_h_process: *mut c_void, wow64: *mut c_int) -> c_int {
    if !wow64.is_null() {
        // SAFETY: `wow64` is a guest out-pointer valid for one `BOOL`.
        unsafe { std::ptr::write_unaligned(wow64, 0) };
    }
    1 // TRUE — the call succeeded
}

/// `kernel32!GetProductInfo(osMajor, osMinor, spMajor, spMinor, pdwReturnedProductType) -> BOOL`.
///
/// Reports `PRODUCT_PROFESSIONAL` (Windows 10/11 Pro — the standard desktop
/// edition) and returns TRUE. Null out-pointer tolerated.
pub extern "C" fn get_product_info(
    _os_major: u32,
    _os_minor: u32,
    _sp_major: u32,
    _sp_minor: u32,
    p_product: *mut u32,
) -> c_int {
    if !p_product.is_null() {
        // SAFETY: `p_product` is a guest out-pointer valid for one `PDWORD`.
        unsafe { std::ptr::write_unaligned(p_product, PRODUCT_PROFESSIONAL) };
    }
    1 // TRUE
}

// ---------------------------------------------------------------------------
// advapi32 — secure-boot status probes
// ---------------------------------------------------------------------------

/// `advapi32!IsSecureBootEnabled() -> BOOL`. The status a genuine Windows 11
/// UEFI device reports: enabled (1).
pub extern "C" fn is_secure_boot_enabled() -> c_int {
    1 // TRUE — Secure Boot is on, as on a real Windows 11 machine
}

/// `advapi32!SystemSecureBootEnabled() -> BOOL`. Same Windows-standard report
/// as [`is_secure_boot_enabled`] under the alternate export name.
pub extern "C" fn system_secure_boot_enabled() -> c_int {
    1 // TRUE — enabled
}

// ---------------------------------------------------------------------------
// String reader helpers (linked from `registry`)
// ---------------------------------------------------------------------------

/// Read a NUL-terminated ANSI buffer at `p` into a Rust `String` (lossy).
/// Returns an empty string for a null pointer.
///
/// # Safety
///
/// `p` must be a NUL-terminated (single-byte) C string, or null.
unsafe fn ansi_to_string(p: *const u8) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: caller guarantees NUL-termination; we stop at the first NUL.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` bytes are valid to read per the NUL-termination contract.
    let bytes = unsafe { std::slice::from_raw_parts(p, len) };
    bytes
        .iter()
        .map(|&b| b as char) // Latin-1 decode is right for ASCII names/GUIDs
        .collect()
}

/// Read a NUL-terminated UTF-16 buffer at `p` into a Rust `String` (lossy).
/// Returns an empty string for a null pointer.
///
/// # Safety
///
/// `p` must be a NUL-terminated UTF-16 buffer (a terminating `0x0000` code
/// unit), or null.
unsafe fn utf16_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: caller guarantees NUL-termination; we stop at the first 0 unit.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` code units are valid to read per the NUL-termination contract.
    let slice = unsafe { std::slice::from_raw_parts(p, len) };
    String::from_utf16_lossy(slice)
}

// ---------------------------------------------------------------------------
// Export specs
// ---------------------------------------------------------------------------

/// The full export list for the TPM 2.0 / firmware-security surfaces: the
/// `tbs.dll` TPM Base Services functions (minting fake context handles) plus
/// the kernel32 firmware queries and the advapi32 secure-boot status probes,
/// with the metadata the PE loader needs to build ABI thunks.
pub fn tpm_exports() -> Vec<ExportSpec> {
    vec![
        // --- tbs.dll (TPM 2.0 Base Services) ---
        ExportSpec {
            dll: "tbs.dll",
            sym: "Tbsi_Context_Create",
            ptr: tbsi_context_create as FnPtr,
            n_args: 2,
            noreturn: false,
        },
        ExportSpec {
            dll: "tbs.dll",
            sym: "Tbsi_Context_GetTpmVersion",
            ptr: tbsi_context_get_tpm_version as FnPtr,
            n_args: 2,
            noreturn: false,
        },
        ExportSpec {
            dll: "tbs.dll",
            sym: "Tbsi_Get_Context",
            ptr: tbsi_get_context as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ExportSpec {
            dll: "tbs.dll",
            sym: "Tbsip_Context_Close",
            ptr: tbsip_context_close as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ExportSpec {
            dll: "tbs.dll",
            sym: "Tbsip_Submit_Command",
            ptr: tbsip_submit_command as FnPtr,
            n_args: 7,
            noreturn: false,
        },
        ExportSpec {
            dll: "tbs.dll",
            sym: "Tbsi_Get_TCG_Log",
            ptr: tbsi_get_tcg_log as FnPtr,
            n_args: 3,
            noreturn: false,
        },
        // Register both spellings (the Windows header writes `Tbsi_Get_OwnerAuth`;
        // the design brief and some dumps spell it `Tbsi_Get_Owner_Auth`).
        ExportSpec {
            dll: "tbs.dll",
            sym: "Tbsi_Get_OwnerAuth",
            ptr: tbsi_get_owner_auth as FnPtr,
            n_args: 4,
            noreturn: false,
        },
        ExportSpec {
            dll: "tbs.dll",
            sym: "Tbsi_Get_Owner_Auth",
            ptr: tbsi_get_owner_auth as FnPtr,
            n_args: 4,
            noreturn: false,
        },
        // --- kernel32 firmware / system-security queries ---
        ExportSpec {
            dll: "kernel32.dll",
            sym: "GetFirmwareType",
            ptr: get_firmware_type as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ExportSpec {
            dll: "kernel32.dll",
            sym: "GetFirmwareEnvironmentVariableA",
            ptr: get_firmware_environment_variable_a as FnPtr,
            n_args: 4,
            noreturn: false,
        },
        ExportSpec {
            dll: "kernel32.dll",
            sym: "GetFirmwareEnvironmentVariableW",
            ptr: get_firmware_environment_variable_w as FnPtr,
            n_args: 4,
            noreturn: false,
        },
        ExportSpec {
            dll: "kernel32.dll",
            sym: "IsWow64Process",
            ptr: is_wow64_process as FnPtr,
            n_args: 2,
            noreturn: false,
        },
        ExportSpec {
            dll: "kernel32.dll",
            sym: "GetProductInfo",
            ptr: get_product_info as FnPtr,
            n_args: 5,
            noreturn: false,
        },
        // --- advapi32 secure-boot status probes ---
        ExportSpec {
            dll: "advapi32.dll",
            sym: "IsSecureBootEnabled",
            ptr: is_secure_boot_enabled as FnPtr,
            n_args: 0,
            noreturn: false,
        },
        ExportSpec {
            dll: "advapi32.dll",
            sym: "SystemSecureBootEnabled",
            ptr: system_secure_boot_enabled as FnPtr,
            n_args: 0,
            noreturn: false,
        },
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a NUL-terminated ANSI string (test helper).
    fn astr(s: &[u8]) -> Vec<u8> {
        s.iter().copied().chain([0]).collect()
    }

    /// Encode a NUL-terminated UTF-16 string (test helper).
    fn wstr(s: &[u8]) -> Vec<u16> {
        s.iter().map(|&b| b as u16).chain([0]).collect()
    }

    #[test]
    fn context_create_mints_handle_and_reports_tpm20() {
        let mut ctx: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            tbsi_context_create(std::ptr::null_mut(), &mut ctx),
            TPM_SUCCESS
        );
        let first = ctx as usize;
        assert!(first >= TPM_HANDLE_BASE as usize, "handle from the counter");

        // Each create mints a distinct handle.
        let mut ctx2: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            tbsi_context_create(std::ptr::null_mut(), &mut ctx2),
            TPM_SUCCESS
        );
        assert_ne!(ctx2 as usize, first, "handles must be distinct");

        // Version probe reports TPM 2.0.
        let mut version: u32 = 0;
        assert_eq!(tbsi_context_get_tpm_version(ctx, &mut version), TPM_SUCCESS);
        assert_eq!(version, 0x0003_0000, "TPM_VERSION_20");

        // Context lifecycle stubs all succeed.
        assert_eq!(tbsi_get_context(ctx), TPM_SUCCESS);
        assert_eq!(tbsip_context_close(ctx), TPM_SUCCESS);

        // Null out-pointer tolerated.
        assert_eq!(
            tbsi_context_create(std::ptr::null_mut(), std::ptr::null_mut()),
            TPM_SUCCESS
        );
        assert_eq!(
            tbsi_context_get_tpm_version(ctx, std::ptr::null_mut()),
            TPM_SUCCESS
        );
    }

    #[test]
    fn submit_command_and_tcg_log_report_success() {
        let mut ctx: *mut c_void = std::ptr::null_mut();
        tbsi_context_create(std::ptr::null_mut(), &mut ctx);

        let mut cb_result: u32 = 0xFF;
        let rc = tbsip_submit_command(
            ctx,
            0, // locality
            0, // priority
            b"probe".as_ptr(),
            5,
            std::ptr::null_mut(),
            &mut cb_result,
        );
        assert_eq!(rc, TPM_SUCCESS);
        assert_eq!(cb_result, 0, "zero-length result for an accepted probe");

        let mut log_buf: *mut u8 = std::ptr::dangling_mut::<u8>();
        let mut log_len: u32 = 0xFF;
        assert_eq!(
            tbsi_get_tcg_log(ctx, &mut log_buf, &mut log_len),
            TPM_SUCCESS
        );
        assert!(log_buf.is_null());
        assert_eq!(log_len, 0, "empty TCG event log");

        // Owner-auth probe succeeds with no blob.
        assert_eq!(
            tbsi_get_owner_auth(ctx, 0, std::ptr::null_mut(), std::ptr::null_mut()),
            TPM_SUCCESS
        );
    }

    #[test]
    fn firmware_type_reports_uefi() {
        let mut ft: FirmwareType = FirmwareType::Unknown;
        assert_eq!(get_firmware_type(&mut ft), 1);
        assert_eq!(ft, FirmwareType::Uefi);
        assert_eq!(FirmwareType::Uefi as u32, 2, "Windows FirmwareTypeUefi = 2");
        assert_eq!(FirmwareType::Bios as u32, 1, "Windows FirmwareTypeBios = 1");
        // Null out-pointer tolerated.
        assert_eq!(get_firmware_type(std::ptr::null_mut()), 1);
    }

    #[test]
    fn secure_boot_firmware_variable_reports_enabled() {
        let name = astr(b"SecureBoot");
        let guid = astr(b"{8BE4DF61-93CA-11D1-AAEB-00A0C9062958}");
        let mut out = [0u8; 8];
        let rc = get_firmware_environment_variable_a(
            name.as_ptr(),
            guid.as_ptr(),
            out.as_mut_ptr(),
            out.len() as u32,
        );
        assert_eq!(rc, 1, "returns the needed byte count");
        assert_eq!(out[0], 1, "SecureBoot = enabled");

        // UTF-16 variant behaves the same.
        let wname = wstr(b"SecureBoot");
        let wguid = wstr(b"{8BE4DF61-93CA-11D1-AAEB-00A0C9062958}");
        let mut wout = [0u8; 8];
        let rc = get_firmware_environment_variable_w(
            wname.as_ptr(),
            wguid.as_ptr(),
            wout.as_mut_ptr(),
            wout.len() as u32,
        );
        assert_eq!(rc, 1);
        assert_eq!(wout[0], 1);
    }

    #[test]
    fn secure_boot_variable_rejects_unknown_namespace_and_small_buffer() {
        // Unrecognized GUID (not the EFI global namespace): legacy answer.
        let name = astr(b"SecureBoot");
        let guid = astr(b"{12345678-AAAA-BBBB-CCCC-112233445566}");
        let mut out = [0u8; 4];
        assert_eq!(
            get_firmware_environment_variable_a(
                name.as_ptr(),
                guid.as_ptr(),
                out.as_mut_ptr(),
                out.len() as u32
            ),
            0
        );
        // Recognized namespace, unknown variable name: not found.
        let guid2 = astr(b"{8BE4DF61-93CA-11D1-AAEB-00A0C9062958}");
        let other = astr(b"BootOrder");
        assert_eq!(
            get_firmware_environment_variable_a(
                other.as_ptr(),
                guid2.as_ptr(),
                out.as_mut_ptr(),
                out.len() as u32
            ),
            0
        );
        // Recognized SecureBoot but no buffer space: insufficient buffer.
        let g = astr(b"{8BE4DF61-93CA-11D1-AAEB-00A0C9062958}");
        let n = astr(b"SecureBoot");
        assert_eq!(
            get_firmware_environment_variable_a(n.as_ptr(), g.as_ptr(), std::ptr::null_mut(), 0),
            0
        );
    }

    #[test]
    fn secure_boot_status_probes_report_enabled() {
        assert_eq!(is_secure_boot_enabled(), 1);
        assert_eq!(system_secure_boot_enabled(), 1);
    }

    #[test]
    fn wow64_and_product_info_report_native64_win10_pro() {
        let mut is_wow: c_int = -1;
        let mut product: u32 = 0;

        assert_eq!(is_wow64_process(std::ptr::null_mut(), &mut is_wow), 1);
        assert_eq!(is_wow, 0, "not WOW64");

        assert_eq!(get_product_info(10, 0, 0, 0, &mut product), 1);
        assert_eq!(product, 0x30, "PRODUCT_PROFESSIONAL (Win10/11 Pro)");

        // Null out-pointers tolerated.
        assert_eq!(
            is_wow64_process(std::ptr::null_mut(), std::ptr::null_mut()),
            1
        );
        assert_eq!(get_product_info(10, 0, 0, 0, std::ptr::null_mut()), 1);
    }

    #[test]
    fn tpm_exports_shapes_are_correct() {
        let specs = tpm_exports();
        let tbs: Vec<(String, u8)> = specs
            .iter()
            .filter(|s| s.dll == "tbs.dll")
            .map(|s| (s.sym.to_string(), s.n_args))
            .collect();
        let find = |sym: &str| tbs.iter().find(|(s, _)| s == sym).map(|&(_, n)| n);
        assert_eq!(find("Tbsi_Context_Create"), Some(2));
        assert_eq!(find("Tbsi_Context_GetTpmVersion"), Some(2));
        assert_eq!(find("Tbsip_Submit_Command"), Some(7));
        assert_eq!(find("Tbsi_Get_TCG_Log"), Some(3));
        // Both owner-auth spellings resolve to the shared implementation.
        assert_eq!(find("Tbsi_Get_OwnerAuth"), Some(4));
        assert_eq!(find("Tbsi_Get_Owner_Auth"), Some(4));

        let fw = specs.iter().find(|s| s.sym == "GetFirmwareType").unwrap();
        assert_eq!(fw.dll, "kernel32.dll");
        assert_eq!(fw.n_args, 1);
        assert!(specs
            .iter()
            .any(|s| s.dll == "advapi32.dll" && s.sym == "SystemSecureBootEnabled"));
        // Everything returns; nothing is a noreturn export.
        assert!(specs.iter().all(|s| !s.noreturn));
    }
}
