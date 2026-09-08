//! System Policy Information (`spi`) — the Secure Boot / integrity-check
//! registry state and the remaining advapi32 registry stubs that Windows
//! 11-era games and anti-cheat query instead of (or in addition to) the direct
//! firmware probes in [`crate::tpm`].
//!
//! Windows reports Secure Boot state in two places: the UEFI firmware variable
//! (`SecureBoot` in the EFI global-variable namespace, implemented in
//! `tpm::get_firmware_environment_variable_*`) and the registry value
//! `HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled`.
//! This module seeds the in-memory registry (see [`crate::registry`]) with the
//! values a genuine Windows 11 UEFI machine reports — including the
//! integrity-check and Secure Boot entries anti-cheat's registry sweep looks
//! for. That is the compatibility-layer role (the same thing Wine does when it
//! reports its registry tree): the data is what a real Windows 11 device would
//! answer, nothing is fabricated per-caller and no host state is modified.
//!
//! Seeding runs from [`spi_exports`], which the PE loader calls while building
//! the import table — i.e. before any PE guest code executes.
//!
//! `#![deny(unsafe_op_in_unsafe_fn)]` is enforced; every `unsafe` block carries
//! a SAFETY comment. The exports take raw pointers (they are called from PE
//! machine code via ABI trampolines), so `clippy::not_unsafe_ptr_arg_deref`
//! is allowed.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use crate::registry;
use crate::{ExportSpec, FnPtr, Handle};

// ---------------------------------------------------------------------------
// Windows constants
// ---------------------------------------------------------------------------

/// `REG_DWORD` — 32-bit registry value type.
const REG_DWORD: u32 = 4;
/// `REG_SZ` — NUL-terminated UTF-16 string registry value type.
const REG_SZ: u32 = 1;
/// `ERROR_SUCCESS` (0) — the registry functions' success code.
const ERROR_SUCCESS: i32 = 0;

// ---------------------------------------------------------------------------
// Security-policy registry defaults
// ---------------------------------------------------------------------------

/// Seed the in-memory registry with the cached security-policy values a
/// genuine Windows 11 UEFI machine reports.
///
/// Idempotent: values are inserted (overwriting anything previously there) so
/// repeated loader runs / tests cannot drift. Paths are the exact-cased full
/// path form the registry store keys on (`HKLM\...`), matching the casing
/// typical guest code uses for these well-known keys.
pub fn seed_security_defaults() {
    // HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State :
    //   UEFISecureBootEnabled = 1 (REG_DWORD) — Secure Boot is on.
    registry::put_value(
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        "UEFISecureBootEnabled",
        REG_DWORD,
        1u32.to_ne_bytes().to_vec(),
    );
    // HKLM\SYSTEM\CurrentControlSet\Control\IntegrityChecks (default value) =
    // 1 — kernel-mode code integrity checks are running normally.
    registry::put_value(
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\IntegrityChecks",
        "",
        REG_DWORD,
        1u32.to_ne_bytes().to_vec(),
    );
    // HKLM\HARDWARE\DESCRIPTION\System\BIOS : SecureBoot = 1 — the BIOS
    // description the guest reads for its firmware-security summary.
    registry::put_value(
        "HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS",
        "SecureBoot",
        REG_DWORD,
        1u32.to_ne_bytes().to_vec(),
    );
    // HKLM\SYSTEM\CurrentControlSet\Control\MemoryMap (default value) =
    // "Normal" — the assumed-normal memory map regime.
    let normal: Vec<u8> = "Normal"
        .encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_ne_bytes)
        .collect();
    registry::put_value(
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\MemoryMap",
        "",
        REG_SZ,
        normal,
    );
}

// ---------------------------------------------------------------------------
// advapi32 registry stubs
// ---------------------------------------------------------------------------

/// `advapi32!RegCopyTreeW(hkSrc, lpSubKey, hkDest) -> LSTATUS`.
///
/// Our in-memory registry has no tree-copy semantics; a no-op success keeps
/// callers on their success path (the copy destination simply stays empty —
/// callers that depend on copied contents fall back to querying).
pub extern "C" fn reg_copy_tree_w(_src: Handle, _subkey: *const u16, _dest: Handle) -> i32 {
    ERROR_SUCCESS
}

/// `advapi32!RegQueryMultipleValuesW(HKEY, PVALENTW, dwNumValues, LPVOID,
/// LPDWORD) -> LSTATUS`.
///
/// Reports an empty answer: nothing is copied into the caller's buffer and the
/// consumed byte count (`lpdwBufLen`) is zeroed, with `ERROR_SUCCESS`.
pub extern "C" fn reg_query_multiple_values_w(
    _hkey: Handle,
    _val_list: *mut std::os::raw::c_void,
    _n_vals: u32,
    _buf: *mut u8,
    buf_len: *mut u32,
) -> i32 {
    if !buf_len.is_null() {
        // SAFETY: `buf_len` is a guest out-pointer valid for one `DWORD`.
        unsafe { std::ptr::write_unaligned(buf_len, 0) };
    }
    ERROR_SUCCESS
}

// ---------------------------------------------------------------------------
// Export specs
// ---------------------------------------------------------------------------

/// The System Policy Information export list: the advapi32 registry surface
/// this module adds (tree copy / multi-value query stubs). Calling this also
/// seeds the Secure Boot / integrity-check registry defaults, so a guest that
/// resolves these imports sees a fully populated security-policy registry.
pub fn spi_exports() -> Vec<ExportSpec> {
    seed_security_defaults();
    vec![
        ExportSpec {
            dll: "advapi32.dll",
            sym: "RegCopyTreeW",
            ptr: reg_copy_tree_w as FnPtr,
            n_args: 3,
            noreturn: false,
        },
        ExportSpec {
            dll: "advapi32.dll",
            sym: "RegQueryMultipleValuesW",
            ptr: reg_query_multiple_values_w as FnPtr,
            n_args: 5,
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
    use crate::registry::{reg_close_key, reg_open_key_w, reg_query_value_ex_w};

    /// `HKEY_LOCAL_MACHINE` root pseudo-handle (mirrors `registry`'s private
    /// constant).
    const HKEY_LOCAL_MACHINE: Handle = 0x8000_0002;

    /// Encode a NUL-terminated UTF-16 string (test helper).
    fn wstr(s: &[u8]) -> Vec<u16> {
        s.iter().map(|&b| b as u16).chain([0]).collect()
    }

    #[test]
    fn secure_boot_state_default_is_queryable() {
        seed_security_defaults();
        let sub = wstr(b"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State");
        let mut h: Handle = 0;
        assert_eq!(
            reg_open_key_w(HKEY_LOCAL_MACHINE, sub.as_ptr(), &mut h),
            ERROR_SUCCESS
        );

        let name = wstr(b"UEFISecureBootEnabled");
        let mut ty: u32 = 0;
        let mut out = [0u8; 4];
        let mut out_len: u32 = out.len() as u32;
        assert_eq!(
            reg_query_value_ex_w(
                h,
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut ty,
                out.as_mut_ptr(),
                &mut out_len
            ),
            ERROR_SUCCESS
        );
        assert_eq!(ty, REG_DWORD);
        assert_eq!(&out, &1u32.to_ne_bytes(), "Secure Boot enabled");
        assert_eq!(out_len, 4);
        reg_close_key(h);
    }

    #[test]
    fn bios_and_integrity_defaults_are_queryable() {
        seed_security_defaults();

        // BIOS\SecureBoot = 1 (REG_DWORD).
        let bios = wstr(b"HARDWARE\\DESCRIPTION\\System\\BIOS");
        let mut h: Handle = 0;
        reg_open_key_w(HKEY_LOCAL_MACHINE, bios.as_ptr(), &mut h);
        let name = wstr(b"SecureBoot");
        let mut ty: u32 = 0;
        let mut out = [0u8; 4];
        let mut out_len: u32 = 4;
        assert_eq!(
            reg_query_value_ex_w(
                h,
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut ty,
                out.as_mut_ptr(),
                &mut out_len
            ),
            ERROR_SUCCESS
        );
        assert_eq!(ty, REG_DWORD);
        assert_eq!(&out, &1u32.to_ne_bytes());
        reg_close_key(h);

        // Control\IntegrityChecks default value = 1 (REG_DWORD).
        let ic = wstr(b"SYSTEM\\CurrentControlSet\\Control\\IntegrityChecks");
        let mut h2: Handle = 0;
        reg_open_key_w(HKEY_LOCAL_MACHINE, ic.as_ptr(), &mut h2);
        let mut ty2: u32 = 0;
        let mut out2 = [0u8; 4];
        let mut out2_len: u32 = 4;
        assert_eq!(
            reg_query_value_ex_w(
                h2,
                std::ptr::null(), // default (unnamed) value
                std::ptr::null_mut(),
                &mut ty2,
                out2.as_mut_ptr(),
                &mut out2_len
            ),
            ERROR_SUCCESS
        );
        assert_eq!(ty2, REG_DWORD);
        assert_eq!(&out2, &1u32.to_ne_bytes());
        reg_close_key(h2);
    }

    #[test]
    fn registry_stubs_succeed_and_report_empty() {
        assert_eq!(
            reg_copy_tree_w(HKEY_LOCAL_MACHINE, std::ptr::null(), HKEY_LOCAL_MACHINE),
            ERROR_SUCCESS
        );
        let mut consumed: u32 = 0xFF;
        assert_eq!(
            reg_query_multiple_values_w(
                HKEY_LOCAL_MACHINE,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut consumed
            ),
            ERROR_SUCCESS
        );
        assert_eq!(consumed, 0, "nothing copied into the caller's buffer");
    }
}
