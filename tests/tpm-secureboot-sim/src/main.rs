//! TPM 2.0 / Secure Boot simulation PE.
//!
//! Simulates the Windows 11-era system-integrity probes a game or anti-cheat
//! performs at startup, validating our compatibility layer's TPM/Secure Boot
//! API surface end-to-end:
//!
//! 1. Firmware type: GetFirmwareType -> FirmwareTypeUefi (2, per winnt.h)
//! 2. Secure Boot EFI variable: GetFirmwareEnvironmentVariableA("SecureBoot",
//!    EFI global-variable GUID) -> 1 byte = 1 (enabled)
//! 3. TPM Base Services: Tbsi_Context_Create (handle) +
//!    Tbsi_Context_GetTpmVersion (TPM_VERSION_20 = 0x00030000)
//! 4. advapi32 secure-boot status: IsSecureBootEnabled / SystemSecureBootEnabled
//! 5. Native 64-bit: IsWow64Process -> not WOW64
//! 6. Windows edition: GetProductInfo -> PRODUCT_PROFESSIONAL (0x30)
//! 7. TPM command probe: Tbsip_Submit_Command, Tbsi_Get_TCG_Log, Tbsip_Context_Close
//! 8. Secure Boot registry state: HKLM\SYSTEM\...\SecureBoot\State\UEFISecureBootEnabled
//! 9. ExitProcess(0) — nonzero first-failure sentinel otherwise.

#![no_std]
#![no_main]
#![allow(dead_code)]

use core::ptr;

const ERROR_SUCCESS: i32 = 0;
/// `FIRMWARE_TYPE` / `FirmwareTypeUefi` (winnt.h).
const FIRMWARE_TYPE_UEFI: u32 = 2;
/// `TPM_VERSION_20` — the TBS TPM-version word for TPM 2.0.
const TPM_VERSION_20: u32 = 0x0003_0000;
/// `PRODUCT_PROFESSIONAL` (0x30) — Win10/11 Pro product type.
const PRODUCT_PROFESSIONAL: u32 = 0x30;
/// `HKEY_LOCAL_MACHINE` root pseudo-handle.
const HKEY_LOCAL_MACHINE: usize = 0x8000_0002;

/// `{"{8BE4DF61-93CA-11D1-AAEB-00A0C9062958}"}` — EFI global-variable namespace,
/// ANSI C-string form, as passed to GetFirmwareEnvironmentVariableA.
const EFI_GLOBAL_VARIABLE_GUID_A: &[u8] =
    b"{8BE4DF61-93CA-11D1-AAEB-00A0C9062958}\0";
/// `SecureBoot` variable name, ANSI C-string form.
const SECUREBOOT_NAME_A: &[u8] = b"SecureBoot\0";

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "C" {
    fn ExitProcess(code: u32) -> !;
    fn GetFirmwareType(ft: *mut u32) -> i32;
    fn GetFirmwareEnvironmentVariableA(
        name: *const u8,
        guid: *const u8,
        buf: *mut u8,
        size: u32,
    ) -> u32;
    fn IsWow64Process(h: *mut u8, wow64: *mut i32) -> i32;
    fn GetProductInfo(major: u32, minor: u32, sp_major: u32, sp_minor: u32, ptype: *mut u32) -> i32;
}

#[link(name = "tbs", kind = "raw-dylib")]
unsafe extern "C" {
    fn Tbsi_Context_Create(params: *mut u8, ctx: *mut *mut u8) -> u32;
    fn Tbsi_Context_GetTpmVersion(ctx: *mut u8, version: *mut u32) -> u32;
    fn Tbsip_Submit_Command(
        ctx: *mut u8,
        locality: u32,
        priority: u32,
        cmd: *const u8,
        cb_cmd: u32,
        result: *mut u8,
        cb_result: *mut u32,
    ) -> u32;
    fn Tbsi_Get_TCG_Log(ctx: *mut u8, buf: *mut *mut u8, len: *mut u32) -> u32;
    fn Tbsip_Context_Close(ctx: *mut u8) -> u32;
}

#[link(name = "advapi32", kind = "raw-dylib")]
unsafe extern "C" {
    fn IsSecureBootEnabled() -> i32;
    fn SystemSecureBootEnabled() -> i32;
    fn RegOpenKeyExW(
        hkey: usize,
        subkey: *const u16,
        reserved: u32,
        access: u32,
        result: *mut *mut u8,
    ) -> i32;
    fn RegQueryValueExW(
        hkey: *mut u8,
        name: *const u16,
        reserved: *mut u32,
        vtype: *mut u32,
        data: *mut u8,
        len: *mut u32,
    ) -> i32;
    fn RegCloseKey(hkey: *mut u8) -> i32;
}

/// Encode a NUL-terminated UTF-16 string into a fixed 260-unit buffer (ASCII
/// input only, like the other sim fixtures).
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
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

#[no_mangle]
pub unsafe extern "C" fn mainCRTStartup() {
    let exit = unsafe { try_run() };
    unsafe { ExitProcess(exit as u32) };
}

unsafe fn try_run() -> i32 {
    // 1. Firmware type — a Windows 11 machine reports UEFI.
    let mut firmware_type: u32 = 0;
    if unsafe { GetFirmwareType(&mut firmware_type) } == 0 || firmware_type != FIRMWARE_TYPE_UEFI {
        return 100;
    }

    // 2. Secure Boot EFI variable — the classic probe games use for the
    //    "Secure Boot on or off?" answer. Expect 1 byte written and == 1.
    let mut sb_buf = [0u8; 16];
    let written = unsafe {
        GetFirmwareEnvironmentVariableA(
            SECUREBOOT_NAME_A.as_ptr(),
            EFI_GLOBAL_VARIABLE_GUID_A.as_ptr(),
            sb_buf.as_mut_ptr(),
            sb_buf.len() as u32,
        )
    };
    if written != 1 || sb_buf[0] != 1 {
        return 101;
    }
    // A different variable in the same namespace must NOT be fabricated.
    let mut scratch = [0u8; 16];
    let bogus = unsafe {
        GetFirmwareEnvironmentVariableA(
            b"BootOrder\0".as_ptr(),
            EFI_GLOBAL_VARIABLE_GUID_A.as_ptr(),
            scratch.as_mut_ptr(),
            scratch.len() as u32,
        )
    };
    if bogus != 0 {
        return 103;
    }

    // 3. TPM 2.0 context — create + version probe (TPM 2.0).
    let mut ctx: *mut u8 = ptr::null_mut();
    if unsafe { Tbsi_Context_Create(ptr::null_mut(), &mut ctx) } != 0 || ctx.is_null() {
        return 104;
    }
    let mut tpm_version: u32 = 0;
    if unsafe { Tbsi_Context_GetTpmVersion(ctx, &mut tpm_version) } != 0
        || tpm_version != TPM_VERSION_20
    {
        return 105;
    }

    // 4. advapi32 secure-boot status — enabled on a real Windows 11 machine.
    if unsafe { IsSecureBootEnabled() } != 1 || unsafe { SystemSecureBootEnabled() } != 1 {
        return 106;
    }

    // 5. Native 64-bit — not running under WOW64.
    let mut is_wow64: i32 = -1;
    if unsafe { IsWow64Process(ptr::null_mut(), &mut is_wow64) } != 1 || is_wow64 != 0 {
        return 107;
    }

    // 6. Windows edition — GetProductInfo reports Windows Pro.
    let mut product: u32 = 0;
    if unsafe { GetProductInfo(10, 0, 0, 0, &mut product) } != 1 || product != PRODUCT_PROFESSIONAL
    {
        return 108;
    }

    // 7. TPM command probe — submit succeeds with a zero-length result; the
    //    TCG log is empty; the context closes cleanly.
    let mut cb_result: u32 = 0xFFFF;
    let probe_cmd = [0x00u8; 12];
    let mut probe_out = [0u8; 32];
    if unsafe {
        Tbsip_Submit_Command(
            ctx,
            0, // locality
            0, // priority
            probe_cmd.as_ptr(),
            probe_cmd.len() as u32,
            probe_out.as_mut_ptr(),
            &mut cb_result,
        )
    } != 0 || cb_result != 0 {
        return 109;
    }
    let mut log_buf: *mut u8 = core::ptr::dangling_mut::<u8>();
    let mut log_len: u32 = 0xFFFF;
    if unsafe { Tbsi_Get_TCG_Log(ctx, &mut log_buf, &mut log_len) } != 0
        || !log_buf.is_null()
        || log_len != 0
    {
        return 110;
    }
    if unsafe { Tbsip_Context_Close(ctx) } != 0 {
        return 111;
    }

    // 8. Secure Boot registry state — the seeded security-policy default must
    //    answer: UEFISecureBootEnabled = 1 (REG_DWORD).
    let subkey = wstr(b"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State");
    let mut hkey: *mut u8 = ptr::null_mut();
    let _ = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, 0x20019, &mut hkey) };
    if hkey.is_null() {
        return 112;
    }
    let value_name = wstr(b"UEFISecureBootEnabled");
    let mut vtype: u32 = 0;
    let mut data = [0u8; 4];
    let mut data_len: u32 = data.len() as u32;
    let rc = unsafe { RegQueryValueExW(hkey, value_name.as_ptr(), ptr::null_mut(), &mut vtype, data.as_mut_ptr(), &mut data_len) };
    let _ = unsafe { RegCloseKey(hkey) };
    if rc != ERROR_SUCCESS || vtype != 4 || data_len != 4 {
        return 113;
    }
    let enabled = u32::from_ne_bytes(data);
    if enabled != 1 {
        return 114;
    }

    // All platform-integrity probes answered like a genuine Windows 11 UEFI
    // machine with TPM 2.0 and Secure Boot enabled.
    0
}
