//! Fixture PE generator for the Nigg PE loader.
//!
//! Produces a tiny valid PE32+ image with a single executable section whose entrypoint is
//! `mov eax, 42 ; ret` (bytes `B8 2A 00 00 00 C3`). The image has no imports and no
//! relocations: the entrypoint is fully position-independent. This is the M0 acceptance
//! target — the loader maps it, the runtime trampoline calls it, and the process exits 42.
//!
//! The bytes are assembled by hand rather than produced by a linker so the fixture is
//! available to host (Linux) test code without cross-compilation: the generator itself
//! builds for any target and the resulting bytes are a standalone Windows PE32+ blob.

#![allow(dead_code)]

const IMAGE_BASE: u64 = 0x140000000;
const SECTION_ALIGNMENT: u32 = 0x1000;
const FILE_ALIGNMENT: u32 = 0x200;
const ENTRY_RVA: u32 = 0x1000;
const TEXT_RVA: u32 = 0x1000;
const SIZE_OF_IMAGE: u32 = 0x2000;
const SIZE_OF_HEADERS: u32 = 0x200;
const SIZE_OF_OPTIONAL_HEADER: u16 = 240;
const NUM_DATA_DIRECTORIES: u32 = 16;

/// File offset of the PE signature (`e_lfanew`). Kept at 0x80 so there is a (zeroed)
/// DOS stub in 0x40..0x80 — goblin's parser requires `e_lfanew` to be strictly greater
/// than the DOS stub start (0x40), matching how real PE images are laid out.
const PE_SIG_OFFSET: u32 = 0x80;

/// The bytes of the minimal entrypoint: `mov eax, 42 ; ret` (sets EAX=42 and returns).
const MINIMAL_CODE: [u8; 6] = [0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3];

/// Machine type for AMD64 (`IMAGE_FILE_MACHINE_AMD64`).
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
/// `IMAGE_NT_OPTIONAL_HDR64_MAGIC` — PE32+ (64-bit).
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20B;
/// `IMAGE_SUBSYSTEM_WINDOWS_CUI` — console subsystem.
const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;
/// `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` — DEP/NX compatible.
const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
/// `IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ`.
const TEXT_CHARACTERISTICS: u32 = 0x6000_0020;

/// Build the bytes of a minimal PE32+ EXE whose entrypoint returns 42 in `eax`.
///
/// Layout:
///   0x000 DOS header (e_lfanew -> 0x80)
///   0x040..0x080 zeroed DOS stub
///   0x080 "PE\0\0" + COFF header (20 bytes)
///   0x098 optional header (PE32+, 240 bytes incl. 16 data dirs, all empty)
///   0x188 section table: one ".text" section
///   0x200 ".text" raw data: `mov eax,42 ; ret`
pub fn minimal_exit_pe() -> Vec<u8> {
    let total = (SIZE_OF_HEADERS + FILE_ALIGNMENT) as usize; // 0x200 + 0x200 = 0x400
    let mut buf = vec![0u8; total];

    // --- DOS header ---
    buf[0..2].copy_from_slice(b"MZ"); // e_magic
    buf[0x3C..0x40].copy_from_slice(&PE_SIG_OFFSET.to_le_bytes()); // e_lfanew

    // --- PE signature ---
    let sig = PE_SIG_OFFSET as usize;
    buf[sig..sig + 4].copy_from_slice(b"PE\0\0");

    // --- COFF header (20 bytes) right after the PE signature ---
    let coff = sig + 4;
    write_u16(&mut buf, coff, IMAGE_FILE_MACHINE_AMD64); // Machine
    write_u16(&mut buf, coff + 2, 1); // NumberOfSections
    write_u32(&mut buf, coff + 4, 0); // TimeDateStamp
    write_u32(&mut buf, coff + 8, 0); // PointerToSymbolTable
    write_u32(&mut buf, coff + 12, 0); // NumberOfSymbols
    write_u16(&mut buf, coff + 16, SIZE_OF_OPTIONAL_HEADER); // SizeOfOptionalHeader
    write_u16(&mut buf, coff + 18, 0x0022); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // --- Optional header (PE32+, 240 bytes) right after the COFF header ---
    let opt = coff + 20;
    let mut o = opt;
    write_u16(&mut buf, o, IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    o += 2;
    write_u8(&mut buf, o, 0);
    o += 1; // MajorLinkerVersion
    write_u8(&mut buf, o, 0);
    o += 1; // MinorLinkerVersion
    write_u32(&mut buf, o, FILE_ALIGNMENT);
    o += 4; // SizeOfCode
    write_u32(&mut buf, o, 0);
    o += 4; // SizeOfInitializedData
    write_u32(&mut buf, o, 0);
    o += 4; // SizeOfUninitializedData
    write_u32(&mut buf, o, ENTRY_RVA);
    o += 4; // AddressOfEntryPoint
    write_u32(&mut buf, o, TEXT_RVA);
    o += 4; // BaseOfCode (no BaseOfData in PE32+)
    write_u64(&mut buf, o, IMAGE_BASE);
    o += 8; // ImageBase
    write_u32(&mut buf, o, SECTION_ALIGNMENT);
    o += 4; // SectionAlignment
    write_u32(&mut buf, o, FILE_ALIGNMENT);
    o += 4; // FileAlignment
    write_u16(&mut buf, o, 6);
    o += 2; // MajorOSVersion
    write_u16(&mut buf, o, 0);
    o += 2; // MinorOSVersion
    write_u16(&mut buf, o, 0);
    o += 2; // MajorImageVersion
    write_u16(&mut buf, o, 0);
    o += 2; // MinorImageVersion
    write_u16(&mut buf, o, 6);
    o += 2; // MajorSubsystemVersion
    write_u16(&mut buf, o, 0);
    o += 2; // MinorSubsystemVersion
    write_u32(&mut buf, o, 0);
    o += 4; // Win32VersionValue
    write_u32(&mut buf, o, SIZE_OF_IMAGE);
    o += 4; // SizeOfImage
    write_u32(&mut buf, o, SIZE_OF_HEADERS);
    o += 4; // SizeOfHeaders
    write_u32(&mut buf, o, 0);
    o += 4; // CheckSum
    write_u16(&mut buf, o, IMAGE_SUBSYSTEM_WINDOWS_CUI);
    o += 2; // Subsystem
    write_u16(&mut buf, o, IMAGE_DLLCHARACTERISTICS_NX_COMPAT);
    o += 2; // DllCharacteristics (NX only — no ASLR/DYNAMIC_BASE)
    write_u64(&mut buf, o, 0x100000);
    o += 8; // SizeOfStackReserve
    write_u64(&mut buf, o, 0x1000);
    o += 8; // SizeOfStackCommit
    write_u64(&mut buf, o, 0x100000);
    o += 8; // SizeOfHeapReserve
    write_u64(&mut buf, o, 0x1000);
    o += 8; // SizeOfHeapCommit
    write_u32(&mut buf, o, 0);
    o += 4; // LoaderFlags
    write_u32(&mut buf, o, NUM_DATA_DIRECTORIES);
    o += 4; // NumberOfRvaAndSizes
    o += (NUM_DATA_DIRECTORIES as usize) * 8; // 16 empty data directories
    debug_assert_eq!(o, opt + SIZE_OF_OPTIONAL_HEADER as usize);

    // --- Section table (1 entry, 40 bytes) right after the optional header ---
    let sect = opt + SIZE_OF_OPTIONAL_HEADER as usize;
    debug_assert!(
        sect + 40 <= FILE_ALIGNMENT as usize,
        "headers must fit before raw data"
    );
    buf[sect..sect + 8].copy_from_slice(b".text\0\0\0");
    write_u32(&mut buf, sect + 8, MINIMAL_CODE.len() as u32); // VirtualSize
    write_u32(&mut buf, sect + 12, TEXT_RVA); // VirtualAddress
    write_u32(&mut buf, sect + 16, FILE_ALIGNMENT); // SizeOfRawData
    write_u32(&mut buf, sect + 20, FILE_ALIGNMENT); // PointerToRawData (0x200)
    write_u32(&mut buf, sect + 24, 0); // PointerToRelocations
    write_u32(&mut buf, sect + 28, 0); // PointerToLinenumbers
    write_u16(&mut buf, sect + 32, 0); // NumberOfRelocations
    write_u16(&mut buf, sect + 34, 0); // NumberOfLinenumbers
    write_u32(&mut buf, sect + 36, TEXT_CHARACTERISTICS); // Characteristics

    // --- Section raw data at 0x200 ---
    let raw = FILE_ALIGNMENT as usize;
    buf[raw..raw + MINIMAL_CODE.len()].copy_from_slice(&MINIMAL_CODE);

    buf
}

// ---------------------------------------------------------------------------
// M1 acceptance fixture: a PE importing kernel32!ExitProcess, called with 42.
// ---------------------------------------------------------------------------

/// Layout constants for the `minimal_exit_process_pe` fixture.
const M1_SIZE_OF_IMAGE: u32 = 0x3000;
/// `.rdata` RVA (holds the import directory, ILT, IAT, import-by-name, and DLL name).
const M1_RDATA_RVA: u32 = 0x2000;
/// Offset within `.rdata` of the import directory (1 descriptor + null terminator).
const M1_IMPORT_DIR_OFF: u32 = 0x00;
/// Size of the import directory (2 descriptors × 20 bytes).
const M1_IMPORT_DIR_SIZE: u32 = 0x28;
/// Offset within `.rdata` of the Import Lookup Table (ILT): [RVA-to-by-name, 0].
const M1_ILT_OFF: u32 = 0x28;
/// Offset within `.rdata` of the Import Address Table (IAT): [RVA-to-by-name, 0].
const M1_IAT_OFF: u32 = 0x38;
/// Offset within `.rdata` of the IMAGE_IMPORT_BY_NAME (hint + "ExitProcess\0").
const M1_BY_NAME_OFF: u32 = 0x48;
/// Offset within `.rdata` of the DLL name "kernel32.dll\0".
const M1_DLL_NAME_OFF: u32 = 0x58;

/// `IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE` for `.rdata`
/// (kept writable so the loader can write the IAT; M1 leaves it RW).
const M1_RDATA_CHARACTERISTICS: u32 = 0xC000_0040;

/// Build the bytes of a minimal PE32+ EXE that imports `kernel32!ExitProcess` and calls
/// `ExitProcess(42)` from its entrypoint.
///
/// Layout:
///   0x000 DOS header (e_lfanew -> 0x80)
///   0x080 "PE\0\0" + COFF header (20 bytes, 2 sections)
///   0x098 optional header (PE32+, 240 bytes, import dir at index 1)
///   0x188 section table: ".text" then ".rdata"
///   0x200 ".text" raw data: `mov ecx,42 ; call [rip+0x102D] ; ret`
///   0x400 ".rdata" raw data: import dir + ILT + IAT + by-name + DLL name
///
/// The entrypoint calls the IAT slot for `ExitProcess` with the Windows x64 ABI (arg1 in
/// RCX=42). The loader overwrites the IAT slot with a Win64->SysV trampoline, so the call
/// lands in our `exit_process(42)` and the process exits 42.
pub fn minimal_exit_process_pe() -> Vec<u8> {
    let total = (SIZE_OF_HEADERS + 2 * FILE_ALIGNMENT) as usize; // 0x200 + 0x400 = 0x600
    let mut buf = vec![0u8; total];

    // --- DOS header ---
    buf[0..2].copy_from_slice(b"MZ"); // e_magic
    buf[0x3C..0x40].copy_from_slice(&PE_SIG_OFFSET.to_le_bytes()); // e_lfanew

    // --- PE signature ---
    let sig = PE_SIG_OFFSET as usize;
    buf[sig..sig + 4].copy_from_slice(b"PE\0\0");

    // --- COFF header (20 bytes): 2 sections ---
    let coff = sig + 4;
    write_u16(&mut buf, coff, IMAGE_FILE_MACHINE_AMD64); // Machine
    write_u16(&mut buf, coff + 2, 2); // NumberOfSections
    write_u32(&mut buf, coff + 4, 0); // TimeDateStamp
    write_u32(&mut buf, coff + 8, 0); // PointerToSymbolTable
    write_u32(&mut buf, coff + 12, 0); // NumberOfSymbols
    write_u16(&mut buf, coff + 16, SIZE_OF_OPTIONAL_HEADER); // SizeOfOptionalHeader
    write_u16(&mut buf, coff + 18, 0x0022); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // --- Optional header (PE32+, 240 bytes) ---
    let opt = coff + 20;
    let mut o = opt;
    write_u16(&mut buf, o, IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    o += 2;
    write_u8(&mut buf, o, 0);
    o += 1; // MajorLinkerVersion
    write_u8(&mut buf, o, 0);
    o += 1; // MinorLinkerVersion
    write_u32(&mut buf, o, FILE_ALIGNMENT);
    o += 4; // SizeOfCode
    write_u32(&mut buf, o, FILE_ALIGNMENT);
    o += 4; // SizeOfInitializedData (.rdata is one file-alignment block)
    write_u32(&mut buf, o, 0);
    o += 4; // SizeOfUninitializedData
    write_u32(&mut buf, o, ENTRY_RVA);
    o += 4; // AddressOfEntryPoint
    write_u32(&mut buf, o, TEXT_RVA);
    o += 4; // BaseOfCode
    write_u64(&mut buf, o, IMAGE_BASE);
    o += 8; // ImageBase
    write_u32(&mut buf, o, SECTION_ALIGNMENT);
    o += 4; // SectionAlignment
    write_u32(&mut buf, o, FILE_ALIGNMENT);
    o += 4; // FileAlignment
    write_u16(&mut buf, o, 6);
    o += 2; // MajorOSVersion
    write_u16(&mut buf, o, 0);
    o += 2; // MinorOSVersion
    write_u16(&mut buf, o, 0);
    o += 2; // MajorImageVersion
    write_u16(&mut buf, o, 0);
    o += 2; // MinorImageVersion
    write_u16(&mut buf, o, 6);
    o += 2; // MajorSubsystemVersion
    write_u16(&mut buf, o, 0);
    o += 2; // MinorSubsystemVersion
    write_u32(&mut buf, o, 0);
    o += 4; // Win32VersionValue
    write_u32(&mut buf, o, M1_SIZE_OF_IMAGE);
    o += 4; // SizeOfImage
    write_u32(&mut buf, o, SIZE_OF_HEADERS);
    o += 4; // SizeOfHeaders
    write_u32(&mut buf, o, 0);
    o += 4; // CheckSum
    write_u16(&mut buf, o, IMAGE_SUBSYSTEM_WINDOWS_CUI);
    o += 2; // Subsystem
    write_u16(&mut buf, o, IMAGE_DLLCHARACTERISTICS_NX_COMPAT);
    o += 2; // DllCharacteristics
    write_u64(&mut buf, o, 0x100000);
    o += 8; // SizeOfStackReserve
    write_u64(&mut buf, o, 0x1000);
    o += 8; // SizeOfStackCommit
    write_u64(&mut buf, o, 0x100000);
    o += 8; // SizeOfHeapReserve
    write_u64(&mut buf, o, 0x1000);
    o += 8; // SizeOfHeapCommit
    write_u32(&mut buf, o, 0);
    o += 4; // LoaderFlags
    write_u32(&mut buf, o, NUM_DATA_DIRECTORIES);
    o += 4; // NumberOfRvaAndSizes

    // Data directory 1 = Import directory (RVA + size). The other 15 stay zero.
    // Directory 0 (Export) is at o+0; skip it. Directory 1 (Import) is at o+8.
    write_u32(&mut buf, o + 8, M1_RDATA_RVA + M1_IMPORT_DIR_OFF); // Import VirtualAddress
    write_u32(&mut buf, o + 12, M1_IMPORT_DIR_SIZE); // Import Size
    o += (NUM_DATA_DIRECTORIES as usize) * 8; // 16 data directories
    debug_assert_eq!(o, opt + SIZE_OF_OPTIONAL_HEADER as usize);

    // --- Section table (2 entries, 40 bytes each) ---
    let sect = opt + SIZE_OF_OPTIONAL_HEADER as usize;
    debug_assert!(
        sect + 80 <= FILE_ALIGNMENT as usize,
        "headers must fit before raw data"
    );
    // .text
    buf[sect..sect + 8].copy_from_slice(b".text\0\0\0");
    write_u32(&mut buf, sect + 8, FILE_ALIGNMENT); // VirtualSize
    write_u32(&mut buf, sect + 12, TEXT_RVA); // VirtualAddress
    write_u32(&mut buf, sect + 16, FILE_ALIGNMENT); // SizeOfRawData
    write_u32(&mut buf, sect + 20, FILE_ALIGNMENT); // PointerToRawData (0x200)
    write_u32(&mut buf, sect + 24, 0); // PointerToRelocations
    write_u32(&mut buf, sect + 28, 0); // PointerToLinenumbers
    write_u16(&mut buf, sect + 32, 0); // NumberOfRelocations
    write_u16(&mut buf, sect + 34, 0); // NumberOfLinenumbers
    write_u32(&mut buf, sect + 36, TEXT_CHARACTERISTICS); // Characteristics
                                                          // .rdata
    let sect2 = sect + 40;
    buf[sect2..sect2 + 8].copy_from_slice(b".rdata\0\0");
    write_u32(&mut buf, sect2 + 8, FILE_ALIGNMENT); // VirtualSize
    write_u32(&mut buf, sect2 + 12, M1_RDATA_RVA); // VirtualAddress
    write_u32(&mut buf, sect2 + 16, FILE_ALIGNMENT); // SizeOfRawData
    write_u32(&mut buf, sect2 + 20, 2 * FILE_ALIGNMENT); // PointerToRawData (0x400)
    write_u32(&mut buf, sect2 + 24, 0); // PointerToRelocations
    write_u32(&mut buf, sect2 + 28, 0); // PointerToLinenumbers
    write_u16(&mut buf, sect2 + 32, 0); // NumberOfRelocations
    write_u16(&mut buf, sect2 + 34, 0); // NumberOfLinenumbers
    write_u32(&mut buf, sect2 + 36, M1_RDATA_CHARACTERISTICS); // Characteristics

    // --- ".text" raw data at file offset 0x200 (RVA 0x1000) ---
    //   mov ecx, 42            ; B9 2A 00 00 00   (Windows x64 arg1 = RCX)
    //   call [rip + 0x102D]    ; FF 15 2D 10 00 00 (RIP after instr = 0x100B; 0x100B+0x102D = 0x2038 = IAT)
    //   ret                    ; C3
    let text = FILE_ALIGNMENT as usize; // 0x200
    let code: [u8; 12] = [
        0xB9, 0x2A, 0x00, 0x00, 0x00, // mov ecx, 42
        0xFF, 0x15, 0x2D, 0x10, 0x00, 0x00, // call [rip+0x102D] -> IAT slot at 0x2038
        0xC3, // ret (unreachable; ExitProcess never returns)
    ];
    buf[text..text + code.len()].copy_from_slice(&code);

    // --- ".rdata" raw data at file offset 0x400 (RVA 0x2000) ---
    let rdata = 2 * FILE_ALIGNMENT as usize; // 0x400
    let rdata_rva = M1_RDATA_RVA as usize;

    // Import directory: descriptor 0 (20 bytes) + null descriptor (20 bytes).
    let ilt_rva = (rdata_rva + M1_ILT_OFF as usize) as u32;
    let iat_rva = (rdata_rva + M1_IAT_OFF as usize) as u32;
    let by_name_rva = (rdata_rva + M1_BY_NAME_OFF as usize) as u32;
    let dll_name_rva = (rdata_rva + M1_DLL_NAME_OFF as usize) as u32;
    let dir = rdata + M1_IMPORT_DIR_OFF as usize;
    write_u32(&mut buf, dir, ilt_rva); // OriginalFirstThunk -> ILT
    write_u32(&mut buf, dir + 4, 0); // TimeDateStamp
    write_u32(&mut buf, dir + 8, 0); // ForwarderChain
    write_u32(&mut buf, dir + 12, dll_name_rva); // Name -> "kernel32.dll"
    write_u32(&mut buf, dir + 16, iat_rva); // FirstThunk -> IAT
                                            // Null descriptor (20 bytes) stays zero.

    // ILT: [by_name_rva, 0]
    let ilt = rdata + M1_ILT_OFF as usize;
    write_u64(&mut buf, ilt, by_name_rva as u64);
    write_u64(&mut buf, ilt + 8, 0);

    // IAT: [by_name_rva, 0] (loader overwrites entry 0 with the thunk pointer)
    let iat = rdata + M1_IAT_OFF as usize;
    write_u64(&mut buf, iat, by_name_rva as u64);
    write_u64(&mut buf, iat + 8, 0);

    // IMAGE_IMPORT_BY_NAME: hint(2) + "ExitProcess\0"
    let by_name = rdata + M1_BY_NAME_OFF as usize;
    write_u16(&mut buf, by_name, 0); // hint
    let name = b"ExitProcess\0";
    buf[by_name + 2..by_name + 2 + name.len()].copy_from_slice(name);

    // DLL name: "kernel32.dll\0"
    let dll = rdata + M1_DLL_NAME_OFF as usize;
    let dllname = b"kernel32.dll\0";
    buf[dll..dll + dllname.len()].copy_from_slice(dllname);

    buf
}

fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn write_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
fn write_u8(buf: &mut [u8], off: usize, v: u8) {
    buf[off] = v;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: the generated blob parses as a PE32+ and reports the expected entrypoint.
    #[test]
    fn minimal_pe_parses_with_goblin() {
        let bytes = minimal_exit_pe();
        let pe = goblin::pe::PE::parse(&bytes).expect("goblin should parse the minimal PE");
        assert!(pe.is_64, "minimal PE must be PE32+");
        assert_eq!(pe.image_base, IMAGE_BASE as usize);
        assert_eq!(pe.entry, ENTRY_RVA as usize);
        assert_eq!(pe.sections.len(), 1);
        assert!(pe.imports.is_empty(), "minimal PE has no imports");
    }

    /// The M1 fixture parses as a PE32+ with one import: kernel32!ExitProcess, whose IAT
    /// slot RVA matches the `call [rip+disp]` target baked into the `.text` code.
    #[test]
    fn minimal_exit_process_pe_parses_with_import() {
        let bytes = minimal_exit_process_pe();
        let pe = goblin::pe::PE::parse(&bytes).expect("goblin should parse the M1 PE");
        assert!(pe.is_64, "M1 PE must be PE32+");
        assert_eq!(pe.entry, ENTRY_RVA as usize);
        assert_eq!(pe.sections.len(), 2, "M1 PE has .text and .rdata");
        assert_eq!(pe.imports.len(), 1, "M1 PE imports exactly one symbol");
        let imp = &pe.imports[0];
        assert_eq!(imp.dll.to_lowercase(), "kernel32.dll");
        assert_eq!(imp.name, "ExitProcess");
        // The IAT slot RVA must be 0x2038 (the `call [rip+0x102D]` target).
        assert_eq!(imp.offset as u32, M1_RDATA_RVA + M1_IAT_OFF);
    }
}
