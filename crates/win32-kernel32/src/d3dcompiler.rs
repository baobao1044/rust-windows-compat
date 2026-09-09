//! `D3DCompiler` — bridges `D3DCompile`/`D3DCompileFromFile` from
//! `d3dcompiler_47.dll` to our pure-Rust HLSL→SPIR-V compiler.
//!
//! Games compile HLSL shaders at runtime via `D3DCompile`. Without it the
//! game cannot create its shader pipeline and aborts. Our `nigg-hlsl-compiler`
//! crate already parses HLSL and emits SPIR-V — this module bridges the
//! Windows `D3DCompile` API to it, returning a `ID3DBlob*` (a COM object
//! wrapping the SPIR-V bytecode).

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::os::raw::{c_int, c_void};

/// `S_OK` = 0.
const S_OK: c_int = 0;
/// `E_FAIL` = 0x80004005.
const E_FAIL: c_int = 0x8000_4005u32 as c_int;

/// `ID3DBlob` — a COM-like object holding shader bytecode. The game reads
/// `GetBufferPointer()` and `GetBufferSize()` to get the SPIR-V data.
///
/// Layout (first field = vtable pointer, as per COM):
/// ```text
/// struct ID3DBlob {
///     vtable: *const ID3DBlobVtbl,
///     refcount: AtomicU32,
///     buffer: *mut u8,    // the SPIR-V bytecode
///     size: usize,
/// }
/// ```
#[repr(C)]
struct D3dBlob {
    vtable: *const D3dBlobVtbl,
    refcount: std::sync::atomic::AtomicU32,
    buffer: *mut u8,
    size: usize,
}

/// `ID3DBlob` vtable: IUnknown (QueryInterface, AddRef, Release) + GetBufferPointer +
/// GetBufferSize.
#[repr(C)]
struct D3dBlobVtbl {
    query_interface: unsafe extern "C" fn(*mut c_void, *const u8, *mut *mut c_void) -> c_int,
    add_ref: unsafe extern "C" fn(*mut c_void) -> u32,
    release: unsafe extern "C" fn(*mut c_void) -> u32,
    get_buffer_pointer: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
    get_buffer_size: unsafe extern "C" fn(*mut c_void) -> usize,
}

// IUnknown methods — the game may call AddRef/Release on the blob.
unsafe extern "C" fn blob_query_interface(
    this: *mut c_void,
    _riid: *const u8,
    ppv: *mut *mut c_void,
) -> c_int {
    if !ppv.is_null() {
        // SAFETY: `this` is a live D3dBlob.
        unsafe { *ppv = this };
    }
    S_OK
}

unsafe extern "C" fn blob_add_ref(this: *mut c_void) -> u32 {
    // SAFETY: `this` is a live D3dBlob.
    let blob = unsafe { &*(this as *const D3dBlob) };
    blob.refcount
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        + 1
}

unsafe extern "C" fn blob_release(this: *mut c_void) -> u32 {
    // SAFETY: `this` is a live D3dBlob.
    let blob = unsafe { &*(this as *const D3dBlob) };
    let prev = blob
        .refcount
        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    if prev == 1 {
        // Last reference: free the buffer and the blob.
        // SAFETY: `buffer` was allocated with `Vec::into_raw_parts`-equivalent.
        if !blob.buffer.is_null() {
            unsafe {
                let _ = Vec::from_raw_parts(blob.buffer, blob.size, blob.size);
            }
        }
        // SAFETY: `this` was Box-allocated.
        unsafe { drop(Box::from_raw(this as *mut D3dBlob)) };
    }
    prev - 1
}

unsafe extern "C" fn blob_get_buffer_pointer(this: *mut c_void) -> *mut c_void {
    // SAFETY: `this` is a live D3dBlob.
    let blob = unsafe { &*(this as *const D3dBlob) };
    blob.buffer as *mut c_void
}

unsafe extern "C" fn blob_get_buffer_size(this: *mut c_void) -> usize {
    // SAFETY: `this` is a live D3dBlob.
    let blob = unsafe { &*(this as *const D3dBlob) };
    blob.size
}

/// The static vtable for all D3DBlob instances.
static BLOB_VTABLE: D3dBlobVtbl = D3dBlobVtbl {
    query_interface: blob_query_interface,
    add_ref: blob_add_ref,
    release: blob_release,
    get_buffer_pointer: blob_get_buffer_pointer,
    get_buffer_size: blob_get_buffer_size,
};

/// Allocate a D3DBlob wrapping the given SPIR-V bytecode.
fn make_blob(spirv: Vec<u8>) -> *mut c_void {
    let size = spirv.len();
    let mut buffer = spirv.into_boxed_slice();
    let buffer_ptr = buffer.as_mut_ptr();
    std::mem::forget(buffer); // ownership moves to the blob

    let blob = Box::new(D3dBlob {
        vtable: &BLOB_VTABLE as *const D3dBlobVtbl,
        refcount: std::sync::atomic::AtomicU32::new(1),
        buffer: buffer_ptr,
        size,
    });
    Box::into_raw(blob) as *mut c_void
}

/// Read a NUL-terminated C string from guest memory.
unsafe fn read_cstr(ptr: *const u8) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut bytes = Vec::new();
    let mut i = 0;
    // SAFETY: guest provides a NUL-terminated string.
    unsafe {
        while *ptr.add(i) != 0 && i < 65536 {
            bytes.push(*ptr.add(i));
            i += 1;
        }
    }
    String::from_utf8(bytes).ok()
}

/// `d3dcompiler_47!D3DCompile(src, src_size, source_name, macros, include,
/// entry, target, flags1, flags2, code, msgs) -> HRESULT`.
///
/// Bridges to our `nigg-hlsl-compiler` crate: parses the HLSL source, compiles
/// it to SPIR-V, and wraps the bytecode in an `ID3DBlob`.
pub extern "C" fn d3d_compile(
    src: *const c_void,
    src_size: usize,
    _source_name: *const u8,
    _macros: *const c_void,
    _include: *const c_void,
    entry: *const u8,
    target: *const u8,
    _flags1: u32,
    _flags2: u32,
    code: *mut *mut c_void,
    _msgs: *mut *mut c_void,
) -> c_int {
    if src.is_null() || code.is_null() {
        return E_FAIL;
    }

    // Read the HLSL source from guest memory.
    // SAFETY: the game provides `src_size` bytes at `src`.
    let source_bytes = unsafe { std::slice::from_raw_parts(src as *const u8, src_size) };
    let source = match std::str::from_utf8(source_bytes) {
        Ok(s) => s,
        Err(_) => return E_FAIL,
    };

    // Read the entry point name (e.g. "VSMain", "PSMain").
    let entry_name = unsafe { read_cstr(entry) }.unwrap_or_default();
    let target_name = unsafe { read_cstr(target) }.unwrap_or_default();

    // Map the D3D target string ("vs_5_0", "ps_5_0", etc.) to our ShaderStage.
    let stage = if target_name.starts_with("vs") {
        nigg_hlsl_compiler::ShaderStage::Vertex
    } else {
        nigg_hlsl_compiler::ShaderStage::Pixel
    };

    log::debug!(
        "d3dcompiler: D3DCompile(entry='{}', target='{}', {} bytes) stage={:?}",
        entry_name,
        target_name,
        source.len(),
        stage
    );

    // Compile HLSL → SPIR-V using our compiler.
    match nigg_hlsl_compiler::compile(source, stage) {
        Ok(spirv_words) => {
            // Convert Vec<u32> to bytes for the blob.
            let spirv_bytes: Vec<u8> = spirv_words.iter().flat_map(|w| w.to_le_bytes()).collect();
            let blob = make_blob(spirv_bytes);
            // SAFETY: `code` is a valid out-pointer per the D3DCompile contract.
            unsafe { *code = blob };
            S_OK
        }
        Err(_e) => {
            log::debug!(
                "d3dcompiler: D3DCompile(entry='{}', target='{}', {} bytes) stage={:?}",
                entry_name,
                target_name,
                source.len(),
                stage
            );
            E_FAIL
        }
    }
}

/// `d3dcompiler_47!D3DCompileFromFile(filename, defines, include, entry, target,
/// flags1, flags2, code, msgs) -> HRESULT`.
pub extern "C" fn d3d_compile_from_file(
    _filename: *const u16,
    _defines: *const c_void,
    _include: *const c_void,
    _entry: *const u8,
    _target: *const u8,
    _flags1: u32,
    _flags2: u32,
    _code: *mut *mut c_void,
    _msgs: *mut *mut c_void,
) -> c_int {
    // File-based compilation is less common — games usually pass shader source
    // inline via D3DCompile. Return E_FAIL for now.
    log::warn!(
        "d3dcompiler: D3DCompileFromFile not implemented (use D3DCompile with inline source)"
    );
    E_FAIL
}

/// `d3dcompiler_47!D3DGetBlobPart` — return a part of a compiled blob.
pub extern "C" fn d3d_get_blob_part(
    _src: *const c_void,
    _src_size: usize,
    _part: u32,
    _flags: u32,
    _part_data: *mut *mut c_void,
    _part_size: *mut usize,
) -> c_int {
    E_FAIL
}

/// `d3dcompiler_47!D3DStripShader` — strip optional data from a compiled shader.
pub extern "C" fn d3d_strip_shader(
    _src: *const c_void,
    _src_size: usize,
    _strip_flags: u32,
    _stripped: *mut *mut c_void,
    _stripped_size: *mut usize,
) -> c_int {
    // Just return the input as-is (no stripping needed for SPIR-V).
    S_OK
}

/// `d3dcompiler_47!D3DReflect` — return reflection interface for a shader.
pub extern "C" fn d3d_reflect(
    _src: *const c_void,
    _src_size: usize,
    _riid: *const u8,
    _reflector: *mut *mut c_void,
) -> c_int {
    E_FAIL
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

pub fn d3d_compiler_exports() -> Vec<ExportSpec> {
    fn e(sym: &'static str, f: *const c_void, n: u8) -> ExportSpec {
        ExportSpec {
            dll: "d3dcompiler_47.dll",
            sym,
            ptr: f,
            n_args: n,
            noreturn: false,
        }
    }

    vec![
        e("D3DCompile", d3d_compile as *const c_void, 11),
        e(
            "D3DCompileFromFile",
            d3d_compile_from_file as *const c_void,
            9,
        ),
        e("D3DGetBlobPart", d3d_get_blob_part as *const c_void, 7),
        e("D3DStripShader", d3d_strip_shader as *const c_void, 6),
        e("D3DReflect", d3d_reflect as *const c_void, 5),
    ]
}
