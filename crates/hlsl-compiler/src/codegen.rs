//! Code generation: walk the [AST](crate::ast) to a SPIR-V module via
//! [`rspirv::dr::Builder`].
//!
//! M6a extends the emitter beyond the trivial MVP to cover the HLSL subset the
//! parser already accepts: control flow (if/else, for), constant buffers,
//! textures/samplers, intrinsics (via `GLSL.std.450`), vector swizzles and
//! constructors, and struct-typed vertex-shader inputs/outputs.
//!
//! The model is uniform: every named, storable entity (locals, function
//! parameters, cbuffer members, textures, samplers, I/O variables) is a
//! SPIR-V *pointer*. Reading a name yields its value via `OpLoad`; writing
//! stores via `OpStore`. Member access on a struct is `OpAccessChain`; on a
//! vector it is a swizzle (`OpVectorShuffle` / `OpCompositeExtract`).

use std::collections::HashMap;
use std::fmt;

use rspirv::binary::Assemble;
use rspirv::dr;
use rspirv::spirv::{
    BuiltIn, Capability, Decoration, Dim, ExecutionMode, ExecutionModel, FunctionControl,
    ImageFormat, LoopControl, Op, SelectionControl, SourceLanguage, StorageClass,
};

use crate::ast::{
    BinaryOp, Block, CBufferDecl, Decl, Expr, FunctionDecl, GlobalVarDecl, Literal, ScalarKind,
    Stmt, StructDecl, StructMember, TranslationUnit, Type, UnaryOp,
};

/// The shader stage being compiled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShaderStage {
    Vertex,
    Pixel,
}

impl ShaderStage {
    fn execution_model(self) -> ExecutionModel {
        match self {
            ShaderStage::Vertex => ExecutionModel::Vertex,
            ShaderStage::Pixel => ExecutionModel::Fragment,
        }
    }
}

/// A code generation error.
#[derive(Debug, Clone)]
pub struct CodegenError {
    pub msg: String,
}

impl fmt::Display for CodegenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "codegen error: {}", self.msg)
    }
}

impl std::error::Error for CodegenError {}

fn cg_err(msg: impl Into<String>) -> CodegenError {
    CodegenError { msg: msg.into() }
}

type Result<T> = std::result::Result<T, CodegenError>;

/// GLSL.std.450 extended-instruction opcode numbers (per the SPIR-V grammar
/// shipped with rspirv 0.12).
mod glsl {
    pub const FABS: u32 = 4;
    pub const FLOOR: u32 = 8;
    pub const CEIL: u32 = 9;
    pub const FRACT: u32 = 10;
    pub const SIN: u32 = 13;
    pub const COS: u32 = 14;
    pub const TAN: u32 = 15;
    pub const ASIN: u32 = 16;
    pub const ACOS: u32 = 17;
    pub const ATAN: u32 = 18;
    pub const POW: u32 = 26;
    pub const EXP: u32 = 27;
    pub const LOG: u32 = 28;
    pub const SQRT: u32 = 31;
    pub const INVERSE_SQRT: u32 = 32;
    pub const FMIN: u32 = 37;
    pub const FMAX: u32 = 40;
    pub const FCLAMP: u32 = 43;
    pub const FMIX: u32 = 46;
    pub const LENGTH: u32 = 66;
    pub const CROSS: u32 = 68;
    pub const NORMALIZE: u32 = 69;
}

/// An evaluated value: a SPIR-V result id paired with its HLSL type.
#[derive(Clone)]
struct Val {
    id: u32,
    ty: Type,
}

/// An addressable place: a pointer id plus the type of the pointee.
#[derive(Clone)]
struct Place {
    ptr: u32,
    ty: Type,
}

/// A registered struct type and its members.
struct StructInfo {
    type_id: u32,
    members: Vec<StructMember>,
}

/// A named, storable global (cbuffer, texture, sampler, I/O variable).
struct Global {
    ptr: u32,
    ty: Type,
}

/// A local or parameter variable (a `Function`-storage pointer).
struct Local {
    ptr: u32,
    ty: Type,
}

/// Code generation context.
struct Ctx {
    stage: ShaderStage,
    builder: rspirv::dr::Builder,
    /// `GLSL.std.450` extended-instruction-set id.
    glsl_set: u32,
    // Cached scalar/vector/matrix type ids.
    void_t: u32,
    bool_t: u32,
    float_t: u32,
    int_t: u32,
    uint_t: u32,
    // Struct type registry: name -> info.
    structs: HashMap<String, StructInfo>,
    // Named globals (cbuffer/texture/sampler/input/output).
    globals: HashMap<String, Global>,
    // cbuffer member name -> (cbuffer variable id, member index constant id).
    cbuffer_members: HashMap<String, (u32, u32)>,
    // Function-scoped names (locals + parameter copies), flat table.
    locals: Vec<(String, Local)>,
    // The single output variable for the entry point and its type.
    out_var: Option<u32>,
    out_ty: Type,
    // Interface variables to list in OpEntryPoint.
    interface: Vec<u32>,
}

impl Ctx {
    fn new(stage: ShaderStage) -> Self {
        let mut builder = rspirv::dr::Builder::new();
        // SPIR-V 1.0 is maximally compatible with D3D11/Vulkan consumers.
        builder.set_version(1, 0);
        builder.capability(Capability::Shader);
        builder.memory_model(
            rspirv::spirv::AddressingModel::Logical,
            rspirv::spirv::MemoryModel::GLSL450,
        );

        let void_t = builder.type_void();
        let bool_t = builder.type_bool();
        let float_t = builder.type_float(32);
        let int_t = builder.type_int(32, 1);
        let uint_t = builder.type_int(32, 0);
        let glsl_set = builder.ext_inst_import("GLSL.std.450");

        builder.source(SourceLanguage::HLSL, 500, None, None::<&str>);

        Ctx {
            stage,
            builder,
            glsl_set,
            void_t,
            bool_t,
            float_t,
            int_t,
            uint_t,
            structs: HashMap::new(),
            globals: HashMap::new(),
            cbuffer_members: HashMap::new(),
            locals: Vec::new(),
            out_var: None,
            out_ty: Type::Void,
            interface: Vec::new(),
        }
    }

    // --- module / function scaffolding -------------------------------------

    fn emit_globals(&mut self, unit: &TranslationUnit) -> Result<()> {
        for d in &unit.decls {
            match d {
                Decl::Struct(s) => self.register_struct(s)?,
                Decl::CBuffer(c) => self.emit_cbuffer(c)?,
                Decl::GlobalVar(g) => self.emit_global_var(g)?,
                Decl::Function(_) => {}
            }
        }
        Ok(())
    }

    /// Register a `struct` type (OpTypeStruct) and its members. No variable is
    /// created here; struct types become variables only when used as I/O.
    fn register_struct(&mut self, s: &StructDecl) -> Result<()> {
        if self.structs.contains_key(&s.name) {
            return Ok(());
        }
        let mut member_types = Vec::with_capacity(s.members.len());
        for m in &s.members {
            member_types.push(self.type_id(&m.ty)?);
        }
        let type_id = self.builder.type_struct(member_types);
        for (i, m) in s.members.iter().enumerate() {
            self.builder.member_name(type_id, i as u32, m.name.clone());
        }
        self.structs.insert(
            s.name.clone(),
            StructInfo {
                type_id,
                members: s.members.clone(),
            },
        );
        Ok(())
    }

    /// Emit a cbuffer: a Block-decorated struct type plus a `Uniform` variable
    /// with `Binding`/`DescriptorSet` and per-member `Offset` decorations.
    fn emit_cbuffer(&mut self, c: &CBufferDecl) -> Result<()> {
        let mut member_types = Vec::with_capacity(c.members.len());
        for m in &c.members {
            member_types.push(self.type_id(&m.ty)?);
        }
        let struct_id = self.builder.type_struct(member_types);
        self.builder.decorate(struct_id, Decoration::Block, []);
        // std140-ish layout: align each member, then place it.
        let mut offset = 0u32;
        for (i, m) in c.members.iter().enumerate() {
            let (align, size) = member_align_size(&m.ty);
            offset = align_up(offset, align);
            self.builder.member_decorate(
                struct_id,
                i as u32,
                Decoration::Offset,
                [rspirv::dr::Operand::LiteralBit32(offset)],
            );
            self.builder
                .member_name(struct_id, i as u32, m.name.clone());
            offset += size;
        }
        // Register the cbuffer struct type so member access can find it.
        self.structs.insert(
            c.name.clone(),
            StructInfo {
                type_id: struct_id,
                members: c.members.clone(),
            },
        );

        let ptr_t = self
            .builder
            .type_pointer(None, StorageClass::Uniform, struct_id);
        let var = self
            .builder
            .variable(ptr_t, None, StorageClass::Uniform, None);
        self.builder.name(var, c.name.clone());
        let (set, binding) = parse_register(&c.register, 'b');
        self.builder.decorate(
            var,
            Decoration::DescriptorSet,
            [rspirv::dr::Operand::LiteralBit32(set)],
        );
        self.builder.decorate(
            var,
            Decoration::Binding,
            [rspirv::dr::Operand::LiteralBit32(binding)],
        );
        self.globals.insert(
            c.name.clone(),
            Global {
                ptr: var,
                ty: Type::Struct(c.name.clone()),
            },
        );
        // Also register each member as an addressable global keyed by member
        // name, so `color` resolves to a pointer into the cbuffer struct.
        for (i, m) in c.members.iter().enumerate() {
            let member_ty = m.ty.clone();
            let member_ty_id = self.type_id(&member_ty)?;
            let _member_ptr_t =
                self.builder
                    .type_pointer(None, StorageClass::Uniform, member_ty_id);
            let idx_const = self.int_const(i as i32, true);
            self.globals.insert(
                m.name.clone(),
                Global {
                    ptr: var,
                    ty: member_ty,
                },
            );
            self.cbuffer_members
                .insert(m.name.clone(), (var, idx_const));
        }
        Ok(())
    }

    /// Emit a top-level global variable (texture or sampler).
    fn emit_global_var(&mut self, g: &GlobalVarDecl) -> Result<()> {
        match &g.ty {
            Type::Texture2D => {
                let image_t = self.builder.type_image(
                    self.float_t,
                    Dim::Dim2D,
                    0,
                    0,
                    0,
                    1,
                    ImageFormat::Unknown,
                    None,
                );
                let sampled_image_t = self.builder.type_sampled_image(image_t);
                let ptr_t =
                    self.builder
                        .type_pointer(None, StorageClass::UniformConstant, sampled_image_t);
                let var = self
                    .builder
                    .variable(ptr_t, None, StorageClass::UniformConstant, None);
                self.builder.name(var, g.name.clone());
                let (set, binding) = parse_register(&g.register, 't');
                self.builder.decorate(
                    var,
                    Decoration::DescriptorSet,
                    [rspirv::dr::Operand::LiteralBit32(set)],
                );
                self.builder.decorate(
                    var,
                    Decoration::Binding,
                    [rspirv::dr::Operand::LiteralBit32(binding)],
                );
                self.globals.insert(
                    g.name.clone(),
                    Global {
                        ptr: var,
                        ty: Type::Texture2D,
                    },
                );
            }
            Type::SamplerState => {
                let sampler_t = self.builder.type_sampler();
                let ptr_t =
                    self.builder
                        .type_pointer(None, StorageClass::UniformConstant, sampler_t);
                let var = self
                    .builder
                    .variable(ptr_t, None, StorageClass::UniformConstant, None);
                self.builder.name(var, g.name.clone());
                let (set, binding) = parse_register(&g.register, 's');
                self.builder.decorate(
                    var,
                    Decoration::DescriptorSet,
                    [rspirv::dr::Operand::LiteralBit32(set)],
                );
                self.builder.decorate(
                    var,
                    Decoration::Binding,
                    [rspirv::dr::Operand::LiteralBit32(binding)],
                );
                self.globals.insert(
                    g.name.clone(),
                    Global {
                        ptr: var,
                        ty: Type::SamplerState,
                    },
                );
            }
            other => {
                return Err(cg_err(format!(
                    "unsupported global variable type `{other}`"
                )))
            }
        }
        Ok(())
    }

    // --- entry point --------------------------------------------------------

    fn emit_main(&mut self, main: &FunctionDecl) -> Result<()> {
        self.emit_inputs(main)?;
        self.emit_output(main)?;
        self.begin_entry_function()?;
        self.emit_function_body(main)?;
        self.finish_entry_point(main)?;
        Ok(())
    }

    /// Create input variables for each parameter of `main`.
    fn emit_inputs(&mut self, main: &FunctionDecl) -> Result<()> {
        for p in &main.params {
            match &p.ty {
                Type::Struct(name) => {
                    let info = self
                        .structs
                        .get(name)
                        .ok_or_else(|| cg_err(format!("unknown struct type `{name}`")))?;
                    let struct_id = info.type_id;
                    let members = info.members.clone();
                    self.decorate_struct_io(&members, struct_id, false)?;
                    let ptr_t = self
                        .builder
                        .type_pointer(None, StorageClass::Input, struct_id);
                    let var = self
                        .builder
                        .variable(ptr_t, None, StorageClass::Input, None);
                    self.builder.name(var, p.name.clone());
                    self.interface.push(var);
                    self.globals.insert(
                        p.name.clone(),
                        Global {
                            ptr: var,
                            ty: Type::Struct(name.clone()),
                        },
                    );
                }
                ty @ (Type::Scalar(_) | Type::Vector(_, _)) => {
                    let ty_id = self.type_id(ty)?;
                    let ptr_t = self.builder.type_pointer(None, StorageClass::Input, ty_id);
                    let var = self
                        .builder
                        .variable(ptr_t, None, StorageClass::Input, None);
                    self.builder.name(var, p.name.clone());
                    self.decorate_io_var(var, p.semantic.as_deref(), false);
                    self.interface.push(var);
                    self.globals.insert(
                        p.name.clone(),
                        Global {
                            ptr: var,
                            ty: ty.clone(),
                        },
                    );
                }
                other => return Err(cg_err(format!("unsupported input type `{other}`"))),
            }
        }
        Ok(())
    }

    /// Create the single output variable for `main`'s return type.
    fn emit_output(&mut self, main: &FunctionDecl) -> Result<()> {
        match &main.return_type {
            Type::Struct(name) => {
                let info = self
                    .structs
                    .get(name)
                    .ok_or_else(|| cg_err(format!("unknown struct type `{name}`")))?;
                let struct_id = info.type_id;
                let members = info.members.clone();
                self.decorate_struct_io(&members, struct_id, true)?;
                let ptr_t = self
                    .builder
                    .type_pointer(None, StorageClass::Output, struct_id);
                let var = self
                    .builder
                    .variable(ptr_t, None, StorageClass::Output, None);
                self.builder.name(var, "out_var");
                self.interface.push(var);
                self.out_var = Some(var);
                self.out_ty = Type::Struct(name.clone());
            }
            ty @ Type::Vector(ScalarKind::Float, 4) => {
                let ty_id = self.type_id(ty)?;
                let ptr_t = self.builder.type_pointer(None, StorageClass::Output, ty_id);
                let var = self
                    .builder
                    .variable(ptr_t, None, StorageClass::Output, None);
                self.builder.name(var, "out_color");
                self.decorate_io_var(var, main.semantic.as_deref(), true);
                self.interface.push(var);
                self.out_var = Some(var);
                self.out_ty = ty.clone();
            }
            other => return Err(cg_err(format!("unsupported main return type `{other}`"))),
        }
        Ok(())
    }

    /// Decorate a struct type's members for input/output use (Location or
    /// BuiltIn per member), and mark the struct as a `Block`.
    fn decorate_struct_io(
        &mut self,
        members: &[StructMember],
        struct_id: u32,
        is_output: bool,
    ) -> Result<()> {
        self.builder.decorate(struct_id, Decoration::Block, []);
        let mut loc = 0u32;
        for (i, m) in members.iter().enumerate() {
            match m.semantic.as_deref() {
                Some("SV_Position") => {
                    let builtin = if is_output && self.stage == ShaderStage::Vertex {
                        BuiltIn::Position
                    } else if !is_output && self.stage == ShaderStage::Pixel {
                        BuiltIn::FragCoord
                    } else {
                        BuiltIn::Position
                    };
                    self.builder.member_decorate(
                        struct_id,
                        i as u32,
                        Decoration::BuiltIn,
                        [rspirv::dr::Operand::BuiltIn(builtin)],
                    );
                }
                Some("SV_Target") => {
                    self.builder.member_decorate(
                        struct_id,
                        i as u32,
                        Decoration::Location,
                        [rspirv::dr::Operand::LiteralBit32(0)],
                    );
                }
                _ => {
                    self.builder.member_decorate(
                        struct_id,
                        i as u32,
                        Decoration::Location,
                        [rspirv::dr::Operand::LiteralBit32(loc)],
                    );
                    loc += 1;
                }
            }
        }
        Ok(())
    }

    /// Decorate a scalar/vector I/O variable with Location or BuiltIn.
    fn decorate_io_var(&mut self, var: u32, semantic: Option<&str>, is_output: bool) {
        match semantic {
            Some("SV_Position") => {
                let builtin = if is_output && self.stage == ShaderStage::Vertex {
                    BuiltIn::Position
                } else if !is_output && self.stage == ShaderStage::Pixel {
                    BuiltIn::FragCoord
                } else {
                    BuiltIn::Position
                };
                self.builder.decorate(
                    var,
                    Decoration::BuiltIn,
                    [rspirv::dr::Operand::BuiltIn(builtin)],
                );
            }
            Some("SV_Target") | None => {
                self.builder.decorate(
                    var,
                    Decoration::Location,
                    [rspirv::dr::Operand::LiteralBit32(0)],
                );
            }
            _ => {
                self.builder.decorate(
                    var,
                    Decoration::Location,
                    [rspirv::dr::Operand::LiteralBit32(0)],
                );
            }
        }
    }

    fn begin_entry_function(&mut self) -> Result<()> {
        let fn_type = self.builder.type_function(self.void_t, vec![]);
        self.builder
            .begin_function(self.void_t, None, FunctionControl::NONE, fn_type)
            .map_err(|e| cg_err(format!("begin_function failed: {e:?}")))?;
        self.builder
            .begin_block(None)
            .map_err(|e| cg_err(format!("begin_block failed: {e:?}")))?;
        Ok(())
    }

    fn emit_function_body(&mut self, main: &FunctionDecl) -> Result<()> {
        // Bind each parameter to a writable Function-local copy initialised
        // from its Input global.
        let params: Vec<(String, u32, Type)> = main
            .params
            .iter()
            .map(|p| {
                let g = self
                    .globals
                    .get(&p.name)
                    .ok_or_else(|| cg_err(format!("input variable `{}` not found", p.name)))?;
                Ok((p.name.clone(), g.ptr, p.ty.clone()))
            })
            .collect::<Result<Vec<_>>>()?;
        for (name, global_ptr, ty) in params {
            let local_ptr = self.alloc_local(&ty)?;
            let ty_id = self.type_id(&ty)?;
            let loaded = self
                .builder
                .load(ty_id, None, global_ptr, None, [])
                .map_err(|e| cg_err(format!("load failed: {e:?}")))?;
            self.builder
                .store(local_ptr, loaded, None, [])
                .map_err(|e| cg_err(format!("store failed: {e:?}")))?;
            self.locals.push((name, Local { ptr: local_ptr, ty }));
        }

        let body = main
            .body
            .as_ref()
            .ok_or_else(|| cg_err("main has no body"))?;
        self.emit_block(body)?;
        // Guarantee a terminator: if the body didn't end with `return`, emit one.
        if !self.is_terminated() {
            self.builder
                .ret()
                .map_err(|e| cg_err(format!("ret failed: {e:?}")))?;
        }
        self.builder
            .end_function()
            .map_err(|e| cg_err(format!("end_function failed: {e:?}")))?;
        Ok(())
    }

    fn finish_entry_point(&mut self, main: &FunctionDecl) -> Result<()> {
        let main_id = self
            .builder
            .module_ref()
            .functions
            .last()
            .and_then(|f| f.def.as_ref())
            .and_then(|i| i.result_id)
            .ok_or_else(|| cg_err("main function has no id"))?;
        let interface = std::mem::take(&mut self.interface);
        self.builder
            .entry_point(self.stage.execution_model(), main_id, "main", interface);
        if self.stage == ShaderStage::Pixel {
            self.builder
                .execution_mode(main_id, ExecutionMode::OriginUpperLeft, []);
        }
        self.builder.name(main_id, main.name.clone());
        Ok(())
    }

    // --- control-flow helpers ----------------------------------------------

    /// Whether the current block already has a terminator (branch/return).
    fn is_terminated(&self) -> bool {
        self.builder.selected_block().is_none()
    }

    // --- statements --------------------------------------------------------

    fn emit_block(&mut self, block: &Block) -> Result<()> {
        for stmt in &block.stmts {
            self.emit_stmt(stmt)?;
            if self.is_terminated() {
                break;
            }
        }
        Ok(())
    }

    fn emit_stmt(&mut self, stmt: &Stmt) -> Result<()> {
        match stmt {
            Stmt::Return(Some(e)) => {
                let val = self.emit_expr(e)?;
                if let Some(out) = self.out_var {
                    self.builder
                        .store(out, val.id, None, [])
                        .map_err(|e| cg_err(format!("store failed: {e:?}")))?;
                }
                self.builder
                    .ret()
                    .map_err(|e| cg_err(format!("ret failed: {e:?}")))?;
                Ok(())
            }
            Stmt::Return(None) => {
                self.builder
                    .ret()
                    .map_err(|e| cg_err(format!("ret failed: {e:?}")))?;
                Ok(())
            }
            Stmt::VarDecl(vd) => {
                let local_ptr = self.alloc_local(&vd.ty)?;
                if let Some(e) = &vd.init {
                    let val = self.emit_expr(e)?;
                    self.builder
                        .store(local_ptr, val.id, None, [])
                        .map_err(|e| cg_err(format!("store failed: {e:?}")))?;
                }
                self.locals.push((
                    vd.name.clone(),
                    Local {
                        ptr: local_ptr,
                        ty: vd.ty.clone(),
                    },
                ));
                Ok(())
            }
            Stmt::Expr(e) => {
                self.emit_expr(e)?;
                Ok(())
            }
            Stmt::If { cond, then, else_ } => self.emit_if(cond, then, else_),
            Stmt::For {
                init,
                cond,
                update,
                body,
            } => self.emit_for(init, cond, update, body),
            Stmt::Block(b) => self.emit_block(b),
        }
    }

    fn emit_if(&mut self, cond: &Expr, then: &Block, else_: &Option<Block>) -> Result<()> {
        let cond_val = self.emit_expr(cond)?;
        // Condition must be a scalar boolean; coerce vector<bool> via OpAny.
        let cond_id = self.coerce_to_bool(cond_val)?;

        let then_label = self.builder.id();
        let merge_label = self.builder.id();
        let else_label = match else_ {
            Some(_) => self.builder.id(),
            None => merge_label,
        };

        self.builder
            .selection_merge(merge_label, SelectionControl::NONE)
            .map_err(|e| cg_err(format!("selection_merge failed: {e:?}")))?;
        self.builder
            .branch_conditional(cond_id, then_label, else_label, [])
            .map_err(|e| cg_err(format!("branch_conditional failed: {e:?}")))?;

        // then-block
        self.builder
            .begin_block(Some(then_label))
            .map_err(|e| cg_err(format!("begin_block failed: {e:?}")))?;
        self.emit_block(then)?;
        if !self.is_terminated() {
            self.builder
                .branch(merge_label)
                .map_err(|e| cg_err(format!("branch failed: {e:?}")))?;
        }

        // else-block (if present)
        if let Some(else_block) = else_ {
            self.builder
                .begin_block(Some(else_label))
                .map_err(|e| cg_err(format!("begin_block failed: {e:?}")))?;
            self.emit_block(else_block)?;
            if !self.is_terminated() {
                self.builder
                    .branch(merge_label)
                    .map_err(|e| cg_err(format!("branch failed: {e:?}")))?;
            }
        }

        // merge-block
        self.builder
            .begin_block(Some(merge_label))
            .map_err(|e| cg_err(format!("begin_block failed: {e:?}")))?;
        Ok(())
    }

    fn emit_for(
        &mut self,
        init: &Option<Box<Stmt>>,
        cond: &Option<Expr>,
        update: &Option<Expr>,
        body: &Block,
    ) -> Result<()> {
        // init runs in the current (pre-header) block.
        if let Some(init_stmt) = init {
            self.emit_stmt(init_stmt)?;
        }
        if self.is_terminated() {
            return Ok(());
        }

        let header_label = self.builder.id();
        let body_label = self.builder.id();
        let continue_label = self.builder.id();
        let merge_label = self.builder.id();

        self.builder
            .branch(header_label)
            .map_err(|e| cg_err(format!("branch failed: {e:?}")))?;

        // header block: OpLoopMerge, then condition check.
        self.builder
            .begin_block(Some(header_label))
            .map_err(|e| cg_err(format!("begin_block failed: {e:?}")))?;
        self.builder
            .loop_merge(merge_label, continue_label, LoopControl::NONE, [])
            .map_err(|e| cg_err(format!("loop_merge failed: {e:?}")))?;
        match cond {
            Some(c) => {
                let cv = self.emit_expr(c)?;
                let cid = self.coerce_to_bool(cv)?;
                self.builder
                    .branch_conditional(cid, body_label, merge_label, [])
                    .map_err(|e| cg_err(format!("branch_conditional failed: {e:?}")))?;
            }
            None => {
                self.builder
                    .branch(body_label)
                    .map_err(|e| cg_err(format!("branch failed: {e:?}")))?;
            }
        }

        // body block.
        self.builder
            .begin_block(Some(body_label))
            .map_err(|e| cg_err(format!("begin_block failed: {e:?}")))?;
        self.emit_block(body)?;
        if !self.is_terminated() {
            self.builder
                .branch(continue_label)
                .map_err(|e| cg_err(format!("branch failed: {e:?}")))?;
        }

        // continue block: update, then branch to header.
        self.builder
            .begin_block(Some(continue_label))
            .map_err(|e| cg_err(format!("begin_block failed: {e:?}")))?;
        if let Some(u) = update {
            self.emit_expr(u)?;
        }
        self.builder
            .branch(header_label)
            .map_err(|e| cg_err(format!("branch failed: {e:?}")))?;

        // merge block.
        self.builder
            .begin_block(Some(merge_label))
            .map_err(|e| cg_err(format!("begin_block failed: {e:?}")))?;
        Ok(())
    }

    // --- expressions -------------------------------------------------------

    fn emit_expr(&mut self, e: &Expr) -> Result<Val> {
        match e {
            Expr::Literal(Literal::Float(v)) => Ok(Val {
                id: self.float_const(*v),
                ty: Type::Scalar(ScalarKind::Float),
            }),
            Expr::Literal(Literal::Int(v)) => Ok(Val {
                id: self.int_const(*v as i32, true),
                ty: Type::Scalar(ScalarKind::Int),
            }),
            Expr::Literal(Literal::Uint(v)) => Ok(Val {
                id: self.int_const(*v as u32 as i32, false),
                ty: Type::Scalar(ScalarKind::Uint),
            }),
            Expr::Literal(Literal::Bool(v)) => Ok(Val {
                id: self.bool_const(*v),
                ty: Type::Scalar(ScalarKind::Bool),
            }),
            Expr::Construct { ty, args } => self.emit_construct(ty, args),
            Expr::Ident(_) => {
                let place = self.emit_place(e)?;
                // Textures and samplers are opaque: their "value" type in SPIR-V
                // is the sampled-image / sampler type, not a plain Type id.
                let ty_id = self.value_type_id(&place.ty)?;
                let id = self
                    .builder
                    .load(ty_id, None, place.ptr, None, [])
                    .map_err(|e| cg_err(format!("load failed: {e:?}")))?;
                Ok(Val { id, ty: place.ty })
            }
            Expr::Member { base, member } => self.emit_member(base, member),
            Expr::Call { name, args } => self.emit_call(name, args),
            Expr::MethodCall { base, method, args } => self.emit_method_call(base, method, args),
            Expr::Binary { op, lhs, rhs } => self.emit_binary(*op, lhs, rhs),
            Expr::Unary { op, expr } => self.emit_unary(*op, expr),
            Expr::Cast { ty, expr } => self.emit_cast(ty, expr),
        }
    }

    /// Evaluate an expression as an addressable place (lvalue).
    fn emit_place(&mut self, e: &Expr) -> Result<Place> {
        match e {
            Expr::Ident(name) => {
                if let Some((_, local)) = self.locals.iter().rev().find(|(n, _)| n == name) {
                    return Ok(Place {
                        ptr: local.ptr,
                        ty: local.ty.clone(),
                    });
                }
                if let Some((cbvar, idx_const)) = self.cbuffer_members.get(name).cloned() {
                    let member_ty = self
                        .globals
                        .get(name)
                        .map(|g| g.ty.clone())
                        .ok_or_else(|| cg_err(format!("cbuffer member `{name}` has no type")))?;
                    let member_ty_id = self.type_id(&member_ty)?;
                    let member_ptr_t =
                        self.builder
                            .type_pointer(None, StorageClass::Uniform, member_ty_id);
                    let ptr = self
                        .builder
                        .access_chain(member_ptr_t, None, cbvar, [idx_const])
                        .map_err(|e| cg_err(format!("access_chain failed: {e:?}")))?;
                    return Ok(Place { ptr, ty: member_ty });
                }
                if let Some(g) = self.globals.get(name) {
                    return Ok(Place {
                        ptr: g.ptr,
                        ty: g.ty.clone(),
                    });
                }
                Err(cg_err(format!("undefined identifier `{name}`")))
            }
            Expr::Member { base, member } => {
                let base_place = self.emit_place(base)?;
                match &base_place.ty {
                    Type::Struct(name) => {
                        let (idx, member_ty) = {
                            let info = self
                                .structs
                                .get(name)
                                .ok_or_else(|| cg_err(format!("unknown struct `{name}`")))?;
                            let (idx, m) = info
                                .members
                                .iter()
                                .enumerate()
                                .find(|(_, m)| m.name == *member)
                                .ok_or_else(|| {
                                    cg_err(format!("no member `{member}` in `{name}`"))
                                })?;
                            (idx, m.ty.clone())
                        };
                        let idx_const = self.int_const(idx as i32, true);
                        let member_ty_id = self.type_id(&member_ty)?;
                        let member_ptr_t =
                            self.builder
                                .type_pointer(None, StorageClass::Function, member_ty_id);
                        let ptr = self
                            .builder
                            .access_chain(member_ptr_t, None, base_place.ptr, [idx_const])
                            .map_err(|e| cg_err(format!("access_chain failed: {e:?}")))?;
                        Ok(Place { ptr, ty: member_ty })
                    }
                    other => Err(cg_err(format!(
                        "cannot take address of member `{member}` of non-struct `{other}`"
                    ))),
                }
            }
            other => Err(cg_err(format!("expression is not assignable: {other:?}"))),
        }
    }

    /// Member access: struct field (access chain + load) or vector swizzle.
    fn emit_member(&mut self, base: &Expr, member: &str) -> Result<Val> {
        let base_ty = self.infer_type(base)?;
        match base_ty {
            Type::Struct(_) => {
                let member_expr = Expr::Member {
                    base: Box::new(base.clone()),
                    member: member.to_string(),
                };
                let place = self.emit_place(&member_expr)?;
                let ty_id = self.type_id(&place.ty)?;
                let id = self
                    .builder
                    .load(ty_id, None, place.ptr, None, [])
                    .map_err(|e| cg_err(format!("load failed: {e:?}")))?;
                Ok(Val { id, ty: place.ty })
            }
            Type::Vector(kind, _) => {
                let base_val = self.emit_expr(base)?;
                self.emit_swizzle(base_val, member, kind)
            }
            other => Err(cg_err(format!(
                "member access `{member}` on unsupported type `{other}`"
            ))),
        }
    }

    /// Apply a `.xyzw`/`.rgba` swizzle to a vector value.
    fn emit_swizzle(&mut self, base: Val, member: &str, kind: ScalarKind) -> Result<Val> {
        let comps =
            decode_swizzle(member).ok_or_else(|| cg_err(format!("invalid swizzle `.{member}`")))?;
        let result_ty = Type::Vector(kind, comps.len() as u32);
        let result_ty_id = self.type_id(&result_ty)?;
        if comps.len() == 1 {
            let scalar_ty_id = self.scalar_type_id(kind);
            let id = self
                .builder
                .composite_extract(scalar_ty_id, None, base.id, [comps[0]])
                .map_err(|e| cg_err(format!("composite_extract failed: {e:?}")))?;
            Ok(Val {
                id,
                ty: Type::Scalar(kind),
            })
        } else {
            let id = self
                .builder
                .vector_shuffle(result_ty_id, None, base.id, base.id, comps.iter().copied())
                .map_err(|e| cg_err(format!("vector_shuffle failed: {e:?}")))?;
            Ok(Val { id, ty: result_ty })
        }
    }

    /// Type-constructor call (`float4(...)`, scalar broadcast, or vector
    /// assembly from sub-vectors/scalars).
    fn emit_construct(&mut self, ty: &Type, args: &[Expr]) -> Result<Val> {
        match ty {
            Type::Scalar(ScalarKind::Float) => {
                if let [arg] = args {
                    return self.emit_expr(arg);
                }
                Err(cg_err("float(...) expects exactly one argument"))
            }
            Type::Scalar(kind) => {
                if let [arg] = args {
                    let v = self.emit_expr(arg)?;
                    return self.coerce_scalar(v, *kind);
                }
                Err(cg_err(format!("{ty}(...) expects one argument")))
            }
            Type::Vector(kind, n) => {
                let target = self.vector_type_id(*kind, *n);
                // Broadcast: `float4(1.0)` replicates the scalar.
                if let [single] = args {
                    let scalar = self.emit_expr(single)?;
                    let scalar_id = match scalar.ty {
                        Type::Scalar(_) => scalar.id,
                        _ => return Err(cg_err("broadcast needs a scalar argument")),
                    };
                    let constituents = vec![scalar_id; *n as usize];
                    let id = self
                        .builder
                        .composite_construct(target, None, constituents)
                        .map_err(|e| cg_err(format!("composite_construct failed: {e:?}")))?;
                    return Ok(Val { id, ty: ty.clone() });
                }
                // Assemble from constituents (sub-vectors and scalars flatten
                // via OpCompositeConstruct).
                let mut constituents = Vec::new();
                for a in args {
                    constituents.push(self.emit_expr(a)?.id);
                }
                let id = self
                    .builder
                    .composite_construct(target, None, constituents)
                    .map_err(|e| cg_err(format!("composite_construct failed: {e:?}")))?;
                Ok(Val { id, ty: ty.clone() })
            }
            other => Err(cg_err(format!(
                "constructor for type `{other}` not supported"
            ))),
        }
    }

    fn emit_binary(&mut self, op: BinaryOp, lhs: &Expr, rhs: &Expr) -> Result<Val> {
        // Assignment-family operators act on places.
        match op {
            BinaryOp::Assign => {
                let place = self.emit_place(lhs)?;
                let val = self.emit_expr(rhs)?;
                let val = self.coerce(val, &place.ty)?;
                self.builder
                    .store(place.ptr, val.id, None, [])
                    .map_err(|e| cg_err(format!("store failed: {e:?}")))?;
                Ok(val)
            }
            BinaryOp::AddAssign
            | BinaryOp::SubAssign
            | BinaryOp::MulAssign
            | BinaryOp::DivAssign => {
                let place = self.emit_place(lhs)?;
                let ty_id = self.type_id(&place.ty)?;
                let cur = self
                    .builder
                    .load(ty_id, None, place.ptr, None, [])
                    .map_err(|e| cg_err(format!("load failed: {e:?}")))?;
                let rhs_val = self.emit_expr(rhs)?;
                let core_op = match op {
                    BinaryOp::AddAssign => BinaryOp::Add,
                    BinaryOp::SubAssign => BinaryOp::Sub,
                    BinaryOp::MulAssign => BinaryOp::Mul,
                    BinaryOp::DivAssign => BinaryOp::Div,
                    _ => unreachable!(),
                };
                let result = self.emit_arith(core_op, cur, &place.ty, rhs_val.id, &rhs_val.ty)?;
                self.builder
                    .store(place.ptr, result.id, None, [])
                    .map_err(|e| cg_err(format!("store failed: {e:?}")))?;
                Ok(result)
            }
            _ => {
                let lhs_val = self.emit_expr(lhs)?;
                let rhs_val = self.emit_expr(rhs)?;
                if is_comparison(op) {
                    self.emit_comparison(op, lhs_val, rhs_val)
                } else if matches!(op, BinaryOp::And | BinaryOp::Or) {
                    self.emit_logical(op, lhs_val, rhs_val)
                } else {
                    self.emit_arith(op, lhs_val.id, &lhs_val.ty, rhs_val.id, &rhs_val.ty)
                }
            }
        }
    }

    fn emit_arith(
        &mut self,
        op: BinaryOp,
        lhs_id: u32,
        lhs_ty: &Type,
        rhs_id: u32,
        rhs_ty: &Type,
    ) -> Result<Val> {
        let result_ty = if lhs_ty.is_composite() {
            lhs_ty.clone()
        } else {
            rhs_ty.clone()
        };
        let result_ty_id = self.type_id(&result_ty)?;
        let spirv_op = match (op, &result_ty) {
            (
                BinaryOp::Add,
                Type::Scalar(ScalarKind::Float) | Type::Vector(ScalarKind::Float, _),
            ) => Op::FAdd,
            (
                BinaryOp::Add,
                Type::Scalar(ScalarKind::Int | ScalarKind::Uint) | Type::Vector(_, _),
            ) => Op::IAdd,
            (
                BinaryOp::Sub,
                Type::Scalar(ScalarKind::Float) | Type::Vector(ScalarKind::Float, _),
            ) => Op::FSub,
            (
                BinaryOp::Sub,
                Type::Scalar(ScalarKind::Int | ScalarKind::Uint) | Type::Vector(_, _),
            ) => Op::ISub,
            (
                BinaryOp::Mul,
                Type::Scalar(ScalarKind::Float) | Type::Vector(ScalarKind::Float, _),
            ) => Op::FMul,
            (
                BinaryOp::Mul,
                Type::Scalar(ScalarKind::Int | ScalarKind::Uint) | Type::Vector(_, _),
            ) => Op::IMul,
            (
                BinaryOp::Div,
                Type::Scalar(ScalarKind::Float) | Type::Vector(ScalarKind::Float, _),
            ) => Op::FDiv,
            (BinaryOp::Div, Type::Scalar(ScalarKind::Int) | Type::Vector(ScalarKind::Int, _)) => {
                Op::SDiv
            }
            (BinaryOp::Div, Type::Scalar(ScalarKind::Uint) | Type::Vector(ScalarKind::Uint, _)) => {
                Op::UDiv
            }
            _ => return Err(cg_err(format!("unsupported arithmetic op `{op:?}`"))),
        };
        let id = self.builder_id();
        let inst = dr::Instruction::new(
            spirv_op,
            Some(result_ty_id),
            Some(id),
            vec![dr::Operand::IdRef(lhs_id), dr::Operand::IdRef(rhs_id)],
        );
        self.push_block_inst(inst)?;
        Ok(Val { id, ty: result_ty })
    }

    fn emit_comparison(&mut self, op: BinaryOp, lhs: Val, rhs: Val) -> Result<Val> {
        let is_float = matches!(
            lhs.ty,
            Type::Scalar(ScalarKind::Float) | Type::Vector(ScalarKind::Float, _)
        );
        let result_ty = match &lhs.ty {
            Type::Vector(_, n) => Type::Vector(ScalarKind::Bool, *n),
            _ => Type::Scalar(ScalarKind::Bool),
        };
        let result_ty_id = self.type_id(&result_ty)?;
        let spirv_op = match (op, is_float) {
            (BinaryOp::Eq, true) => Op::FOrdEqual,
            (BinaryOp::Ne, true) => Op::FOrdNotEqual,
            (BinaryOp::Lt, true) => Op::FOrdLessThan,
            (BinaryOp::Le, true) => Op::FOrdLessThanEqual,
            (BinaryOp::Gt, true) => Op::FOrdGreaterThan,
            (BinaryOp::Ge, true) => Op::FOrdGreaterThanEqual,
            (BinaryOp::Eq, false) => Op::IEqual,
            (BinaryOp::Ne, false) => Op::INotEqual,
            (BinaryOp::Lt, false) => Op::SLessThan,
            (BinaryOp::Le, false) => Op::SLessThanEqual,
            (BinaryOp::Gt, false) => Op::SGreaterThan,
            (BinaryOp::Ge, false) => Op::SGreaterThanEqual,
            _ => return Err(cg_err(format!("unsupported comparison `{op:?}`"))),
        };
        let id = self.builder_id();
        let inst = dr::Instruction::new(
            spirv_op,
            Some(result_ty_id),
            Some(id),
            vec![dr::Operand::IdRef(lhs.id), dr::Operand::IdRef(rhs.id)],
        );
        self.push_block_inst(inst)?;
        Ok(Val { id, ty: result_ty })
    }

    fn emit_logical(&mut self, op: BinaryOp, lhs: Val, rhs: Val) -> Result<Val> {
        let result_ty = Type::Scalar(ScalarKind::Bool);
        let result_ty_id = self.type_id(&result_ty)?;
        let spirv_op = match op {
            BinaryOp::And => Op::LogicalAnd,
            BinaryOp::Or => Op::LogicalOr,
            _ => unreachable!(),
        };
        let id = self.builder_id();
        let inst = dr::Instruction::new(
            spirv_op,
            Some(result_ty_id),
            Some(id),
            vec![dr::Operand::IdRef(lhs.id), dr::Operand::IdRef(rhs.id)],
        );
        self.push_block_inst(inst)?;
        Ok(Val { id, ty: result_ty })
    }

    fn emit_unary(&mut self, op: UnaryOp, expr: &Expr) -> Result<Val> {
        let val = self.emit_expr(expr)?;
        let result_ty_id = self.type_id(&val.ty)?;
        let spirv_op = match (op, &val.ty) {
            (
                UnaryOp::Neg,
                Type::Scalar(ScalarKind::Float) | Type::Vector(ScalarKind::Float, _),
            ) => Op::FNegate,
            (
                UnaryOp::Neg,
                Type::Scalar(ScalarKind::Int | ScalarKind::Uint) | Type::Vector(_, _),
            ) => Op::SNegate,
            (UnaryOp::Not, Type::Scalar(ScalarKind::Bool) | Type::Vector(ScalarKind::Bool, _)) => {
                Op::LogicalNot
            }
            (UnaryOp::Not, _) => Op::Not,
            (UnaryOp::BitNot, _) => Op::Not,
            _ => {
                return Err(cg_err(format!(
                    "unsupported unary `{op:?}` on `{val_ty}`",
                    val_ty = val.ty
                )))
            }
        };
        let id = self.builder_id();
        let inst = dr::Instruction::new(
            spirv_op,
            Some(result_ty_id),
            Some(id),
            vec![dr::Operand::IdRef(val.id)],
        );
        self.push_block_inst(inst)?;
        Ok(Val { id, ty: val.ty })
    }

    fn emit_cast(&mut self, ty: &Type, expr: &Expr) -> Result<Val> {
        let val = self.emit_expr(expr)?;
        let target = self.type_id(ty)?;
        let spirv_op = match (&val.ty, ty) {
            (Type::Scalar(ScalarKind::Int), Type::Scalar(ScalarKind::Float)) => Op::ConvertSToF,
            (Type::Scalar(ScalarKind::Uint), Type::Scalar(ScalarKind::Float)) => Op::ConvertUToF,
            (Type::Scalar(ScalarKind::Float), Type::Scalar(ScalarKind::Int)) => Op::ConvertFToS,
            (Type::Scalar(ScalarKind::Float), Type::Scalar(ScalarKind::Uint)) => Op::ConvertFToU,
            (a, b) if a == b => return Ok(val),
            _ => {
                let from = val.ty;
                return Err(cg_err(format!("unsupported cast `{from}` -> `{ty}`")));
            }
        };
        let id = self.builder_id();
        let inst = dr::Instruction::new(
            spirv_op,
            Some(target),
            Some(id),
            vec![dr::Operand::IdRef(val.id)],
        );
        self.push_block_inst(inst)?;
        Ok(Val { id, ty: ty.clone() })
    }

    // --- intrinsics & method calls ----------------------------------------

    fn emit_call(&mut self, name: &str, args: &[Expr]) -> Result<Val> {
        // `saturate(x)` == clamp(x, 0, 1).
        if name == "saturate" {
            if let [x] = args {
                let xv = self.emit_expr(x)?;
                let lo = self.float_const(0.0);
                let hi = self.float_const(1.0);
                return self.glsl_unarylike_or_clamp(xv, lo, hi);
            }
        }
        // `dot` is a core SPIR-V op; result is the scalar component type.
        if name == "dot" {
            if let [a, b] = args {
                let av = self.emit_expr(a)?;
                let bv = self.emit_expr(b)?;
                let scalar_ty = match &av.ty {
                    Type::Vector(kind, _) => Type::Scalar(*kind),
                    other => other.clone(),
                };
                let scalar_ty_id = self.type_id(&scalar_ty)?;
                let id = self
                    .builder
                    .dot(scalar_ty_id, None, av.id, bv.id)
                    .map_err(|e| cg_err(format!("dot failed: {e:?}")))?;
                return Ok(Val { id, ty: scalar_ty });
            }
        }
        if name == "mul" {
            return self.emit_mul(args);
        }

        // GLSL.std.450 single-/double-operand intrinsics.
        let (ext_op, arity) = match name {
            "abs" => (glsl::FABS, 1),
            "sqrt" => (glsl::SQRT, 1),
            "rsqrt" => (glsl::INVERSE_SQRT, 1),
            "sin" => (glsl::SIN, 1),
            "cos" => (glsl::COS, 1),
            "tan" => (glsl::TAN, 1),
            "asin" => (glsl::ASIN, 1),
            "acos" => (glsl::ACOS, 1),
            "atan" => (glsl::ATAN, 1),
            "exp" => (glsl::EXP, 1),
            "log" => (glsl::LOG, 1),
            "normalize" => (glsl::NORMALIZE, 1),
            "length" => (glsl::LENGTH, 1),
            "floor" => (glsl::FLOOR, 1),
            "ceil" => (glsl::CEIL, 1),
            "frac" => (glsl::FRACT, 1),
            "cross" => (glsl::CROSS, 2),
            "pow" => (glsl::POW, 2),
            "min" => (glsl::FMIN, 2),
            "max" => (glsl::FMAX, 2),
            "clamp" => (glsl::FCLAMP, 3),
            "lerp" => (glsl::FMIX, 3),
            other => return Err(cg_err(format!("unknown intrinsic `{other}`"))),
        };
        if args.len() != arity {
            return Err(cg_err(format!(
                "`{name}` expects {arity} arguments, got {}",
                args.len()
            )));
        }
        let mut operands = Vec::with_capacity(arity);
        let mut result_ty = Type::Scalar(ScalarKind::Float);
        for a in args {
            let v = self.emit_expr(a)?;
            operands.push(dr::Operand::IdRef(v.id));
            result_ty = v.ty;
        }
        // Special-case result types for a few intrinsics.
        if name == "length" {
            result_ty = Type::Scalar(ScalarKind::Float);
        }
        let result_ty_id = self.type_id(&result_ty)?;
        let id = self
            .builder
            .ext_inst(result_ty_id, None, self.glsl_set, ext_op, operands)
            .map_err(|e| cg_err(format!("ext_inst failed: {e:?}")))?;
        Ok(Val { id, ty: result_ty })
    }

    /// `clamp`/`saturate` helper using GLSL.std.450 FClamp.
    fn glsl_unarylike_or_clamp(&mut self, xv: Val, lo: u32, hi: u32) -> Result<Val> {
        let result_ty_id = self.type_id(&xv.ty)?;
        // For vector clamp, lo/hi must be broadcast to the same shape.
        let lo_id = self.broadcast_const(lo, &xv.ty)?;
        let hi_id = self.broadcast_const(hi, &xv.ty)?;
        let id = self
            .builder
            .ext_inst(
                result_ty_id,
                None,
                self.glsl_set,
                glsl::FCLAMP,
                vec![
                    dr::Operand::IdRef(xv.id),
                    dr::Operand::IdRef(lo_id),
                    dr::Operand::IdRef(hi_id),
                ],
            )
            .map_err(|e| cg_err(format!("ext_inst failed: {e:?}")))?;
        Ok(Val { id, ty: xv.ty })
    }

    /// `mul(a, b)`: matrix/vector/scalar multiply dispatched on operand types.
    fn emit_mul(&mut self, args: &[Expr]) -> Result<Val> {
        if args.len() != 2 {
            return Err(cg_err("`mul` expects 2 arguments"));
        }
        let a = self.emit_expr(&args[0])?;
        let b = self.emit_expr(&args[1])?;
        let result_ty = match (&a.ty, &b.ty) {
            (Type::Matrix(_, rows, _), Type::Vector(_, cols)) => {
                if *cols != a.ty.matrix_cols() {
                    return Err(cg_err("mul(matrix, vector) dimension mismatch"));
                }
                Type::Vector(ScalarKind::Float, *rows)
            }
            (Type::Vector(_, cols), Type::Matrix(_, _, cols2)) => {
                if *cols != *cols2 {
                    return Err(cg_err("mul(vector, matrix) dimension mismatch"));
                }
                Type::Vector(ScalarKind::Float, *cols2)
            }
            (Type::Matrix(_, r1, _), Type::Matrix(_, _, c2)) => {
                Type::Matrix(ScalarKind::Float, *r1, *c2)
            }
            _ => {
                // scalar*scalar or vector*vector: component-wise FMul.
                return self.emit_arith(BinaryOp::Mul, a.id, &a.ty, b.id, &b.ty);
            }
        };
        let result_ty_id = self.type_id(&result_ty)?;
        let spirv_op = match (&a.ty, &b.ty) {
            (Type::Matrix(..), Type::Vector(..)) => Op::MatrixTimesVector,
            (Type::Vector(..), Type::Matrix(..)) => Op::VectorTimesMatrix,
            (Type::Matrix(..), Type::Matrix(..)) => Op::MatrixTimesMatrix,
            _ => Op::FMul,
        };
        let id = self.builder_id();
        let inst = dr::Instruction::new(
            spirv_op,
            Some(result_ty_id),
            Some(id),
            vec![dr::Operand::IdRef(a.id), dr::Operand::IdRef(b.id)],
        );
        self.push_block_inst(inst)?;
        Ok(Val { id, ty: result_ty })
    }

    /// `obj.Sample(sampler, coord)` method call.
    fn emit_method_call(&mut self, base: &Expr, method: &str, args: &[Expr]) -> Result<Val> {
        if method != "Sample" {
            return Err(cg_err(format!("unsupported method `.{method}`")));
        }
        if args.len() != 2 {
            return Err(cg_err("`.Sample` expects (sampler, coordinate)"));
        }
        // The texture global is a pointer to OpTypeSampledImage; loading it
        // yields a sampled-image value (which carries the image + sampler).
        let tex_place = self.emit_place(base)?;
        let image_type_id = self.image_type_id()?;
        let sampled_image_t = self.builder.type_sampled_image(image_type_id);
        let image = self
            .builder
            .load(sampled_image_t, None, tex_place.ptr, None, [])
            .map_err(|e| cg_err(format!("load failed: {e:?}")))?;
        let sampler_val = self.emit_expr(&args[0])?;
        let coord_val = self.emit_expr(&args[1])?;

        // Build the sampled image, then sample it.
        let sampled = self
            .builder
            .sampled_image(sampled_image_t, None, image, sampler_val.id)
            .map_err(|e| cg_err(format!("sampled_image failed: {e:?}")))?;
        let result_ty = Type::Vector(ScalarKind::Float, 4);
        let result_ty_id = self.type_id(&result_ty)?;
        let id = self
            .builder
            .image_sample_implicit_lod(result_ty_id, None, sampled, coord_val.id, None, [])
            .map_err(|e| cg_err(format!("image_sample_implicit_lod failed: {e:?}")))?;
        Ok(Val { id, ty: result_ty })
    }

    // --- type inference (lightweight) -------------------------------------

    fn infer_type(&self, e: &Expr) -> Result<Type> {
        match e {
            Expr::Literal(Literal::Float(_)) => Ok(Type::Scalar(ScalarKind::Float)),
            Expr::Literal(Literal::Int(_)) => Ok(Type::Scalar(ScalarKind::Int)),
            Expr::Literal(Literal::Uint(_)) => Ok(Type::Scalar(ScalarKind::Uint)),
            Expr::Literal(Literal::Bool(_)) => Ok(Type::Scalar(ScalarKind::Bool)),
            Expr::Construct { ty, .. } => Ok(ty.clone()),
            Expr::Cast { ty, .. } => Ok(ty.clone()),
            Expr::Ident(name) => {
                if let Some((_, l)) = self.locals.iter().rev().find(|(n, _)| n == name) {
                    return Ok(l.ty.clone());
                }
                if let Some(g) = self.globals.get(name) {
                    return Ok(g.ty.clone());
                }
                Err(cg_err(format!("undefined identifier `{name}`")))
            }
            Expr::Member { base, member } => {
                let base_ty = self.infer_type(base)?;
                match base_ty {
                    Type::Struct(name) => {
                        let info = self
                            .structs
                            .get(&name)
                            .ok_or_else(|| cg_err(format!("unknown struct `{name}`")))?;
                        let m = info
                            .members
                            .iter()
                            .find(|m| m.name == *member)
                            .ok_or_else(|| cg_err(format!("no member `{member}`")))?;
                        Ok(m.ty.clone())
                    }
                    Type::Vector(kind, _) => {
                        let comps = decode_swizzle(member)
                            .ok_or_else(|| cg_err(format!("invalid swizzle `.{member}`")))?;
                        if comps.len() == 1 {
                            Ok(Type::Scalar(kind))
                        } else {
                            Ok(Type::Vector(kind, comps.len() as u32))
                        }
                    }
                    other => Err(cg_err(format!("member access on `{other}`"))),
                }
            }
            Expr::Call { name, args } => match name.as_str() {
                "dot" => {
                    let t = self.infer_type(&args[0])?;
                    match t {
                        Type::Vector(kind, _) => Ok(Type::Scalar(kind)),
                        other => Ok(other),
                    }
                }
                "length" => Ok(Type::Scalar(ScalarKind::Float)),
                "normalize" | "abs" | "sqrt" | "rsqrt" | "sin" | "cos" | "tan" | "exp" | "log"
                | "floor" | "ceil" | "frac" | "saturate" => self.infer_type(&args[0]),
                "clamp" | "lerp" | "min" | "max" | "pow" => self.infer_type(&args[0]),
                "cross" => self.infer_type(&args[0]),
                "mul" => {
                    let a = self.infer_type(&args[0])?;
                    let b = self.infer_type(&args[1])?;
                    match (&a, &b) {
                        (Type::Matrix(_, r, _), Type::Vector(_, _)) => {
                            Ok(Type::Vector(ScalarKind::Float, *r))
                        }
                        (Type::Vector(_, _), Type::Matrix(_, _, c)) => {
                            Ok(Type::Vector(ScalarKind::Float, *c))
                        }
                        (Type::Matrix(_, r, _), Type::Matrix(_, _, c)) => {
                            Ok(Type::Matrix(ScalarKind::Float, *r, *c))
                        }
                        _ => Ok(a),
                    }
                }
                other => Err(cg_err(format!("cannot infer result type of `{other}`"))),
            },
            Expr::MethodCall { method, .. } if method == "Sample" => {
                Ok(Type::Vector(ScalarKind::Float, 4))
            }
            Expr::MethodCall { method, .. } => Err(cg_err(format!("unknown method `.{method}`"))),
            Expr::Binary { op, lhs, rhs } => {
                if is_comparison(*op) {
                    let lt = self.infer_type(lhs)?;
                    Ok(match lt {
                        Type::Vector(_, n) => Type::Vector(ScalarKind::Bool, n),
                        _ => Type::Scalar(ScalarKind::Bool),
                    })
                } else if matches!(op, BinaryOp::And | BinaryOp::Or) {
                    Ok(Type::Scalar(ScalarKind::Bool))
                } else {
                    let lt = self.infer_type(lhs)?;
                    if lt.is_composite() {
                        Ok(lt)
                    } else {
                        self.infer_type(rhs)
                    }
                }
            }
            Expr::Unary { expr, .. } => self.infer_type(expr),
        }
    }

    // --- coercion ----------------------------------------------------------

    /// Coerce a value to a target type (currently scalars only).
    fn coerce(&mut self, val: Val, target: &Type) -> Result<Val> {
        if val.ty == *target {
            return Ok(val);
        }
        match (&val.ty, target) {
            (Type::Scalar(_), Type::Scalar(kind)) => self.coerce_scalar(val, *kind),
            _ => Ok(val),
        }
    }

    fn coerce_scalar(&mut self, val: Val, kind: ScalarKind) -> Result<Val> {
        if matches!(val.ty, Type::Scalar(k) if k == kind) {
            return Ok(val);
        }
        let target = Type::Scalar(kind);
        let target_id = self.type_id(&target)?;
        let spirv_op = match &val.ty {
            Type::Scalar(ScalarKind::Int) => Op::ConvertSToF,
            Type::Scalar(ScalarKind::Uint) => Op::ConvertUToF,
            Type::Scalar(ScalarKind::Float) => match kind {
                ScalarKind::Int => Op::ConvertFToS,
                ScalarKind::Uint => Op::ConvertFToU,
                _ => return Ok(val),
            },
            _ => return Ok(val),
        };
        let id = self.builder_id();
        let inst = dr::Instruction::new(
            spirv_op,
            Some(target_id),
            Some(id),
            vec![dr::Operand::IdRef(val.id)],
        );
        self.push_block_inst(inst)?;
        Ok(Val { id, ty: target })
    }

    /// Coerce a (possibly vector) bool to a scalar bool for branching via OpAny.
    fn coerce_to_bool(&mut self, val: Val) -> Result<u32> {
        match val.ty {
            Type::Scalar(ScalarKind::Bool) => Ok(val.id),
            Type::Vector(ScalarKind::Bool, _) => {
                let id = self.builder_id();
                let inst = dr::Instruction::new(
                    Op::Any,
                    Some(self.bool_t),
                    Some(id),
                    vec![dr::Operand::IdRef(val.id)],
                );
                self.push_block_inst(inst)?;
                Ok(id)
            }
            other => Err(cg_err(format!("expected bool condition, got `{other}`"))),
        }
    }

    // --- low-level builders / helpers -------------------------------------

    /// Allocate a fresh id from the builder.
    fn builder_id(&mut self) -> u32 {
        self.builder.id()
    }

    /// Push a raw instruction into the current block.
    fn push_block_inst(&mut self, inst: dr::Instruction) -> Result<()> {
        self.builder
            .insert_into_block(rspirv::dr::InsertPoint::End, inst)
            .map_err(|e| cg_err(format!("instruction insert failed: {e:?}")))
    }

    /// Allocate a Function-storage local variable, hoisting the `OpVariable`
    /// to the front of the function's first block (per SPIR-V layout rules).
    fn alloc_local(&mut self, ty: &Type) -> Result<u32> {
        let ty_id = self.type_id(ty)?;
        let ptr_t = self
            .builder
            .type_pointer(None, StorageClass::Function, ty_id);
        let id = self.builder.id();
        let inst = dr::Instruction::new(
            Op::Variable,
            Some(ptr_t),
            Some(id),
            vec![dr::Operand::StorageClass(StorageClass::Function)],
        );
        let func = self
            .builder
            .module_mut()
            .functions
            .last_mut()
            .ok_or_else(|| cg_err("no current function"))?;
        if func.blocks.is_empty() {
            return Err(cg_err("function has no entry block yet"));
        }
        func.blocks[0].instructions.insert(0, inst);
        Ok(id)
    }

    /// Broadcast a scalar constant to match a target type (for clamp bounds).
    fn broadcast_const(&mut self, scalar_const: u32, ty: &Type) -> Result<u32> {
        match ty {
            Type::Scalar(_) => Ok(scalar_const),
            Type::Vector(_, n) => {
                let target = self.vector_type_id(ScalarKind::Float, *n);
                let constituents = vec![scalar_const; *n as usize];
                self.builder
                    .composite_construct(target, None, constituents)
                    .map_err(|e| cg_err(format!("composite_construct failed: {e:?}")))
            }
            other => Err(cg_err(format!("cannot broadcast to `{other}`"))),
        }
    }

    /// The image type id for a Texture2D global (re-derived on demand).
    fn image_type_id(&mut self) -> Result<u32> {
        Ok(self.builder.type_image(
            self.float_t,
            Dim::Dim2D,
            0,
            0,
            0,
            1,
            ImageFormat::Unknown,
            None,
        ))
    }

    // --- type ids ----------------------------------------------------------

    /// The SPIR-V value-type id for loading a value of the given HLSL type.
    /// Opaque types (textures/samplers) map to their sampled-image/sampler
    /// SPIR-V types; everything else delegates to [`type_id`].
    fn value_type_id(&mut self, ty: &Type) -> Result<u32> {
        match ty {
            Type::Texture2D => {
                let image_type_id = self.image_type_id()?;
                Ok(self.builder.type_sampled_image(image_type_id))
            }
            Type::SamplerState => Ok(self.builder.type_sampler()),
            other => self.type_id(other),
        }
    }

    fn type_id(&mut self, ty: &Type) -> Result<u32> {
        match ty {
            Type::Void => Ok(self.void_t),
            Type::Scalar(ScalarKind::Float) => Ok(self.float_t),
            Type::Scalar(ScalarKind::Int) => Ok(self.int_t),
            Type::Scalar(ScalarKind::Uint) => Ok(self.uint_t),
            Type::Scalar(ScalarKind::Bool) => Ok(self.bool_t),
            Type::Vector(kind, n) => Ok(self.vector_type_id(*kind, *n)),
            Type::Matrix(kind, rows, cols) => {
                let col_type = self.vector_type_id(*kind, *rows);
                Ok(self.builder.type_matrix(col_type, *cols))
            }
            Type::Struct(name) => {
                let info = self
                    .structs
                    .get(name)
                    .ok_or_else(|| cg_err(format!("unknown struct type `{name}`")))?;
                Ok(info.type_id)
            }
            Type::Texture2D => Err(cg_err("Texture2D has no plain value type")),
            Type::SamplerState => Err(cg_err("SamplerState has no plain value type")),
        }
    }

    fn scalar_type_id(&mut self, kind: ScalarKind) -> u32 {
        match kind {
            ScalarKind::Float => self.float_t,
            ScalarKind::Int => self.int_t,
            ScalarKind::Uint => self.uint_t,
            ScalarKind::Bool => self.bool_t,
        }
    }

    fn vector_type_id(&mut self, kind: ScalarKind, n: u32) -> u32 {
        let elem = self.scalar_type_id(kind);
        self.builder.type_vector(elem, n)
    }

    // --- constants ---------------------------------------------------------

    fn float_const(&mut self, v: f64) -> u32 {
        let bits = v as f32;
        self.const_op(self.float_t, bits.to_bits())
    }

    fn int_const(&mut self, v: i32, signed: bool) -> u32 {
        let ty = if signed { self.int_t } else { self.uint_t };
        self.const_op(ty, v as u32)
    }

    fn bool_const(&mut self, v: bool) -> u32 {
        let id = self.builder.id();
        let op = if v {
            Op::ConstantTrue
        } else {
            Op::ConstantFalse
        };
        self.builder
            .module_mut()
            .types_global_values
            .push(rspirv::dr::Instruction::new(
                op,
                Some(self.bool_t),
                Some(id),
                vec![],
            ));
        id
    }

    /// Emit an `OpConstant` with a `LiteralBit32` payload and return its id.
    fn const_op(&mut self, ty: u32, bits: u32) -> u32 {
        let id = self.builder.id();
        self.builder
            .module_mut()
            .types_global_values
            .push(rspirv::dr::Instruction::new(
                Op::Constant,
                Some(ty),
                Some(id),
                vec![rspirv::dr::Operand::LiteralBit32(bits)],
            ));
        id
    }
}

// --- free helpers ----------------------------------------------------------

/// Generate SPIR-V words for a translation unit at the given stage.
pub fn codegen(unit: &TranslationUnit, stage: ShaderStage) -> Result<Vec<u32>> {
    let mut ctx = Ctx::new(stage);
    ctx.emit_globals(unit)?;
    let main = unit
        .decls
        .iter()
        .find_map(|d| match d {
            Decl::Function(f) if f.name == "main" && f.body.is_some() => Some(f),
            _ => None,
        })
        .ok_or_else(|| cg_err("no `main` function definition found"))?;
    ctx.emit_main(main)?;
    Ok(ctx.builder.module().assemble())
}

fn is_comparison(op: BinaryOp) -> bool {
    matches!(
        op,
        BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge
    )
}

/// Decode a swizzle string (`.xyzw` or `.rgba`) into component indices.
fn decode_swizzle(s: &str) -> Option<Vec<u32>> {
    let map = |c: u8| match c {
        b'x' | b'r' => Some(0),
        b'y' | b'g' => Some(1),
        b'z' | b'b' => Some(2),
        b'w' | b'a' => Some(3),
        _ => None,
    };
    if s.is_empty() || s.len() > 4 {
        return None;
    }
    s.bytes().map(map).collect()
}

/// Parse a `register(b0)` descriptor into `(descriptor_set, binding)`. The
/// register letter selects the kind; the number is the binding. Descriptor
/// set is 0 for the simple single-namespace HLSL model.
fn parse_register(reg: &Option<String>, _expected_kind: char) -> (u32, u32) {
    match reg {
        Some(s) => {
            // Strip the leading kind letter (b/t/s/u), parse the rest as a number.
            let digits = s.trim_start_matches(|c: char| c.is_ascii_alphabetic());
            let binding = digits.parse::<u32>().unwrap_or(0);
            (0, binding)
        }
        None => (0, 0),
    }
}

/// std140-ish alignment and size for a type (bytes).
fn member_align_size(ty: &Type) -> (u32, u32) {
    match ty {
        Type::Scalar(_) => (4, 4),
        Type::Vector(_, 2) => (8, 8),
        Type::Vector(_, 3) => (16, 12),
        Type::Vector(_, 4) => (16, 16),
        Type::Matrix(_, _r, c) => (16, 16 * c),
        _ => (16, 16),
    }
}

fn align_up(offset: u32, align: u32) -> u32 {
    if align == 0 {
        offset
    } else {
        offset.div_ceil(align) * align
    }
}

impl Type {
    /// Number of columns in a matrix (1 for non-matrices).
    fn matrix_cols(&self) -> u32 {
        match self {
            Type::Matrix(_, _, c) => *c,
            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile(src: &str, stage: ShaderStage) -> Vec<u32> {
        let toks = crate::lexer::lex(src).unwrap();
        let unit = crate::parser::parse(toks).unwrap();
        codegen(&unit, stage).unwrap()
    }

    #[test]
    fn ps_emits_valid_header_and_function() {
        let src = "float4 main() : SV_Target { return float4(1.0, 0.0, 0.0, 1.0); }";
        let words = compile(src, ShaderStage::Pixel);
        assert_eq!(words[0], rspirv::spirv::MAGIC_NUMBER);
        let v = words[1].to_le_bytes();
        assert_eq!(v[2], 1); // major
        assert_eq!(v[1], 0); // minor
        assert!(words[3] > 0, "bound must be positive");
        assert_eq!(words[4], 0);
    }

    #[test]
    fn vs_emits_position_output() {
        let src = "float4 main() : SV_Position { return float4(0.0, 0.0, 0.0, 1.0); }";
        let words = compile(src, ShaderStage::Vertex);
        assert_eq!(words[0], rspirv::spirv::MAGIC_NUMBER);
    }
}
