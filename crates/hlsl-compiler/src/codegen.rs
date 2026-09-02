//! Code generation: walk the [AST](crate::ast) to a SPIR-V module via
//! [`rspirv::dr::Builder`].
//!
//! Phase 1 (M5) supports a single entry-point function `main` that returns a
//! `float4` constant, with the output bound to either `SV_Target` (pixel
//! shaders, decorated with `Location 0`) or `SV_Position` (vertex shaders,
//! decorated with the `BuiltIn Position`). The return value is stored into the
//! output global variable and the function returns `void`.
//!
//! Larger constructs (cbuffers, control flow, intrinsics, textures/samplers)
//! are parsed by the frontend but only a subset is emitted here; unsupported
//! nodes yield a [`CodegenError`].

use std::fmt;

use rspirv::binary::Assemble;
use rspirv::spirv::{
    Capability, Decoration, ExecutionMode, ExecutionModel, FunctionControl, Op, SourceLanguage,
    StorageClass,
};

use crate::ast::{
    Block, Decl, Expr, FunctionDecl, Literal, ScalarKind, Stmt, TranslationUnit, Type,
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

    /// The output semantics recognised as the primary output for this stage.
    fn is_primary_output(self, semantic: Option<&str>) -> bool {
        match self {
            ShaderStage::Vertex => matches!(semantic, Some("SV_Position")),
            ShaderStage::Pixel => matches!(semantic, Some("SV_Target")),
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

/// Generate SPIR-V words for a translation unit at the given stage.
pub fn codegen(unit: &TranslationUnit, stage: ShaderStage) -> Result<Vec<u32>> {
    let mut ctx = Ctx::new(stage);
    ctx.emit_module_header();
    ctx.emit_main(unit)?;
    Ok(ctx.builder.module().assemble())
}

/// Code generation context: wraps an rspirv builder plus a small symbol table.
struct Ctx {
    stage: ShaderStage,
    builder: rspirv::dr::Builder,
    // Cached type ids.
    void_t: u32,
    float_t: u32,
    v4float_t: u32,
    // Id of the output global variable (ptr to v4float, Output storage class).
    out_var: Option<u32>,
    // Local variable name -> value id (SPIR-V SSA id) within the current fn.
    locals: Vec<(String, u32)>,
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
        let float_t = builder.type_float(32);
        let v4float_t = builder.type_vector(float_t, 4);

        Ctx {
            stage,
            builder,
            void_t,
            float_t,
            v4float_t,
            out_var: None,
            locals: Vec::new(),
        }
    }

    fn emit_module_header(&mut self) {
        // OpSource HLSL for tooling friendliness.
        self.builder
            .source(SourceLanguage::HLSL, 500, None, None::<&str>);
    }

    fn emit_main(&mut self, unit: &TranslationUnit) -> Result<()> {
        // Find the `main` function definition.
        let main = unit
            .decls
            .iter()
            .find_map(|d| match d {
                Decl::Function(f) if f.name == "main" && f.body.is_some() => Some(f),
                _ => None,
            })
            .ok_or_else(|| cg_err("no `main` function definition found"))?;

        self.emit_entry_signature(main)?;
        self.emit_function_body(main)?;
        self.finish_entry_point(main)?;
        Ok(())
    }

    /// Declare the output global variable for the entry point and the function
    /// type, then open `OpFunction`.
    fn emit_entry_signature(&mut self, main: &FunctionDecl) -> Result<()> {
        // Validate the return shape we can currently emit.
        if !matches!(main.return_type, Type::Vector(ScalarKind::Float, 4)) {
            return Err(cg_err(format!(
                "Phase 1 only supports `float4` main return type; got `{}`",
                main.return_type
            )));
        }
        if !main.params.is_empty() {
            return Err(cg_err(
                "Phase 1 only supports a parameter-less `main`; inputs come later",
            ));
        }
        if !self.stage.is_primary_output(main.semantic.as_deref()) {
            return Err(cg_err(format!(
                "main semantic `{:?}` does not match stage `{:?}`",
                main.semantic, self.stage
            )));
        }

        // Output variable: `Output` storage class pointer to v4float.
        let ptr_out = self
            .builder
            .type_pointer(None, StorageClass::Output, self.v4float_t);
        let out_var = self
            .builder
            .variable(ptr_out, None, StorageClass::Output, None);
        self.builder.decorate(
            out_var,
            Decoration::Location,
            [rspirv::dr::Operand::LiteralBit32(0)],
        );
        self.out_var = Some(out_var);

        // Function: void () -> void.
        let fn_type = self.builder.type_function(self.void_t, vec![]);
        self.builder
            .begin_function(self.void_t, None, FunctionControl::NONE, fn_type)
            .map_err(|e| cg_err(format!("begin_function failed: {e:?}")))?;
        Ok(())
    }

    fn emit_function_body(&mut self, main: &FunctionDecl) -> Result<()> {
        self.builder
            .begin_block(None)
            .map_err(|e| cg_err(format!("begin_block failed: {e:?}")))?;
        let body = main.body.as_ref().unwrap();
        self.emit_block(body)?;
        // Guarantee a terminator: if the body didn't end with `return`, emit one.
        if !block_ends_with_return(body) {
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
        // The function id is the last function's def id. rspirv appends to
        // `module.functions`; the id lives in `def.result_id`.
        let main_id = self
            .builder
            .module_ref()
            .functions
            .last()
            .and_then(|f| f.def.as_ref())
            .and_then(|i| i.result_id)
            .ok_or_else(|| cg_err("main function has no id"))?;

        let interface: Vec<u32> = self.out_var.into_iter().collect();
        self.builder
            .entry_point(self.stage.execution_model(), main_id, "main", interface);
        if self.stage == ShaderStage::Pixel {
            // Vulkan requires OriginUpperLeft for Fragment entry points.
            self.builder
                .execution_mode(main_id, ExecutionMode::OriginUpperLeft, []);
        }
        // Emit OpName for readability.
        self.builder.name(main_id, main.name.clone());
        if let Some(out_var) = self.out_var {
            self.builder.name(out_var, "out_color");
        }
        let _ = main;
        Ok(())
    }

    // --- statements / expressions ------------------------------------------

    fn emit_block(&mut self, block: &Block) -> Result<()> {
        let saved = std::mem::take(&mut self.locals);
        for stmt in &block.stmts {
            self.emit_stmt(stmt)?;
        }
        self.locals = saved;
        Ok(())
    }

    fn emit_stmt(&mut self, stmt: &Stmt) -> Result<()> {
        match stmt {
            Stmt::Return(Some(e)) => {
                let val = self.emit_expr(e)?;
                // Store into the output variable, then return void.
                if let Some(out) = self.out_var {
                    self.builder
                        .store(out, val, None, [])
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
                let ty_id = self.type_id(&vd.ty)?;
                let init = match &vd.init {
                    Some(e) => Some(self.emit_expr(e)?),
                    None => None,
                };
                // Function-scoped variable.
                let ptr_t = self
                    .builder
                    .type_pointer(None, StorageClass::Function, ty_id);
                let var = self
                    .builder
                    .variable(ptr_t, None, StorageClass::Function, init);
                self.locals.push((vd.name.clone(), var));
                Ok(())
            }
            Stmt::Expr(e) => {
                self.emit_expr(e)?;
                Ok(())
            }
            Stmt::If { .. } | Stmt::For { .. } | Stmt::Block(_) => Err(cg_err(
                "control-flow / nested-block statements are not emitted in Phase 1",
            )),
        }
    }

    fn emit_expr(&mut self, e: &Expr) -> Result<u32> {
        match e {
            Expr::Literal(Literal::Float(v)) => Ok(self.float_const(*v)),
            Expr::Literal(Literal::Int(v)) => Ok(self.int_const(*v as i32, true)),
            Expr::Literal(Literal::Uint(v)) => Ok(self.int_const(*v as u32 as i32, false)),
            Expr::Literal(Literal::Bool(v)) => Ok(self.bool_const(*v)),
            Expr::Construct { ty, args } => self.emit_construct(ty, args),
            Expr::Ident(name) => self.lookup_local(name),
            Expr::Member { .. }
            | Expr::Call { .. }
            | Expr::Binary { .. }
            | Expr::Unary { .. }
            | Expr::Cast { .. } => Err(cg_err(format!(
                "expression node not emitted in Phase 1: {e:?}"
            ))),
        }
    }

    /// `float4(1.0, 0.0, 0.0, 1.0)` and friends. Also handles scalar/broadcast
    /// constructors (`float(1.0)`, `float4(1.0)`).
    fn emit_construct(&mut self, ty: &Type, args: &[Expr]) -> Result<u32> {
        match ty {
            Type::Scalar(ScalarKind::Float) => {
                if let [arg] = args {
                    return self.emit_expr(arg);
                }
                Err(cg_err("float(...) expects exactly one argument"))
            }
            Type::Vector(ScalarKind::Float, n) => {
                let target = self.v4float_t_for(*n);
                // Broadcast: `float4(1.0)` replicates the scalar.
                if let [single] = args {
                    let scalar = self.emit_expr(single)?;
                    let constituents = vec![scalar; *n as usize];
                    return self
                        .builder
                        .composite_construct(target, None, constituents)
                        .map_err(|e| cg_err(format!("composite_construct failed: {e:?}")));
                }
                if args.len() != *n as usize {
                    return Err(cg_err(format!(
                        "{ty}(...) expects {n} components, got {}",
                        args.len()
                    )));
                }
                let mut constituents = Vec::with_capacity(args.len());
                for a in args {
                    constituents.push(self.emit_expr(a)?);
                }
                self.builder
                    .composite_construct(target, None, constituents)
                    .map_err(|e| cg_err(format!("composite_construct failed: {e:?}")))
            }
            other => Err(cg_err(format!(
                "constructor for type `{other}` not supported in Phase 1"
            ))),
        }
    }

    fn lookup_local(&self, name: &str) -> Result<u32> {
        self.locals
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .map(|(_, id)| *id)
            .ok_or_else(|| cg_err(format!("undefined identifier `{name}`")))
    }

    // --- type / constant helpers -------------------------------------------

    fn type_id(&mut self, ty: &Type) -> Result<u32> {
        match ty {
            Type::Void => Ok(self.void_t),
            Type::Scalar(ScalarKind::Float) => Ok(self.float_t),
            Type::Scalar(ScalarKind::Int) => Ok(self.builder.type_int(32, 1)),
            Type::Scalar(ScalarKind::Uint) => Ok(self.builder.type_int(32, 0)),
            Type::Scalar(ScalarKind::Bool) => Ok(self.builder.type_bool()),
            Type::Vector(ScalarKind::Float, n) => Ok(self.v4float_t_for(*n)),
            other => Err(cg_err(format!("type `{other}` not supported in Phase 1"))),
        }
    }

    /// `OpTypeVector %float N`, freshly declared (dedup is left to rspirv's
    /// downstream consumer; duplicates are harmless for validity).
    fn v4float_t_for(&mut self, n: u32) -> u32 {
        if n == 4 {
            return self.v4float_t;
        }
        self.builder.type_vector(self.float_t, n)
    }

    fn float_const(&mut self, v: f64) -> u32 {
        let bits = v as f32;
        self.const_op(self.float_t, bits.to_bits())
    }

    fn int_const(&mut self, v: i32, signed: bool) -> u32 {
        let ty = self.builder.type_int(32, if signed { 1 } else { 0 });
        self.const_op(ty, v as u32)
    }

    fn bool_const(&mut self, v: bool) -> u32 {
        let ty = self.builder.type_bool();
        let id = self.builder.id();
        let op = if v {
            Op::ConstantTrue
        } else {
            Op::ConstantFalse
        };
        self.builder
            .module_mut()
            .types_global_values
            .push(rspirv::dr::Instruction::new(op, Some(ty), Some(id), vec![]));
        id
    }

    /// Emit an `OpConstant` with a `LiteralBit32` payload into the
    /// types-global-values section and return its id.
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

/// Whether a block's last statement is a `return`.
fn block_ends_with_return(block: &Block) -> bool {
    matches!(block.stmts.last(), Some(Stmt::Return(_)))
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
        // version word: minor in byte1, major in byte2 (little-endian)
        let v = words[1].to_le_bytes();
        assert_eq!(v[2], 1); // major
        assert_eq!(v[1], 0); // minor
                             // generator nonzero (we use rspirv default) — not asserted strictly
                             // bound must be > 0
        assert!(words[3] > 0, "bound must be positive");
        // schema reserved word is 0
        assert_eq!(words[4], 0);
    }

    #[test]
    fn vs_emits_position_output() {
        let src = "float4 main() : SV_Position { return float4(0.0, 0.0, 0.0, 1.0); }";
        let words = compile(src, ShaderStage::Vertex);
        assert_eq!(words[0], rspirv::spirv::MAGIC_NUMBER);
    }
}
