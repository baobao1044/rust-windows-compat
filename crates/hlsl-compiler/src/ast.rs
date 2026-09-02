//! Abstract syntax tree for the supported HLSL subset.
//!
//! The AST is deliberately permissive: it can represent more than the
//! [codegen](crate::codegen) currently emits, so later milestones (M6+) can
//! extend code generation without reshaping the tree.

use std::fmt;

/// A complete HLSL translation unit (a single file's worth of declarations).
#[derive(Debug, Clone, Default)]
pub struct TranslationUnit {
    /// Top-level declarations in source order.
    pub decls: Vec<Decl>,
}

/// A top-level declaration.
#[derive(Debug, Clone)]
pub enum Decl {
    /// `struct Name { ... }`
    Struct(StructDecl),
    /// `cbuffer Name : register(b0) { ... }`
    CBuffer(CBufferDecl),
    /// A function definition or (forward) declaration.
    Function(FunctionDecl),
    /// A top-level global variable, e.g. `Texture2D tex : register(t0);`.
    GlobalVar(GlobalVarDecl),
}

/// A top-level global variable declaration (e.g. a texture or sampler).
#[derive(Debug, Clone)]
pub struct GlobalVarDecl {
    pub ty: Type,
    pub name: String,
    /// Optional register, e.g. `t0`, `s0`.
    pub register: Option<String>,
}

/// A `struct` declaration.
#[derive(Debug, Clone)]
pub struct StructDecl {
    pub name: String,
    pub members: Vec<StructMember>,
}

/// A member of a `struct`.
#[derive(Debug, Clone)]
pub struct StructMember {
    pub ty: Type,
    pub name: String,
    /// e.g. `SV_Target`, `TEXCOORD0`, `COLOR0`.
    pub semantic: Option<String>,
}

/// A `cbuffer` declaration.
#[derive(Debug, Clone)]
pub struct CBufferDecl {
    pub name: String,
    /// Optional register, e.g. `b0`.
    pub register: Option<String>,
    pub members: Vec<StructMember>,
}

/// A function declaration / definition.
#[derive(Debug, Clone)]
pub struct FunctionDecl {
    pub return_type: Type,
    pub name: String,
    pub params: Vec<Param>,
    /// Output semantic, e.g. `SV_Target` / `SV_Position`.
    pub semantic: Option<String>,
    /// `None` for a forward declaration (prototype).
    pub body: Option<Block>,
}

/// A formal parameter.
#[derive(Debug, Clone)]
pub struct Param {
    pub ty: Type,
    pub name: String,
    pub semantic: Option<String>,
}

/// A type reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type {
    /// `void`
    Void,
    /// Scalar: `float`, `int`, `uint`, `bool`, ...
    Scalar(ScalarKind),
    /// Vector: `float2`, `float3`, `float4`, `int4`, ...
    Vector(ScalarKind, u32),
    /// Matrix: `float4x4`, `float3x4`, ...
    Matrix(ScalarKind, u32, u32),
    /// Named (struct) type.
    Struct(String),
    /// `Texture2D<...>` (opaque; type arg elided for now).
    Texture2D,
    /// `SamplerState`.
    SamplerState,
}

/// The element kind of a scalar/vector/matrix type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarKind {
    Float,
    Int,
    Uint,
    Bool,
}

impl Type {
    /// The component count (1 for scalars, N for vectors, M*N for matrices).
    pub fn component_count(&self) -> u32 {
        match self {
            Type::Void => 0,
            Type::Scalar(_) => 1,
            Type::Vector(_, n) => *n,
            Type::Matrix(_, r, c) => r * c,
            Type::Struct(_) | Type::Texture2D | Type::SamplerState => 0,
        }
    }

    /// Whether this is a vector or matrix (composite) type.
    pub fn is_composite(&self) -> bool {
        matches!(self, Type::Vector(..) | Type::Matrix(..))
    }
}

/// A brace-delimited statement block.
#[derive(Debug, Clone, Default)]
pub struct Block {
    pub stmts: Vec<Stmt>,
}

/// A statement.
#[derive(Debug, Clone)]
pub enum Stmt {
    /// `return <expr>?;`
    Return(Option<Expr>),
    /// `Type name [= expr];`
    VarDecl(VarDecl),
    /// A bare expression statement.
    Expr(Expr),
    /// `if (cond) { ... } else { ... }`
    If {
        cond: Expr,
        then: Block,
        else_: Option<Block>,
    },
    /// `for (init; cond; update) { ... }`
    For {
        init: Option<Box<Stmt>>,
        cond: Option<Expr>,
        update: Option<Expr>,
        body: Block,
    },
    /// `{ ... }`
    Block(Block),
}

/// A local variable declaration.
#[derive(Debug, Clone)]
pub struct VarDecl {
    pub ty: Type,
    pub name: String,
    /// Optional initializer: `= expr`.
    pub init: Option<Expr>,
    /// Optional input semantic (used for struct-shader-style signatures).
    pub semantic: Option<String>,
}

/// An expression.
#[derive(Debug, Clone)]
pub enum Expr {
    /// `1.0`, `0`, `0x1Au`, ...
    Literal(Literal),
    /// An identifier reference.
    Ident(String),
    /// `float4(1.0, 0.0, 0.0, 1.0)` — a type-constructor call.
    Construct { ty: Type, args: Vec<Expr> },
    /// `foo(args)` — an ordinary (intrinsic or user) function call.
    Call { name: String, args: Vec<Expr> },
    /// `obj.method(args)` — a method call (e.g. `tex.Sample(samp, uv)`).
    MethodCall {
        base: Box<Expr>,
        method: String,
        args: Vec<Expr>,
    },
    /// `a.x`, `a.xy`, `color.rgb`, ...
    Member { base: Box<Expr>, member: String },
    /// `a + b`, `a * b`, ...
    Binary {
        op: BinaryOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    /// `-a`, `!a`, `~a`
    Unary { op: UnaryOp, expr: Box<Expr> },
    /// `(Type)expr` — explicit cast.
    Cast { ty: Type, expr: Box<Expr> },
}

/// A literal value.
#[derive(Debug, Clone)]
pub enum Literal {
    Int(i64),
    Uint(u64),
    Float(f64),
    Bool(bool),
}

/// A binary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Assign,
    AddAssign,
    SubAssign,
    MulAssign,
    DivAssign,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    BitAnd,
    BitOr,
    BitXor,
}

/// A unary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Neg,
    Not,
    BitNot,
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Void => write!(f, "void"),
            Type::Scalar(k) => write!(f, "{}", k),
            Type::Vector(k, n) => write!(f, "{}{}", k, n),
            Type::Matrix(k, r, c) => write!(f, "{}{}x{}", k, r, c),
            Type::Struct(name) => write!(f, "{}", name),
            Type::Texture2D => write!(f, "Texture2D"),
            Type::SamplerState => write!(f, "SamplerState"),
        }
    }
}

impl fmt::Display for ScalarKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScalarKind::Float => write!(f, "float"),
            ScalarKind::Int => write!(f, "int"),
            ScalarKind::Uint => write!(f, "uint"),
            ScalarKind::Bool => write!(f, "bool"),
        }
    }
}
