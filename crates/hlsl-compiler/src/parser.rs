//! Recursive-descent parser: `parse(tokens) -> Result<TranslationUnit, ParseError>`.
//!
//! The parser accepts the supported HLSL subset and produces the [AST](crate::ast).
//! It is hand-written and spans-aware; errors point at the offending token.

use std::fmt;

use crate::ast::*;
use crate::lexer::{Keyword, Span, Token, TokenKind};

/// A parse error carrying a span and a message.
#[derive(Debug, Clone)]
pub struct ParseError {
    pub span: Span,
    pub msg: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "parse error at {}..{}: {}",
            self.span.start, self.span.end, self.msg
        )
    }
}

impl std::error::Error for ParseError {}

type Result<T> = std::result::Result<T, ParseError>;

/// Parse a token stream into a translation unit.
pub fn parse(tokens: Vec<Token>) -> Result<TranslationUnit> {
    Parser::new(tokens).parse_unit()
}

struct Parser {
    toks: Vec<Token>,
    /// Index into `toks`; the last token is always `Eof`.
    idx: usize,
}

impl Parser {
    fn new(toks: Vec<Token>) -> Self {
        Parser { toks, idx: 0 }
    }

    // --- token helpers -----------------------------------------------------

    fn peek(&self) -> &TokenKind {
        &self.toks[self.idx].kind
    }

    fn at_eof(&self) -> bool {
        matches!(self.peek(), TokenKind::Eof)
    }

    fn span_here(&self) -> Span {
        self.toks[self.idx].span
    }

    fn bump(&mut self) -> TokenKind {
        let k = self.toks[self.idx].kind.clone();
        if !matches!(k, TokenKind::Eof) {
            self.idx += 1;
        }
        k
    }

    fn eat(&mut self, want: &TokenKind) -> bool {
        if std::mem::discriminant(self.peek()) == std::mem::discriminant(want) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, want: &TokenKind, what: &str) -> Result<()> {
        if std::mem::discriminant(self.peek()) == std::mem::discriminant(want) {
            self.bump();
            Ok(())
        } else {
            Err(self.unexpected(what))
        }
    }

    fn unexpected(&self, what: &str) -> ParseError {
        let span = self.span_here();
        let got = self.peek().describe();
        ParseError {
            span,
            msg: format!("expected {what}, got {got}"),
        }
    }

    fn err(&self, span: Span, msg: impl Into<String>) -> ParseError {
        ParseError {
            span,
            msg: msg.into(),
        }
    }

    // --- grammar ------------------------------------------------------------

    fn parse_unit(&mut self) -> Result<TranslationUnit> {
        let mut decls = Vec::new();
        while !self.at_eof() {
            decls.push(self.parse_decl()?);
        }
        Ok(TranslationUnit { decls })
    }

    fn parse_decl(&mut self) -> Result<Decl> {
        match self.peek() {
            TokenKind::Keyword(Keyword::Struct) => {
                let s = self.parse_struct()?;
                Ok(Decl::Struct(s))
            }
            TokenKind::Keyword(Keyword::CBuffer) => {
                let c = self.parse_cbuffer()?;
                Ok(Decl::CBuffer(c))
            }
            // function or global var beginning with a type
            _ => {
                let f = self.parse_function()?;
                Ok(Decl::Function(f))
            }
        }
    }

    fn parse_struct(&mut self) -> Result<StructDecl> {
        self.expect(&TokenKind::Keyword(Keyword::Struct), "struct")?;
        let name = self.expect_ident("struct name")?;
        self.expect(&TokenKind::LBrace, "{")?;
        let mut members = Vec::new();
        while !self.eat(&TokenKind::RBrace) {
            let ty = self.parse_type()?;
            let mname = self.expect_ident("member name")?;
            let semantic = self.parse_optional_semantic();
            self.expect(&TokenKind::Semicolon, ";")?;
            members.push(StructMember {
                ty,
                name: mname,
                semantic,
            });
        }
        self.expect(&TokenKind::Semicolon, "; after struct")?;
        Ok(StructDecl { name, members })
    }

    fn parse_cbuffer(&mut self) -> Result<CBufferDecl> {
        self.expect(&TokenKind::Keyword(Keyword::CBuffer), "cbuffer")?;
        let name = self.expect_ident("cbuffer name")?;
        let register = self.parse_optional_register();
        self.expect(&TokenKind::LBrace, "{")?;
        let mut members = Vec::new();
        while !self.eat(&TokenKind::RBrace) {
            let ty = self.parse_type()?;
            let mname = self.expect_ident("cbuffer member name")?;
            let semantic = self.parse_optional_semantic();
            self.expect(&TokenKind::Semicolon, ";")?;
            members.push(StructMember {
                ty,
                name: mname,
                semantic,
            });
        }
        self.expect(&TokenKind::Semicolon, "; after cbuffer")?;
        Ok(CBufferDecl {
            name,
            register,
            members,
        })
    }

    /// Parses a `: register(b0)` clause if present, returning the inner text
    /// (e.g. `b0`). Returns `None` if no `: register(...)` follows.
    fn parse_optional_register(&mut self) -> Option<String> {
        if !self.eat(&TokenKind::Colon) {
            return None;
        }
        self.expect(&TokenKind::Keyword(Keyword::Register), "register")
            .ok()?;
        if !self.eat(&TokenKind::LParen) {
            return None;
        }
        // Collect the register descriptor (e.g. `b0`, `s0`, `t0`), which the
        // lexer emits as a single identifier.
        let reg = match self.bump() {
            TokenKind::Ident(s) => s,
            _ => {
                // Skip to the matching `)` defensively.
                self.skip_until_rparen();
                return None;
            }
        };
        // Consume any trailing tokens up to and including `)`.
        self.skip_until_rparen();
        Some(reg)
    }

    /// Consume tokens through the next `)`.
    fn skip_until_rparen(&mut self) {
        while !matches!(self.peek(), TokenKind::RParen | TokenKind::Eof) {
            self.bump();
        }
        self.eat(&TokenKind::RParen);
    }

    fn parse_function(&mut self) -> Result<FunctionDecl> {
        let return_type = self.parse_type()?;
        let name = self.expect_ident("function name")?;
        self.expect(&TokenKind::LParen, "(")?;
        let params = self.parse_params()?;
        self.expect(&TokenKind::RParen, ")")?;
        let semantic = self.parse_optional_semantic();

        // Forward declaration: `... );`
        if self.eat(&TokenKind::Semicolon) {
            return Ok(FunctionDecl {
                return_type,
                name,
                params,
                semantic,
                body: None,
            });
        }

        self.expect(&TokenKind::LBrace, "{")?;
        let body = self.parse_block_body()?;
        self.expect(&TokenKind::RBrace, "}")?;
        Ok(FunctionDecl {
            return_type,
            name,
            params,
            semantic,
            body: Some(body),
        })
    }

    fn parse_params(&mut self) -> Result<Vec<Param>> {
        let mut params = Vec::new();
        if matches!(self.peek(), TokenKind::RParen) {
            return Ok(params);
        }
        loop {
            // Optional `in`/`out`/`inout` modifiers are tolerated and ignored.
            self.eat_modifier_word();
            let ty = self.parse_type()?;
            let name = self.expect_ident("parameter name")?;
            let semantic = self.parse_optional_semantic();
            params.push(Param { ty, name, semantic });
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }
        Ok(params)
    }

    /// Consume and ignore `in`/`out`/`inout` (carried as plain identifiers).
    fn eat_modifier_word(&mut self) {
        if let TokenKind::Ident(s) = self.peek() {
            if matches!(s.as_str(), "in" | "out" | "inout" | "uniform") {
                self.bump();
            }
        }
    }

    fn parse_block_body(&mut self) -> Result<Block> {
        let mut stmts = Vec::new();
        while !matches!(self.peek(), TokenKind::RBrace | TokenKind::Eof) {
            stmts.push(self.parse_stmt()?);
        }
        Ok(Block { stmts })
    }

    fn parse_stmt(&mut self) -> Result<Stmt> {
        match self.peek() {
            TokenKind::Keyword(Keyword::Return) => self.parse_return(),
            TokenKind::Keyword(Keyword::If) => self.parse_if(),
            TokenKind::Keyword(Keyword::For) => self.parse_for(),
            TokenKind::LBrace => {
                self.bump();
                let b = self.parse_block_body()?;
                self.expect(&TokenKind::RBrace, "}")?;
                Ok(Stmt::Block(b))
            }
            _ => {
                // Either a var-decl (starts with a type) or an expression
                // statement. We disambiguate: if the upcoming token sequence is
                // `<type> <ident> ...` it's a declaration.
                if self.looks_like_var_decl() {
                    let vd = self.parse_var_decl()?;
                    self.expect(&TokenKind::Semicolon, ";")?;
                    Ok(Stmt::VarDecl(vd))
                } else {
                    let e = self.parse_expr()?;
                    self.expect(&TokenKind::Semicolon, ";")?;
                    Ok(Stmt::Expr(e))
                }
            }
        }
    }

    /// Heuristic: is the next thing a `Type ident` var declaration?
    fn looks_like_var_decl(&self) -> bool {
        if !self.peek_is_type() {
            return false;
        }
        // Skip the type token(s) and check for an identifier following it.
        // A constructor call `float4(...)` is an expression, not a decl.
        let j = self.type_token_len();
        matches!(&self.toks[self.idx + j].kind, TokenKind::Ident(_))
    }

    /// Number of leading tokens consumed by the type at the cursor.
    fn type_token_len(&self) -> usize {
        match &self.toks[self.idx].kind {
            TokenKind::Keyword(Keyword::Void)
            | TokenKind::Keyword(Keyword::Float)
            | TokenKind::Keyword(Keyword::Int)
            | TokenKind::Keyword(Keyword::Uint)
            | TokenKind::Keyword(Keyword::Bool)
            | TokenKind::Keyword(Keyword::SamplerState)
            | TokenKind::Keyword(Keyword::Texture2D) => 1,
            TokenKind::Ident(s) if is_type_word(s) => 1,
            _ => 0,
        }
    }

    fn peek_is_type(&self) -> bool {
        self.type_token_len() > 0
    }

    fn parse_return(&mut self) -> Result<Stmt> {
        self.expect(&TokenKind::Keyword(Keyword::Return), "return")?;
        if self.eat(&TokenKind::Semicolon) {
            return Ok(Stmt::Return(None));
        }
        let e = self.parse_expr()?;
        self.expect(&TokenKind::Semicolon, ";")?;
        Ok(Stmt::Return(Some(e)))
    }

    fn parse_if(&mut self) -> Result<Stmt> {
        self.expect(&TokenKind::Keyword(Keyword::If), "if")?;
        self.expect(&TokenKind::LParen, "(")?;
        let cond = self.parse_expr()?;
        self.expect(&TokenKind::RParen, ")")?;
        let then = self.parse_block_or_stmt()?;
        let else_ = if self.eat(&TokenKind::Keyword(Keyword::Else)) {
            Some(self.parse_block_or_stmt()?)
        } else {
            None
        };
        Ok(Stmt::If { cond, then, else_ })
    }

    fn parse_for(&mut self) -> Result<Stmt> {
        self.expect(&TokenKind::Keyword(Keyword::For), "for")?;
        self.expect(&TokenKind::LParen, "(")?;
        // init
        let init = if self.eat(&TokenKind::Semicolon) {
            None
        } else {
            let init_stmt = if self.looks_like_var_decl() {
                let vd = self.parse_var_decl()?;
                Stmt::VarDecl(vd)
            } else {
                let e = self.parse_expr()?;
                Stmt::Expr(e)
            };
            self.expect(&TokenKind::Semicolon, ";")?;
            Some(Box::new(init_stmt))
        };
        let cond = if self.eat(&TokenKind::Semicolon) {
            None
        } else {
            let e = self.parse_expr()?;
            self.expect(&TokenKind::Semicolon, ";")?;
            Some(e)
        };
        let update = if matches!(self.peek(), TokenKind::RParen) {
            None
        } else {
            let e = self.parse_expr()?;
            Some(e)
        };
        self.expect(&TokenKind::RParen, ")")?;
        let body = self.parse_block_or_stmt()?;
        Ok(Stmt::For {
            init,
            cond,
            update,
            body,
        })
    }

    fn parse_block_or_stmt(&mut self) -> Result<Block> {
        if self.eat(&TokenKind::LBrace) {
            let b = self.parse_block_body()?;
            self.expect(&TokenKind::RBrace, "}")?;
            return Ok(b);
        }
        let s = self.parse_stmt()?;
        Ok(Block { stmts: vec![s] })
    }

    fn parse_var_decl(&mut self) -> Result<VarDecl> {
        let ty = self.parse_type()?;
        let name = self.expect_ident("variable name")?;
        let semantic = self.parse_optional_semantic();
        let init = if self.eat(&TokenKind::Assign) {
            Some(self.parse_expr()?)
        } else {
            None
        };
        Ok(VarDecl {
            ty,
            name,
            init,
            semantic,
        })
    }

    /// Parse an optional `: Semantic` clause following a signature element.
    fn parse_optional_semantic(&mut self) -> Option<String> {
        if !self.eat(&TokenKind::Colon) {
            return None;
        }
        match self.bump() {
            TokenKind::Semantic(s) => Some(s),
            TokenKind::Ident(s) => Some(s),
            other => {
                // Best-effort: tolerate unexpected tokens by recording none.
                let _ = other;
                None
            }
        }
    }

    // --- types --------------------------------------------------------------

    fn parse_type(&mut self) -> Result<Type> {
        match self.bump() {
            TokenKind::Keyword(Keyword::Void) => Ok(Type::Void),
            TokenKind::Keyword(Keyword::Float) => Ok(Type::Scalar(ScalarKind::Float)),
            TokenKind::Keyword(Keyword::Int) => Ok(Type::Scalar(ScalarKind::Int)),
            TokenKind::Keyword(Keyword::Uint) => Ok(Type::Scalar(ScalarKind::Uint)),
            TokenKind::Keyword(Keyword::Bool) => Ok(Type::Scalar(ScalarKind::Bool)),
            TokenKind::Keyword(Keyword::SamplerState) => Ok(Type::SamplerState),
            TokenKind::Keyword(Keyword::Texture2D) => {
                // optional `<ElementType>` (elided for now)
                if self.eat(&TokenKind::Lt) {
                    self.skip_until_gt();
                }
                Ok(Type::Texture2D)
            }
            TokenKind::Ident(s) => decode_type_word(&s).ok_or_else(|| {
                self.err(
                    self.toks[self.idx.saturating_sub(1)].span,
                    format!("unknown type `{s}`"),
                )
            }),
            other => Err(self.err(
                self.toks[self.idx.saturating_sub(1)].span,
                format!("expected type, got {}", other.describe()),
            )),
        }
    }

    fn skip_until_gt(&mut self) {
        // Naive: consume tokens until a `>` (used to skip `Texture2D<float4>`).
        while !matches!(self.peek(), TokenKind::Gt | TokenKind::Eof) {
            self.bump();
        }
        if matches!(self.peek(), TokenKind::Gt) {
            self.bump();
        }
    }

    fn expect_ident(&mut self, what: &str) -> Result<String> {
        match self.bump() {
            TokenKind::Ident(s) => Ok(s),
            other => {
                let span = self.toks[self.idx.saturating_sub(1)].span;
                Err(self.err(span, format!("expected {what}, got {}", other.describe())))
            }
        }
    }

    // --- expressions --------------------------------------------------------

    /// Pratt-ish expression parser. Precedence ladder.
    fn parse_expr(&mut self) -> Result<Expr> {
        self.parse_assign()
    }

    fn parse_assign(&mut self) -> Result<Expr> {
        let lhs = self.parse_or()?;
        match self.peek() {
            TokenKind::Assign => {
                self.bump();
                let rhs = self.parse_assign()?;
                Ok(Expr::Binary {
                    op: BinaryOp::Assign,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                })
            }
            TokenKind::PlusEq => {
                self.bump();
                let rhs = self.parse_assign()?;
                Ok(Expr::Binary {
                    op: BinaryOp::AddAssign,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                })
            }
            TokenKind::MinusEq => {
                self.bump();
                let rhs = self.parse_assign()?;
                Ok(Expr::Binary {
                    op: BinaryOp::SubAssign,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                })
            }
            TokenKind::StarEq => {
                self.bump();
                let rhs = self.parse_assign()?;
                Ok(Expr::Binary {
                    op: BinaryOp::MulAssign,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                })
            }
            TokenKind::SlashEq => {
                self.bump();
                let rhs = self.parse_assign()?;
                Ok(Expr::Binary {
                    op: BinaryOp::DivAssign,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                })
            }
            _ => Ok(lhs),
        }
    }

    fn parse_or(&mut self) -> Result<Expr> {
        let mut lhs = self.parse_and()?;
        while matches!(self.peek(), TokenKind::OrOr) {
            self.bump();
            let rhs = self.parse_and()?;
            lhs = Expr::Binary {
                op: BinaryOp::Or,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<Expr> {
        let mut lhs = self.parse_equality()?;
        while matches!(self.peek(), TokenKind::AndAnd) {
            self.bump();
            let rhs = self.parse_equality()?;
            lhs = Expr::Binary {
                op: BinaryOp::And,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_equality(&mut self) -> Result<Expr> {
        let mut lhs = self.parse_rel()?;
        loop {
            let op = match self.peek() {
                TokenKind::EqEq => BinaryOp::Eq,
                TokenKind::Neq => BinaryOp::Ne,
                _ => break,
            };
            self.bump();
            let rhs = self.parse_rel()?;
            lhs = Expr::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_rel(&mut self) -> Result<Expr> {
        let mut lhs = self.parse_add()?;
        loop {
            let op = match self.peek() {
                TokenKind::Lt => BinaryOp::Lt,
                TokenKind::Le => BinaryOp::Le,
                TokenKind::Gt => BinaryOp::Gt,
                TokenKind::Ge => BinaryOp::Ge,
                _ => break,
            };
            self.bump();
            let rhs = self.parse_add()?;
            lhs = Expr::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_add(&mut self) -> Result<Expr> {
        let mut lhs = self.parse_mul()?;
        loop {
            let op = match self.peek() {
                TokenKind::Plus => BinaryOp::Add,
                TokenKind::Minus => BinaryOp::Sub,
                _ => break,
            };
            self.bump();
            let rhs = self.parse_mul()?;
            lhs = Expr::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_mul(&mut self) -> Result<Expr> {
        let mut lhs = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                TokenKind::Star => BinaryOp::Mul,
                TokenKind::Slash => BinaryOp::Div,
                TokenKind::Percent => BinaryOp::Mod,
                _ => break,
            };
            self.bump();
            let rhs = self.parse_unary()?;
            lhs = Expr::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expr> {
        match self.peek() {
            TokenKind::Minus => {
                self.bump();
                let e = self.parse_unary()?;
                Ok(Expr::Unary {
                    op: UnaryOp::Neg,
                    expr: Box::new(e),
                })
            }
            TokenKind::Bang => {
                self.bump();
                let e = self.parse_unary()?;
                Ok(Expr::Unary {
                    op: UnaryOp::Not,
                    expr: Box::new(e),
                })
            }
            TokenKind::Tilde => {
                self.bump();
                let e = self.parse_unary()?;
                Ok(Expr::Unary {
                    op: UnaryOp::BitNot,
                    expr: Box::new(e),
                })
            }
            _ => self.parse_postfix(),
        }
    }

    fn parse_postfix(&mut self) -> Result<Expr> {
        let mut e = self.parse_primary()?;
        while let TokenKind::Dot = self.peek() {
            self.bump();
            let member = self.expect_ident("member name")?;
            e = Expr::Member {
                base: Box::new(e),
                member,
            };
        }
        Ok(e)
    }

    fn parse_primary(&mut self) -> Result<Expr> {
        match self.peek().clone() {
            TokenKind::IntLiteral(v) => {
                self.bump();
                Ok(Expr::Literal(Literal::Int(v)))
            }
            TokenKind::UintLiteral(v) => {
                self.bump();
                Ok(Expr::Literal(Literal::Uint(v)))
            }
            TokenKind::FloatLiteral(v) => {
                self.bump();
                Ok(Expr::Literal(Literal::Float(v)))
            }
            TokenKind::BoolLiteral(v) => {
                self.bump();
                Ok(Expr::Literal(Literal::Bool(v)))
            }
            TokenKind::LParen => {
                self.bump();
                // Possible cast: `(Type)expr`.
                if self.peek_is_type() {
                    let ty = self.parse_type()?;
                    if self.eat(&TokenKind::RParen) {
                        let inner = self.parse_unary()?;
                        return Ok(Expr::Cast {
                            ty,
                            expr: Box::new(inner),
                        });
                    }
                }
                let e = self.parse_expr()?;
                self.expect(&TokenKind::RParen, ")")?;
                Ok(e)
            }
            TokenKind::Ident(s) => {
                // Could be: type-constructor `float4(...)`, function call
                // `foo(...)`, or a plain identifier reference.
                self.bump();
                if self.eat(&TokenKind::LParen) {
                    let args = self.parse_args()?;
                    self.expect(&TokenKind::RParen, ")")?;
                    if let Some(ty) = decode_type_word(&s) {
                        return Ok(Expr::Construct { ty, args });
                    }
                    return Ok(Expr::Call { name: s, args });
                }
                Ok(Expr::Ident(s))
            }
            other => Err(self.unexpected(&format!("expression, got {}", other.describe()))),
        }
    }

    fn parse_args(&mut self) -> Result<Vec<Expr>> {
        let mut args = Vec::new();
        if matches!(self.peek(), TokenKind::RParen) {
            return Ok(args);
        }
        loop {
            args.push(self.parse_expr()?);
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }
        Ok(args)
    }
}

// --- helpers --------------------------------------------------------------

/// Whether an identifier-looking word names a type (e.g. `float4`, `int3`,
/// `float4x4`, or a `struct` name). Struct names are structurally indistinguishable
/// from variables, so we conservatively only flag the builtin vector/matrix
/// shape words here.
fn is_type_word(s: &str) -> bool {
    decode_type_word(s).is_some()
}

/// Decode a builtin HLSL type word like `float`, `float4`, `int3`, `uint2`,
/// `float4x4` into a [`Type`]. Struct names are not handled here (the parser
/// treats any unknown identifier as a struct name only inside declarations).
fn decode_type_word(s: &str) -> Option<Type> {
    if let Some(rest) = s.strip_prefix("float") {
        return decode_shape(rest).map(|(r, c)| match (r, c) {
            (1, 1) => Type::Scalar(ScalarKind::Float),
            (n, 1) => Type::Vector(ScalarKind::Float, n),
            (r, c) => Type::Matrix(ScalarKind::Float, r, c),
        });
    }
    if let Some(rest) = s.strip_prefix("int") {
        return decode_shape(rest).map(|(r, c)| match (r, c) {
            (1, 1) => Type::Scalar(ScalarKind::Int),
            (n, 1) => Type::Vector(ScalarKind::Int, n),
            (r, c) => Type::Matrix(ScalarKind::Int, r, c),
        });
    }
    if let Some(rest) = s.strip_prefix("uint") {
        return decode_shape(rest).map(|(r, c)| match (r, c) {
            (1, 1) => Type::Scalar(ScalarKind::Uint),
            (n, 1) => Type::Vector(ScalarKind::Uint, n),
            (r, c) => Type::Matrix(ScalarKind::Uint, r, c),
        });
    }
    if let Some(rest) = s.strip_prefix("bool") {
        return decode_shape(rest).map(|(r, c)| match (r, c) {
            (1, 1) => Type::Scalar(ScalarKind::Bool),
            (n, 1) => Type::Vector(ScalarKind::Bool, n),
            (r, c) => Type::Matrix(ScalarKind::Bool, r, c),
        });
    }
    None
}

/// Parse a trailing shape like `4`, `4x4`, or `` (scalar) into `(rows, cols)`,
/// where a bare `N` means an N-component vector `(N, 1)`.
fn decode_shape(rest: &str) -> Option<(u32, u32)> {
    if rest.is_empty() {
        return Some((1, 1));
    }
    if let Some((r, c)) = rest.split_once('x') {
        let r: u32 = r.parse().ok()?;
        let c: u32 = c.parse().ok()?;
        if r >= 1 && c >= 1 {
            return Some((r, c));
        }
        return None;
    }
    let n: u32 = rest.parse().ok()?;
    if (2..=4).contains(&n) {
        Some((n, 1))
    } else {
        None
    }
}

/// Human-readable description of a token kind, for diagnostics.
impl TokenKind {
    fn describe(&self) -> String {
        match self {
            TokenKind::Ident(s) => format!("identifier `{s}`"),
            TokenKind::Keyword(k) => format!("keyword `{k:?}`"),
            TokenKind::Semantic(s) => format!("semantic `{s}`"),
            TokenKind::IntLiteral(v) => format!("int literal {v}"),
            TokenKind::UintLiteral(v) => format!("uint literal {v}"),
            TokenKind::FloatLiteral(v) => format!("float literal {v}"),
            TokenKind::BoolLiteral(v) => format!("bool literal {v}"),
            other => format!("{other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::lex;

    fn parse_src(src: &str) -> TranslationUnit {
        let toks = lex(src).unwrap();
        parse(toks).unwrap()
    }

    #[test]
    fn parse_trivial_main() {
        let src = "float4 main() : SV_Target { return float4(1.0, 0.0, 0.0, 1.0); }";
        let unit = parse_src(src);
        assert_eq!(unit.decls.len(), 1);
        let f = match &unit.decls[0] {
            Decl::Function(f) => f,
            other => panic!("expected function, got {other:?}"),
        };
        assert_eq!(f.name, "main");
        assert_eq!(f.semantic.as_deref(), Some("SV_Target"));
        assert!(matches!(f.return_type, Type::Vector(ScalarKind::Float, 4)));
        assert!(f.body.is_some());
        assert_eq!(f.body.as_ref().unwrap().stmts.len(), 1);
    }

    #[test]
    fn parse_struct_and_cbuffer() {
        let src = "\
struct VSOut { float4 pos : SV_Position; float2 uv : TEXCOORD0; };
cbuffer Consts : register(b0) { float4 color; float scale; };
float4 main() : SV_Target { return float4(1.0, 0.0, 0.0, 1.0); }";
        let unit = parse_src(src);
        assert_eq!(unit.decls.len(), 3);
        assert!(matches!(&unit.decls[0], Decl::Struct(_)));
        assert!(matches!(&unit.decls[1], Decl::CBuffer(_)));
    }

    #[test]
    fn parse_if_for() {
        let src = "\
float4 main() : SV_Target {
    if (true) { return float4(1.0,1.0,1.0,1.0); } else { return float4(0.0,0.0,0.0,1.0); }
    for (int i = 0; i < 4; i = i + 1) { float x = 1.0; }
    return float4(0.0, 0.0, 0.0, 1.0);
}";
        let unit = parse_src(src);
        let f = match &unit.decls[0] {
            Decl::Function(f) => f,
            _ => unreachable!(),
        };
        assert_eq!(f.body.as_ref().unwrap().stmts.len(), 3);
    }
}
