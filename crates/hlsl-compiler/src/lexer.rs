//! Lexer for the supported HLSL subset.
//!
//! Turns source text into a flat `Vec<Token>` stream with byte spans. Handles
//! `//` and `/* */` comments, numeric literals (decimal, hex, float with
//! exponents/suffixes), identifiers/keywords, and the operators/punctuation
//! needed by the [parser](crate::parser).

use std::fmt;

/// A byte span (half-open `[start, end)`) into the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Span { start, end }
    }
}

/// A lexical token with its source span.
#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

/// The concrete kind of a token.
#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    // --- Identifiers / keywords ---
    Ident(String),
    Keyword(Keyword),
    /// A semantic annotation like `SV_Target`, `SV_Position`, `TEXCOORD0`.
    Semantic(String),

    // --- Literals ---
    IntLiteral(i64),
    UintLiteral(u64),
    FloatLiteral(f64),
    BoolLiteral(bool),

    // --- Punctuation / operators ---
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `{`
    LBrace,
    /// `}`
    RBrace,
    /// `[`
    LBracket,
    /// `]`
    RBracket,
    /// `,`
    Comma,
    /// `;`
    Semicolon,
    /// `:`
    Colon,
    /// `.`
    Dot,
    /// `=`
    Assign,
    /// `==`
    EqEq,
    /// `!=`
    Neq,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
    /// `+`
    Plus,
    /// `-`
    Minus,
    /// `*`
    Star,
    /// `/`
    Slash,
    /// `%`
    Percent,
    /// `!`
    Bang,
    /// `~`
    Tilde,
    /// `&`
    Amp,
    /// `|`
    Pipe,
    /// `^`
    Caret,
    /// `&&`
    AndAnd,
    /// `||`
    OrOr,
    /// `+=`, `-=`, `*=`, `/=`
    PlusEq,
    MinusEq,
    StarEq,
    SlashEq,
    /// `<` `>` `=` also used as generics/angle for now; unused in Phase 1.

    /// End of input.
    Eof,
}

/// Reserved keywords for the supported subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keyword {
    Void,
    Float,
    Int,
    Uint,
    Bool,
    Struct,
    Return,
    If,
    Else,
    For,
    SamplerState,
    Texture2D,
    CBuffer,
    /// `register` (as in `: register(b0)`).
    Register,
}

/// A lexing error.
#[derive(Debug, Clone)]
pub struct LexError {
    pub span: Span,
    pub msg: String,
}

impl fmt::Display for LexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "lex error at {}..{}: {}",
            self.span.start, self.span.end, self.msg
        )
    }
}

impl std::error::Error for LexError {}

/// Lex an HLSL source string into a token stream.
pub fn lex(source: &str) -> Result<Vec<Token>, LexError> {
    Lexer::new(source).run()
}

struct Lexer<'a> {
    src: &'a [u8],
    /// Current byte offset into `src`.
    pos: usize,
    tokens: Vec<Token>,
}

impl<'a> Lexer<'a> {
    fn new(source: &'a str) -> Self {
        Lexer {
            src: source.as_bytes(),
            pos: 0,
            tokens: Vec::new(),
        }
    }

    fn run(mut self) -> Result<Vec<Token>, LexError> {
        while self.pos < self.src.len() {
            self.skip_ws_and_comments()?;
            if self.pos >= self.src.len() {
                break;
            }
            let start = self.pos;
            let c = self.src[self.pos];
            let starts_number = c.is_ascii_digit()
                || (c == b'.' && self.peek_is(1).is_some_and(|n| n.is_ascii_digit()));
            if starts_number {
                self.number(start)?;
            } else if c == b'"' {
                return Err(self.err(start, start + 1, "string literals are not supported yet"));
            } else if c.is_ascii_alphabetic() || c == b'_' {
                self.ident(start);
            } else {
                self.op(start)?;
            }
        }
        self.tokens.push(Token {
            kind: TokenKind::Eof,
            span: Span::new(self.pos, self.pos),
        });
        Ok(self.tokens)
    }

    fn err(&self, start: usize, end: usize, msg: impl Into<String>) -> LexError {
        LexError {
            span: Span::new(start, end),
            msg: msg.into(),
        }
    }

    fn peek_is(&self, off: usize) -> Option<u8> {
        self.src.get(self.pos + off).copied()
    }

    fn bump(&mut self) -> u8 {
        let c = self.src[self.pos];
        self.pos += 1;
        c
    }

    fn skip_ws_and_comments(&mut self) -> Result<(), LexError> {
        while self.pos < self.src.len() {
            let c = self.src[self.pos];
            if c.is_ascii_whitespace() {
                self.pos += 1;
            } else if c == b'/' && self.peek_is(1) == Some(b'/') {
                // line comment
                self.pos += 2;
                while self.pos < self.src.len() && self.src[self.pos] != b'\n' {
                    self.pos += 1;
                }
            } else if c == b'/' && self.peek_is(1) == Some(b'*') {
                // block comment
                let start = self.pos;
                self.pos += 2;
                let mut closed = false;
                while self.pos + 1 < self.src.len() {
                    if self.src[self.pos] == b'*' && self.src[self.pos + 1] == b'/' {
                        self.pos += 2;
                        closed = true;
                        break;
                    }
                    self.pos += 1;
                }
                if !closed {
                    return Err(self.err(start, self.src.len(), "unterminated block comment"));
                }
            } else if c == b'/' && self.peek_is(1) == Some(b'/') {
                // handled above
                unreachable!();
            } else {
                break;
            }
        }
        Ok(())
    }

    fn emit(&mut self, span: Span, kind: TokenKind) {
        self.tokens.push(Token { kind, span });
    }

    // --- numbers ------------------------------------------------------------

    fn number(&mut self, start: usize) -> Result<(), LexError> {
        // Detect hex: 0x...
        if self.src[self.pos] == b'0' && self.peek_is(1).is_some_and(|c| c == b'x' || c == b'X') {
            self.pos += 2;
            let hex_start = self.pos;
            while self.peek_is(0).is_some_and(|c| c.is_ascii_hexdigit()) {
                self.pos += 1;
            }
            if self.pos == hex_start {
                return Err(self.err(start, self.pos, "empty hex literal"));
            }
            let text = std::str::from_utf8(&self.src[hex_start..self.pos]).unwrap_or("");
            let is_uint = self.consume_uint_suffix();
            let span = Span::new(start, self.pos);
            let val = u64::from_str_radix(text, 16)
                .map_err(|_| self.err(start, self.pos, "invalid hex literal"))?;
            if is_uint {
                self.emit(span, TokenKind::UintLiteral(val));
            } else {
                self.emit(span, TokenKind::IntLiteral(val as i64));
            }
            return Ok(());
        }

        // Decimal integer or float.
        let mut had_dot = false;
        let mut had_exp = false;
        while self.pos < self.src.len() {
            let c = self.src[self.pos];
            if c.is_ascii_digit() {
                self.pos += 1;
            } else if c == b'.' && !had_dot && !had_exp {
                // Lookahead: only treat as decimal point if followed by digit
                // or (end / non-identifier). This avoids eating the `.x` in
                // `1.0.x`. Practically `1.0` is always followed by a delimiter.
                had_dot = true;
                self.pos += 1;
            } else if (c == b'e' || c == b'E') && !had_exp {
                had_exp = true;
                had_dot = true; // exponent implies float
                self.pos += 1;
                // optional sign
                if self.peek_is(0) == Some(b'+') || self.peek_is(0) == Some(b'-') {
                    self.pos += 1;
                }
            } else {
                break;
            }
        }

        if had_dot || had_exp {
            // float
            self.consume_float_suffix();
            let s = Span::new(start, self.pos);
            let text = std::str::from_utf8(&self.src[start..self.pos]).unwrap_or("");
            let val: f64 = text
                .parse()
                .map_err(|_| self.err(start, self.pos, "invalid float literal"))?;
            self.emit(s, TokenKind::FloatLiteral(val));
        } else {
            let is_uint = self.consume_uint_suffix();
            let s = Span::new(start, self.pos);
            let text = std::str::from_utf8(&self.src[start..self.pos]).unwrap_or("");
            if is_uint {
                let val: u64 = text
                    .parse()
                    .map_err(|_| self.err(start, self.pos, "invalid integer literal"))?;
                self.emit(s, TokenKind::UintLiteral(val));
            } else {
                let val: i64 = text
                    .parse()
                    .map_err(|_| self.err(start, self.pos, "invalid integer literal"))?;
                self.emit(s, TokenKind::IntLiteral(val));
            }
        }
        Ok(())
    }

    /// If the next char is `u`/`U`, consume it and return true (uint literal).
    fn consume_uint_suffix(&mut self) -> bool {
        if self.peek_is(0).is_some_and(|c| c == b'u' || c == b'U') {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// Consume an optional `f`/`F` float suffix.
    fn consume_float_suffix(&mut self) {
        if self.peek_is(0).is_some_and(|c| c == b'f' || c == b'F') {
            self.pos += 1;
        }
    }

    // --- identifiers / keywords / semantics ---------------------------------

    fn ident(&mut self, start: usize) {
        while self
            .peek_is(0)
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_')
        {
            self.pos += 1;
        }
        let text = std::str::from_utf8(&self.src[start..self.pos]).unwrap_or("");
        let span = Span::new(start, self.pos);
        let kind = classify_ident(text);
        self.emit(span, kind);
    }

    // --- operators / punctuation -------------------------------------------

    fn op(&mut self, start: usize) -> Result<(), LexError> {
        let c = self.bump();
        // 2-char operators first.
        let two = match self.peek_is(0) {
            Some(n) => [c, n],
            None => [c, 0],
        };
        macro_rules! emit2 {
            ($k:expr) => {{
                self.pos += 1;
                self.emit(Span::new(start, self.pos), $k);
                return Ok(());
            }};
        }
        match two {
            [b'=', b'='] => emit2!(TokenKind::EqEq),
            [b'!', b'='] => emit2!(TokenKind::Neq),
            [b'<', b'='] => emit2!(TokenKind::Le),
            [b'>', b'='] => emit2!(TokenKind::Ge),
            [b'&', b'&'] => emit2!(TokenKind::AndAnd),
            [b'|', b'|'] => emit2!(TokenKind::OrOr),
            [b'+', b'='] => emit2!(TokenKind::PlusEq),
            [b'-', b'='] => emit2!(TokenKind::MinusEq),
            [b'*', b'='] => emit2!(TokenKind::StarEq),
            [b'/', b'='] => emit2!(TokenKind::SlashEq),
            _ => {}
        }
        // single-char
        let span = Span::new(start, start + 1);
        let kind = match c {
            b'(' => TokenKind::LParen,
            b')' => TokenKind::RParen,
            b'{' => TokenKind::LBrace,
            b'}' => TokenKind::RBrace,
            b'[' => TokenKind::LBracket,
            b']' => TokenKind::RBracket,
            b',' => TokenKind::Comma,
            b';' => TokenKind::Semicolon,
            b':' => TokenKind::Colon,
            b'.' => TokenKind::Dot,
            b'=' => TokenKind::Assign,
            b'<' => TokenKind::Lt,
            b'>' => TokenKind::Gt,
            b'+' => TokenKind::Plus,
            b'-' => TokenKind::Minus,
            b'*' => TokenKind::Star,
            b'/' => TokenKind::Slash,
            b'%' => TokenKind::Percent,
            b'!' => TokenKind::Bang,
            b'~' => TokenKind::Tilde,
            b'&' => TokenKind::Amp,
            b'|' => TokenKind::Pipe,
            b'^' => TokenKind::Caret,
            other => {
                return Err(self.err(start, start + 1, format!("unexpected character {other:?}")));
            }
        };
        self.emit(span, kind);
        Ok(())
    }
}

/// Decide whether an identifier-looking word is a keyword, a semantic, or a
/// plain identifier.
fn classify_ident(text: &str) -> TokenKind {
    // Type constructors that also serve as keywords for vector types.
    match text {
        "void" => return TokenKind::Keyword(Keyword::Void),
        "int" => return TokenKind::Keyword(Keyword::Int),
        "uint" => return TokenKind::Keyword(Keyword::Uint),
        "bool" => return TokenKind::Keyword(Keyword::Bool),
        "struct" => return TokenKind::Keyword(Keyword::Struct),
        "return" => return TokenKind::Keyword(Keyword::Return),
        "if" => return TokenKind::Keyword(Keyword::If),
        "else" => return TokenKind::Keyword(Keyword::Else),
        "for" => return TokenKind::Keyword(Keyword::For),
        "SamplerState" => return TokenKind::Keyword(Keyword::SamplerState),
        "Texture2D" => return TokenKind::Keyword(Keyword::Texture2D),
        "cbuffer" => return TokenKind::Keyword(Keyword::CBuffer),
        "register" => return TokenKind::Keyword(Keyword::Register),
        "true" => return TokenKind::BoolLiteral(true),
        "false" => return TokenKind::BoolLiteral(false),
        _ => {}
    }

    // `float` and the vector forms `float2`..`float4` (and matrices later).
    if let Some(rest) = text.strip_prefix("float") {
        if rest.is_empty() {
            return TokenKind::Keyword(Keyword::Float);
        }
        // floatN or floatNxM
        if rest.chars().all(|c| c.is_ascii_digit() || c == 'x')
            && rest.contains(|c: char| c.is_ascii_digit())
            && !rest.contains(|c: char| !(c.is_ascii_digit() || c == 'x'))
        {
            // Treat as a keyword-ish type token carried as Semantic? We carry
            // the whole type word as an Ident so the parser can decode it into
            // a Type. Using Ident keeps the type-token set open-ended.
            return TokenKind::Ident(text.to_string());
        }
    }

    // Semantics: SV_Target, SV_Position, SV_Depth, plus common `TEXCOORD0`,
    // `COLOR0`, `POSITION`, etc. We match `SV_`-prefixed and the well-known
    // binding semantics; everything else stays an identifier.
    if is_semantic(text) {
        return TokenKind::Semantic(text.to_string());
    }

    TokenKind::Ident(text.to_string())
}

/// Whether `text` should be treated as a semantic annotation rather than an
/// ordinary identifier. Conservative: only recognises the `SV_*` family and a
/// few common legacy semantics (with or without a trailing numeric index).
fn is_semantic(text: &str) -> bool {
    if text.starts_with("SV_") {
        return true;
    }
    // Legacy semantics like `TEXCOORD0`, `COLOR0`, `POSITION`, `NORMAL`. We
    // match a known base optionally followed by ASCII digits.
    const BASES: &[&str] = &[
        "POSITION",
        "POSITIONT",
        "PSIZE",
        "COLOR",
        "FOG",
        "TEXCOORD",
        "TANGENT",
        "BINORMAL",
        "NORMAL",
        "DEPTH",
        "VPOS",
        "VFACE",
        "BLENDWEIGHT",
        "BLENDINDICES",
    ];
    BASES.iter().any(|base| {
        text == *base
            || (text.starts_with(base)
                && text.len() > base.len()
                && text[base.len()..].bytes().all(|b| b.is_ascii_digit()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lex_trivial() {
        let src = "float4 main() : SV_Target { return float4(1.0, 0.0, 0.0, 1.0); }";
        let toks = lex(src).unwrap();
        // First token is the type word `float4` (ident).
        assert!(matches!(&toks[0].kind, TokenKind::Ident(s) if s == "float4"));
        // SV_Target is somewhere in the stream as a semantic.
        assert!(
            toks.iter()
                .any(|t| matches!(&t.kind, TokenKind::Semantic(s) if s == "SV_Target")),
            "expected SV_Target semantic token"
        );
        // Float literals present.
        let floats: Vec<f64> = toks
            .iter()
            .filter_map(|t| match t.kind {
                TokenKind::FloatLiteral(v) => Some(v),
                _ => None,
            })
            .collect();
        assert_eq!(floats, vec![1.0, 0.0, 0.0, 1.0]);
        // EOF at the end.
        assert!(matches!(toks.last().unwrap().kind, TokenKind::Eof));
    }

    #[test]
    fn lex_comments_and_hex() {
        let src = "int x = 0x1Au; // line\n /* block */ float y = 2.5;";
        let toks = lex(src).unwrap();
        assert!(toks
            .iter()
            .any(|t| matches!(&t.kind, TokenKind::UintLiteral(26))));
        assert!(toks
            .iter()
            .any(|t| matches!(&t.kind, TokenKind::FloatLiteral(v) if (v - 2.5).abs() < 1e-9)));
    }
}
