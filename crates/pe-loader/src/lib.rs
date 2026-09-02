//! PE32/PE32+ loader: parse, map sections, apply relocations, resolve imports,
//! and build the TEB/PEB Windows process structures in Rust.

#![deny(unsafe_op_in_unsafe_fn)]
