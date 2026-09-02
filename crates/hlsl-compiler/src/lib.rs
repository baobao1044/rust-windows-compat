//! HLSL → SPIR-V compiler, written from scratch in Rust.
//! Targets the SM5.0 (Shader Model 5.0) subset required by D3D11.

#![deny(unsafe_op_in_unsafe_fn)]
