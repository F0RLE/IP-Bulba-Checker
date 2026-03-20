//! Public interface exposed for benchmarking via `benches/`.
//!
//! This module exists solely to allow `[[bench]]` targets to import
//! from the crate. Application entry point remains `src/main.rs`.

pub mod signatures;
