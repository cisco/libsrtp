// This module provides a layer of indirection with regard to the implementation of SRTP functions
// (C via FFI or pure Rust).  Once we have a Rust implementation with the same API exposed
// by the `ffi` submodule, we will be able to use features to build the tests in a few modes:
//
// 1. C called via FFI
// 2. Rust called via FFI
// 3. Rust called natively
//
// The difference between (1) and (2) is the difference that C callers will see.  The difference
// between (2) and (3) indicates how much of that is due to the FFI interface, vs. the core of the
// Rust implementation.

// TODO #[cfg(feature = cffi)]
mod ffi;
pub(crate) use ffi::*;

// TODO #[cfg(feature = pure-rust)]
// pub use srtp::*;
