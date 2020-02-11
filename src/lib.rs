//! #libunwind-rs
//!
//! `libunwind-rs`  is a library providing safe Rust API for retrieving backtrace from local and
//! remote process, and also from coredumps. Crate is build on a top of [libunwind] library.
//! 
//!
//! [libunwind]: http://www.nongnu.org/libunwind/
#[macro_use]
extern crate num_derive;

pub use crate::common::*;
mod common;
