//! QEMU command-line parser library.
//!
//! Tokenizes a QEMU invocation string and groups options into the
//! [`Grouped`](crate::model::Grouped) semantic model.

pub mod model;
pub mod options;
pub mod property;
pub mod tokenizer;

pub use model::{Grouped, Props};

/// Parse a raw QEMU command string into the grouped semantic model.
pub fn parse(command: &str) -> Grouped {
    let tokens = tokenizer::tokenize(command);
    Grouped::from(tokens.as_slice())
}
