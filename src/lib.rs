//! storm-rs: MPQ archive library for Rust.
//! Ported from StormLib (https://github.com/ladislav-zezula/StormLib)

pub mod constants;
pub mod crypto;
pub mod error;
pub mod types;

pub mod archive;
pub mod compression;
pub mod file;
pub mod verify;

// Re-export commonly used items
pub use archive::{AddFileOptions, MpqArchive, MpqArchiveWriter};
pub use constants::*;
pub use crypto::{calculate_file_key, decrypt_block, encrypt_block, hash_string};
pub use error::{MpqError, MpqErrorKind, MpqResult};
pub use types::*;
