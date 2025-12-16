//! Example: Creating an MPQ archive.
//!
//! Demonstrates:
//! - Creating a new archive.
//! - Adding files with different compression/encryption settings.
//! - Adding files from memory.

use storm_rs::archive::{MpqCreateOptions, create_archive};
use storm_rs::constants::*;
use storm_rs::{AddFileOptions, MpqArchiveWriter};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filename = "example_create.mpq";

    // 1. Create an empty archive
    // We use version 1 (up to 4GB) and limit file count to 16 for this example.
    let options = MpqCreateOptions::v1().max_files(16);
    create_archive(filename, &options)?;

    // 2. Open the archive for writing
    let mut writer = MpqArchiveWriter::open(filename)?;

    // 3. Add a simple text file (Compressed by default)
    writer.add_file(
        "hello.txt",
        b"Hello, World! This is a test file.",
        &AddFileOptions::default(),
    )?;

    // 4. Add an encrypted file
    // Note: Encryption requires the file to be compressed or single-unit usually,
    // but here we just enable encryption.
    let mut encrypt_opts = AddFileOptions::default();
    encrypt_opts.encrypt = true;
    writer.add_file("secret.txt", b"This is a secret message.", &encrypt_opts)?;

    // 5. Add a file with specific compression (e.g., LZMA)
    // Note: LZMA is efficient but slower.
    let mut lzma_opts = AddFileOptions::default();
    lzma_opts.compression = MPQ_COMPRESSION_LZMA;
    writer.add_file(
        "compressed.bin",
        &vec![0xAA; 10000], // Highly compressible data
        &lzma_opts,
    )?;

    // 6. Finish writing (writes hash/block tables)
    writer.finish()?;

    println!("Archive created successfully: {}", filename);
    Ok(())
}
