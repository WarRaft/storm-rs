//! Example: Reading an MPQ archive.
//!
//! Demonstrates:
//! - Opening an archive.
//! - Iterating over files.
//! - Reading file content.
//! - Extracting files.

use std::io::Write;
use storm_rs::MpqArchive;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ensure we have an archive to read (create it if missing, using the other example logic)
    let filename = "example_create.mpq";
    if !std::path::Path::new(filename).exists() {
        eprintln!(
            "Please run 'cargo run --example create_archive' first to generate the test file."
        );
        return Ok(());
    }

    // 1. Open the archive
    let archive = MpqArchive::open(filename)?;
    println!("Archive opened: {}", filename);

    // 2. List files
    // Note: This relies on the (listfile) being present and populated.
    println!("\nFiles in archive:");
    let files = archive.list_files();
    for file in &files {
        println!(" - {}", file);
    }

    // 3. Read a specific file
    if archive.has_file("hello.txt") {
        let content = archive.read_file("hello.txt")?;
        println!("\nContent of 'hello.txt':");
        println!("{}", String::from_utf8_lossy(&content));
    }

    // 4. Extract a file to disk
    if archive.has_file("secret.txt") {
        let content = archive.read_file("secret.txt")?;
        let out_path = "extracted_secret.txt";
        let mut file = std::fs::File::create(out_path)?;
        file.write_all(&content)?;
        println!("\nExtracted 'secret.txt' to '{}'", out_path);

        // Cleanup extracted file
        std::fs::remove_file(out_path)?;
    }

    Ok(())
}
