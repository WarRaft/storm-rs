//! Example: Modifying an MPQ archive.
//!
//! Demonstrates:
//! - Renaming files.
//! - Deleting files.
//! - Changing file locale.

use storm_rs::archive::{MpqCreateOptions, create_archive};
use storm_rs::{AddFileOptions, MpqArchiveWriter};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filename = "example_modify.mpq";

    // Setup: Create an archive with some files
    create_archive(filename, &MpqCreateOptions::v1())?;
    {
        let mut writer = MpqArchiveWriter::open(filename)?;
        writer.add_file("file_to_rename.txt", b"content", &AddFileOptions::default())?;
        writer.add_file(
            "file_to_delete.txt",
            b"delete me",
            &AddFileOptions::default(),
        )?;
        writer.finish()?;
    }

    println!("Created initial archive: {}", filename);

    // 1. Rename a file
    {
        let mut writer = MpqArchiveWriter::open(filename)?;
        writer.rename_file("file_to_rename.txt", "renamed_file.txt")?;
        println!("Renamed 'file_to_rename.txt' to 'renamed_file.txt'");
        writer.finish()?;
    }

    // 2. Delete a file
    {
        let mut writer = MpqArchiveWriter::open(filename)?;
        writer.remove_file("file_to_delete.txt")?;
        println!("Deleted 'file_to_delete.txt'");
        writer.finish()?;
    }

    // 3. Verify changes
    let archive = storm_rs::MpqArchive::open(filename)?;

    if archive.has_file("renamed_file.txt") {
        println!("Verified: 'renamed_file.txt' exists.");
    } else {
        eprintln!("Error: 'renamed_file.txt' missing!");
    }

    if !archive.has_file("file_to_delete.txt") {
        println!("Verified: 'file_to_delete.txt' is gone.");
    } else {
        eprintln!("Error: 'file_to_delete.txt' still exists!");
    }

    // Cleanup
    // std::fs::remove_file(filename)?;
    Ok(())
}
