//! Example: Incremental Patching.
//!
//! Demonstrates:
//! - Creating a base archive.
//! - Creating a patch archive.
//! - Applying the patch at runtime (virtual patching).

use storm_rs::archive::{MpqCreateOptions, create_archive};
use storm_rs::{AddFileOptions, MpqArchive, MpqArchiveWriter};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_mpq = "base.mpq";
    let patch_mpq = "patch.mpq";

    // 1. Create Base Archive
    create_archive(base_mpq, &MpqCreateOptions::v1())?;
    {
        let mut writer = MpqArchiveWriter::open(base_mpq)?;
        writer.add_file("config.txt", b"ver=1.0", &AddFileOptions::default())?;
        writer.add_file("data.bin", b"base data", &AddFileOptions::default())?;
        writer.finish()?;
    }
    println!("Created base archive: {}", base_mpq);

    // 2. Create Patch Archive
    // Patch archives usually contain updated versions of files.
    create_archive(patch_mpq, &MpqCreateOptions::v1())?;
    {
        let mut writer = MpqArchiveWriter::open(patch_mpq)?;
        // Update config.txt
        writer.add_file("config.txt", b"ver=1.1", &AddFileOptions::default())?;
        // Add new file
        writer.add_file("new_feature.txt", b"new stuff", &AddFileOptions::default())?;
        writer.finish()?;
    }
    println!("Created patch archive: {}", patch_mpq);

    // 3. Open Base Archive
    let mut archive = MpqArchive::open(base_mpq)?;

    // Verify initial state
    let ver_1 = archive.read_file("config.txt")?;
    println!("Base version: {}", String::from_utf8_lossy(&ver_1)); // "ver=1.0"

    // 4. Apply Patch
    println!("Applying patch...");
    archive.add_patch(patch_mpq)?;

    // 5. Verify Patched State
    // Reading "config.txt" should now return the version from the patch.
    let ver_2 = archive.read_file("config.txt")?;
    println!("Patched version: {}", String::from_utf8_lossy(&ver_2)); // "ver=1.1"

    if ver_2 == b"ver=1.1" {
        println!("Patch applied successfully!");
    } else {
        eprintln!("Patch failed!");
    }

    // Verify new file access
    if archive.has_file("new_feature.txt") {
        println!("New feature file found.");
    }

    // Cleanup
    // std::fs::remove_file(base_mpq)?;
    // std::fs::remove_file(patch_mpq)?;

    Ok(())
}
