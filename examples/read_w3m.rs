//! Example: Reading files from TheDeathSheep.w3m MPQ archive.
//!
//! Lists all files and prints their content (or size for binary files).

use storm_rs::MpqArchive;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filename = "mpq/TheDeathSheep.w3m";

    let archive = MpqArchive::open(filename)?;
    println!("Archive opened: {}", filename);

    let files = archive.list_files();
    println!("\nFound {} files:", files.len());

    for name in &files {
        match archive.read_file(name) {
            Ok(data) => {
                // Try to display as text, otherwise show size
                match std::str::from_utf8(&data) {
                    Ok(text) => {
                        println!("\n=== {} ({} bytes) ===", name, data.len());
                        // Print first 512 chars to avoid flooding the console
                        if text.len() > 512 {
                            println!("{}...", &text[..512]);
                        } else {
                            println!("{}", text);
                        }
                    }
                    Err(_) => {
                        println!("\n=== {} ({} bytes, binary) ===", name, data.len());
                    }
                }
            }
            Err(e) => {
                println!("\n=== {} — error: {} ===", name, e);
            }
        }
    }

    Ok(())
}

