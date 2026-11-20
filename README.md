# storm-rs

A Rust port of [StormLib](https://github.com/ladislav-zezula/StormLib) — a library for reading and writing MPQ (MoPaQ) archives, used by Blizzard Entertainment games.

## Features

- **Read & Write**: Full support for creating, reading, and modifying MPQ archives.
- **Compression**: Supports ZLIB, PKWARE (Implode), LZMA, Huffman, and ADPCM compression.
- **Encryption**: Supports file encryption and decryption.
- **Patching**: Support for incremental patching (BSDIFF40).
- **Standard Compliance**: Compatible with standard MPQ tools and specifications.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
storm-rs = { git = "https://github.com/WarRaft/storm-rs" }
```

## Usage

### Reading an Archive

```rust
use storm_rs::MpqArchive;

let archive = MpqArchive::open("archive.mpq")?;
if archive.has_file("file.txt") {
    let content = archive.read_file("file.txt")?;
    println!("Content: {:?}", String::from_utf8_lossy(&content));
}
```

### Creating an Archive

```rust
use storm_rs::{MpqArchiveWriter, MpqCreateOptions, AddFileOptions, create_archive};

// Create empty archive
create_archive("new.mpq", &MpqCreateOptions::v1())?;

// Add files
let mut writer = MpqArchiveWriter::open("new.mpq")?;
writer.add_file("hello.txt", b"Hello World", &AddFileOptions::default())?;
writer.finish()?;
```

## Examples

Check the `examples/` directory for more comprehensive usage:

- `create_archive.rs`: Creating archives and adding files.
- `read_archive.rs`: Reading and extracting files.
- `modify_archive.rs`: Renaming, deleting, and updating files.
- `patch_archive.rs`: Applying incremental patches.

Run examples with:

```bash
cargo run --example create_archive
```

## Acknowledgments

This project is a Rust port of [StormLib](https://github.com/ladislav-zezula/StormLib), originally developed by **Ladislav Zezula**. Without his extensive work on documenting and implementing the MPQ format, this project would not be possible.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
