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

### Tools: listing, extracting, building from a folder

`storm_rs::archive::files` holds what a tool needs over the files as a
whole, so the CLI and other front ends (an MCP server) share it:

```rust
use storm_rs::archive::{MpqArchive, extract_path};

let mut map = MpqArchive::open("map.w3x")?;
map.add_external_listfile("listfile.txt")?; // a map without (listfile)
for file in map.find_files(&["war3map.*", "Units/*.txt"]) {
    // `None` for a name like `..\evil.j`, which would leave the folder.
    if let Some(path) = extract_path("out".as_ref(), &file.name) {
        map.extract_file(&file.name, path)?;
    }
}
println!("{} files have no known name", map.unnamed_count());
```

`named_files()` lists the files with a known name (from the listfile, an
external one, and the archive's own `(listfile)`, `(attributes)`,
`(signature)`); `find_files(masks)` filters them by StormLib masks;
`MpqArchiveBuilder::add_folder(dir)` adds every file under a folder.

## Command line

The workspace's `cli` crate is the `storm` command, built on the library:

```sh
cargo install --path cli        # or: cargo run -p storm-cli -- <command> ...
```

```text
storm info    <archive> [--json]                  the header, the tables, how many files have no name
storm list    <archive> [<mask>...] [-l] [--json] the files, sorted; -l: sizes and flags
storm cat     <archive> <name>                    a file's bytes to stdout
storm extract <archive> [<mask>...] [-o <dir>]    files into <dir>, folders from the names
storm verify  <archive> [<mask>...] [--json]      CRC32 / MD5 from (attributes), sector CRCs
storm create  <archive> <dir>                     a new archive of every file under <dir>
storm add     <archive> <file> [<name>]           add or replace a file
storm remove  <archive> <name>...                 remove files
storm rename  <archive> <old> <new>               rename a file
```

- Names inside an archive use `\` (`Units\HumanUnitFunc.txt`); `/` works
  too. Masks are StormLib's: `*` and `?`, any case, over the whole name.
- `--listfile <file>` (repeatable) gives names to an archive's files that
  its own `(listfile)` doesn't: protected maps have none.
- `--json` prints one JSON document, for tools.
- Exit codes: 0 done, 1 failed (a bad file in `verify`, a file that
  couldn't be extracted), 2 wrong arguments.
- `extract` never writes outside its folder: a name like `..\x` is
  skipped and reported.

## Layout

- the repository root is the library, `storm-rs`;
- `cli/` is `storm-cli`, the `storm` command: arguments and output only;
  what the commands do is the library's (`archive::files`).

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
