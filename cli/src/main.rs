//! `storm`: look into MPQ archives (Warcraft III's `.mpq`, `.w3x`,
//! `.w3m`) and change them from the command line. See `usage`.
//!
//! Names inside an archive use `\` (`Units\HumanUnitFunc.txt`); `/` is
//! accepted too. Masks are StormLib's: `*` and `?`, in any case, over the
//! whole name (`Units\*.txt`, `war3map.*`). `--json` output is for tools:
//! one JSON document on stdout.
//!
//! Only arguments and output live here; what the commands do is the
//! library's (`storm_rs::archive::files`), so other front ends share it.

use std::path::Path;
use std::process::ExitCode;

use storm_rs::archive::create::MpqCreateOptions;
use storm_rs::archive::{MpqArchiveBuilder, extract_path, folder_files, mpq_name};
use storm_rs::verify::flags::{VERIFY_FILE_CRC, VERIFY_FILE_MD5, VERIFY_SECTOR_CRC};
use storm_rs::verify::verify_file;
use storm_rs::{
    AddFileOptions, MPQ_FILE_COMPRESS, MPQ_FILE_ENCRYPTED, MPQ_FILE_IMPLODE, MPQ_FILE_KEY_V2,
    MPQ_FILE_PATCH_FILE, MPQ_FILE_SECTOR_CRC, MPQ_FILE_SINGLE_UNIT, MpqArchive, MpqArchiveWriter,
};

fn usage() {
    eprintln!(
        "usage: storm <command> <archive> ...

  info    <archive> [--json]                 the header, the tables, how many files have no name
  list    <archive> [<mask>...] [-l] [--json] the files, sorted; -l: sizes and flags
  cat     <archive> <name>                    a file's bytes to stdout
  extract <archive> [<mask>...] [-o <dir>]    files into <dir> (default: .), folders from the names
  verify  <archive> [<mask>...] [--json]      CRC32 / MD5 from (attributes), sector CRCs
  create  <archive> <dir>                     a new archive of every file under <dir>
  add     <archive> <file> [<name>]           add or replace a file (name: the file's own)
  remove  <archive> <name>...                 remove files
  rename  <archive> <old> <new>               rename a file

  --listfile <file>   more names to look for (list, extract, verify, info; repeatable):
                      an archive without a (listfile) has files with no known name
  masks: * and ?, any case, over the whole name: Units\\*.txt  war3map.*"
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(Error::Usage(message)) => {
            if !message.is_empty() {
                eprintln!("storm: {message}");
            }
            usage();
            ExitCode::from(2)
        }
        Err(Error::Failed(message)) => {
            eprintln!("storm: {message}");
            ExitCode::FAILURE
        }
    }
}

enum Error {
    /// Wrong arguments: the usage is shown.
    Usage(String),
    Failed(String),
}

type Result<T> = std::result::Result<T, Error>;

fn failed(message: impl Into<String>) -> Error {
    Error::Failed(message.into())
}

/// The command line after the command: positional arguments and options.
struct Args {
    positional: Vec<String>,
    long: bool,
    json: bool,
    out: Option<String>,
    listfiles: Vec<String>,
}

impl Args {
    fn parse(args: &[String]) -> Result<Args> {
        let mut parsed = Args {
            positional: Vec::new(),
            long: false,
            json: false,
            out: None,
            listfiles: Vec::new(),
        };
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            let mut value = |name: &str| {
                it.next()
                    .cloned()
                    .ok_or_else(|| Error::Usage(format!("{name} needs a value")))
            };
            match arg.as_str() {
                "-l" | "--long" => parsed.long = true,
                "--json" => parsed.json = true,
                "-o" | "--out" => parsed.out = Some(value(arg)?),
                "--listfile" => parsed.listfiles.push(value(arg)?),
                "--" => parsed.positional.extend(it.by_ref().cloned()),
                a if a.starts_with('-') && a.len() > 1 => {
                    return Err(Error::Usage(format!("unknown option {a}")));
                }
                _ => parsed.positional.push(arg.clone()),
            }
        }
        Ok(parsed)
    }
}

fn run(args: &[String]) -> Result<ExitCode> {
    let Some((command, rest)) = args.split_first() else {
        return Err(Error::Usage(String::new()));
    };
    if matches!(command.as_str(), "-h" | "--help" | "help") {
        usage();
        return Ok(ExitCode::SUCCESS);
    }
    let a = Args::parse(rest)?;
    let p: Vec<&str> = a.positional.iter().map(String::as_str).collect();
    match (command.as_str(), p.as_slice()) {
        ("info", [archive]) => info(&open(archive, &a.listfiles)?, a.json),
        ("list", [archive, masks @ ..]) => {
            list(&open(archive, &a.listfiles)?, masks, a.long, a.json)
        }
        ("cat", [archive, name]) => cat(&open(archive, &a.listfiles)?, name),
        ("extract", [archive, masks @ ..]) => extract(
            &open(archive, &a.listfiles)?,
            masks,
            Path::new(a.out.as_deref().unwrap_or(".")),
        ),
        ("verify", [archive, masks @ ..]) => verify(&open(archive, &a.listfiles)?, masks, a.json),
        ("create", [archive, dir]) => create(archive, Path::new(dir)),
        ("add", [archive, file]) => {
            let name = Path::new(file)
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or(failed(format!("{file}: no file name")))?;
            add(archive, Path::new(file), name)
        }
        ("add", [archive, file, name]) => add(archive, Path::new(file), name),
        ("remove", [archive, names @ ..]) if !names.is_empty() => remove(archive, names),
        ("rename", [archive, old, new]) => rename(archive, old, new),
        (
            "info" | "list" | "cat" | "extract" | "verify" | "create" | "add" | "remove" | "rename",
            _,
        ) => Err(Error::Usage(format!("wrong arguments for {command}"))),
        _ => Err(Error::Usage(format!("unknown command {command}"))),
    }
}

fn open(path: &str, listfiles: &[String]) -> Result<MpqArchive> {
    let mut archive = MpqArchive::open(path).map_err(|e| failed(format!("{path}: {e}")))?;
    for listfile in listfiles {
        archive
            .add_external_listfile(listfile)
            .map_err(|e| failed(format!("{listfile}: {e}")))?;
    }
    Ok(archive)
}

fn info(archive: &MpqArchive, json: bool) -> Result<ExitCode> {
    let h = &archive.header;
    let named = archive.named_files().len();
    let unnamed = archive.unnamed_count();
    let has = |name: &str| archive.has_file(name);
    let fields: Vec<(&str, String)> = vec![
        ("path", json_str(&archive.path)),
        ("offset", archive.mpq_offset.to_string()),
        ("format_version", (h.format_version + 1).to_string()),
        ("header_size", h.header_size.to_string()),
        ("archive_size", h.archive_size.to_string()),
        ("sector_size", archive.sector_size.to_string()),
        ("hash_table_size", h.hash_table_size.to_string()),
        ("block_table_size", h.block_table_size.to_string()),
        ("files", (named + unnamed).to_string()),
        ("named", named.to_string()),
        ("unnamed", unnamed.to_string()),
        ("listfile", has("(listfile)").to_string()),
        ("attributes", has("(attributes)").to_string()),
        ("signature", has("(signature)").to_string()),
    ];
    if json {
        let body: Vec<String> = fields
            .iter()
            .map(|(k, v)| format!("{}: {v}", json_str(k)))
            .collect();
        println!("{{{}}}", body.join(", "));
    } else {
        for (k, v) in fields {
            let v = if k == "path" { archive.path.clone() } else { v };
            println!("{:<17} {v}", k.replace('_', " "));
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// The block flags in words.
fn flags_text(flags: u32) -> String {
    let names = [
        (MPQ_FILE_IMPLODE, "implode"),
        (MPQ_FILE_COMPRESS, "compress"),
        (MPQ_FILE_ENCRYPTED, "encrypted"),
        (MPQ_FILE_KEY_V2, "fix-key"),
        (MPQ_FILE_PATCH_FILE, "patch"),
        (MPQ_FILE_SINGLE_UNIT, "single-unit"),
        (MPQ_FILE_SECTOR_CRC, "sector-crc"),
    ];
    let set: Vec<&str> = names
        .iter()
        .filter(|(f, _)| flags & f != 0)
        .map(|(_, n)| *n)
        .collect();
    if set.is_empty() {
        "-".into()
    } else {
        set.join(",")
    }
}

fn list(archive: &MpqArchive, masks: &[&str], long: bool, json: bool) -> Result<ExitCode> {
    let found = archive.find_files(masks);
    if json {
        let items: Vec<String> = found
            .iter()
            .map(|f| {
                format!(
                    "{{\"name\": {}, \"size\": {}, \"compressed_size\": {}, \"flags\": {}}}",
                    json_str(&f.name),
                    f.file_size,
                    f.compressed_size,
                    json_str(&flags_text(f.flags))
                )
            })
            .collect();
        println!("[{}]", items.join(",\n "));
    } else if long {
        for f in &found {
            println!(
                "{:>10} {:>10}  {:<28} {}",
                f.file_size,
                f.compressed_size,
                flags_text(f.flags),
                f.name
            );
        }
    } else {
        for f in &found {
            println!("{}", f.name);
        }
    }
    let unnamed = archive.unnamed_count();
    if unnamed > 0 && !json {
        eprintln!("storm: {unnamed} more files have no known name (give names with --listfile)");
    }
    Ok(ExitCode::SUCCESS)
}

fn cat(archive: &MpqArchive, name: &str) -> Result<ExitCode> {
    use std::io::Write;
    let name = mpq_name(name);
    if !archive.has_file(&name) {
        return Err(failed(format!("{}: no {name} in it", archive.path)));
    }
    let data = archive
        .read_file(&name)
        .map_err(|e| failed(format!("{name}: {e}")))?;
    let mut out = std::io::stdout().lock();
    out.write_all(&data)
        .and_then(|_| out.flush())
        .map_err(|e| failed(e.to_string()))?;
    Ok(ExitCode::SUCCESS)
}

fn extract(archive: &MpqArchive, masks: &[&str], dir: &Path) -> Result<ExitCode> {
    let found = archive.find_files(masks);
    let mut failures = 0;
    for f in &found {
        let Some(path) = extract_path(dir, &f.name) else {
            eprintln!("storm: {}: skipped, the name leaves the folder", f.name);
            failures += 1;
            continue;
        };
        let written = archive
            .read_file(&f.name)
            .map_err(|e| e.to_string())
            .and_then(|data| {
                std::fs::create_dir_all(path.parent().unwrap_or(dir)).map_err(|e| e.to_string())?;
                std::fs::write(&path, data).map_err(|e| e.to_string())
            });
        match written {
            Ok(()) => println!("{}", f.name),
            Err(e) => {
                eprintln!("storm: {}: {e}", f.name);
                failures += 1;
            }
        }
    }
    eprintln!(
        "storm: {} of {} files extracted to {}",
        found.len() - failures,
        found.len(),
        dir.display()
    );
    Ok(if failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn verify(archive: &MpqArchive, masks: &[&str], json: bool) -> Result<ExitCode> {
    let found = archive.find_files(masks);
    let mut bad = 0;
    let mut items = Vec::new();
    for f in &found {
        let r = verify_file(
            archive,
            &f.name,
            VERIFY_FILE_CRC | VERIFY_FILE_MD5 | VERIFY_SECTOR_CRC,
        );
        if !r.is_ok() {
            bad += 1;
        }
        if json {
            items.push(format!(
                "{{\"name\": {}, \"ok\": {}, \"result\": {}}}",
                json_str(&f.name),
                r.is_ok(),
                json_str(&r.error_string())
            ));
        } else if !r.is_ok() {
            println!("{}: {}", f.name, r.error_string());
        }
    }
    if json {
        println!("[{}]", items.join(",\n "));
    } else {
        eprintln!("storm: {} files checked, {bad} bad", found.len());
    }
    Ok(if bad == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn create(archive: &str, dir: &Path) -> Result<ExitCode> {
    if Path::new(archive).exists() {
        return Err(failed(format!("{archive}: already exists")));
    }
    let count = folder_files(dir)
        .map_err(|e| failed(format!("{}: {e}", dir.display())))?
        .len();
    MpqArchiveBuilder::new(archive)
        .options(MpqCreateOptions::v1().create_attributes(true))
        .add_folder(dir)
        .map_err(|e| failed(format!("{}: {e}", dir.display())))?
        .build()
        .map_err(|e| failed(format!("{archive}: {e}")))?;
    eprintln!("storm: {archive}: {count} files");
    Ok(ExitCode::SUCCESS)
}

/// Opens `archive` for changing, lets `change` do it, and writes it back.
fn change(
    archive: &str,
    change: impl FnOnce(&mut MpqArchiveWriter) -> Result<()>,
) -> Result<ExitCode> {
    let mut writer =
        MpqArchiveWriter::open(archive).map_err(|e| failed(format!("{archive}: {e}")))?;
    change(&mut writer)?;
    writer
        .finish()
        .map_err(|e| failed(format!("{archive}: {e}")))?;
    Ok(ExitCode::SUCCESS)
}

fn add(archive: &str, file: &Path, name: &str) -> Result<ExitCode> {
    let data = std::fs::read(file).map_err(|e| failed(format!("{}: {e}", file.display())))?;
    let name = mpq_name(name);
    change(archive, |w| {
        w.add_file(&name, &data, &AddFileOptions::default())
            .map_err(|e| failed(format!("{name}: {e}")))
    })
}

fn remove(archive: &str, names: &[&str]) -> Result<ExitCode> {
    change(archive, |w| {
        for name in names {
            let name = mpq_name(name);
            w.remove_file(&name)
                .map_err(|e| failed(format!("{name}: {e}")))?;
        }
        Ok(())
    })
}

fn rename(archive: &str, old: &str, new: &str) -> Result<ExitCode> {
    let (old, new) = (mpq_name(old), mpq_name(new));
    change(archive, |w| {
        w.rename_file(&old, &new)
            .map_err(|e| failed(format!("{old}: {e}")))
    })
}

/// A JSON string literal.
fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out += "\\\"",
            '\\' => out += "\\\\",
            '\n' => out += "\\n",
            '\r' => out += "\\r",
            '\t' => out += "\\t",
            c if (c as u32) < 0x20 => out += &format!("\\u{:04x}", c as u32),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
