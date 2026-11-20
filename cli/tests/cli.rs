//! The `storm` command, run as a program on archives made for the test.

use std::path::{Path, PathBuf};
use std::process::Command;

use storm_rs::archive::MpqArchiveBuilder;
use storm_rs::archive::create::MpqCreateOptions;

/// A fresh folder for one test.
fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("storm-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Runs `storm` with `args`: exit code, stdout, stderr.
fn storm(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_storm"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn create_list_cat_extract() {
    let dir = temp("roundtrip");
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("Units")).unwrap();
    std::fs::write(
        src.join("war3map.j"),
        "function main takes nothing returns nothing\nendfunction\n",
    )
    .unwrap();
    std::fs::write(
        src.join("Units").join("HumanUnitFunc.txt"),
        "[hfoo]\nArt=x\n",
    )
    .unwrap();
    let mpq = dir.join("a.w3x");

    let (code, _, err) = storm(&["create", s(&mpq), s(&src)]);
    assert_eq!(code, 0, "{err}");
    // It won't overwrite.
    assert_eq!(storm(&["create", s(&mpq), s(&src)]).0, 1);

    let (code, out, _) = storm(&["list", s(&mpq)]);
    assert_eq!(code, 0);
    assert_eq!(
        out,
        "(attributes)\n(listfile)\nUnits\\HumanUnitFunc.txt\nwar3map.j\n"
    );
    // Masks, `/` for `\`, any case.
    assert_eq!(
        storm(&["list", s(&mpq), "units/*.TXT"]).1,
        "Units\\HumanUnitFunc.txt\n"
    );
    let (_, json, _) = storm(&["list", s(&mpq), "war3map.*", "--json"]);
    assert!(
        json.starts_with("[{\"name\": \"war3map.j\", \"size\": 56,"),
        "{json}"
    );

    assert_eq!(
        storm(&["cat", s(&mpq), "Units/HumanUnitFunc.txt"]).1,
        "[hfoo]\nArt=x\n"
    );
    assert_eq!(storm(&["cat", s(&mpq), "nope.j"]).0, 1);

    let out_dir = dir.join("out");
    let (code, out, _) = storm(&["extract", s(&mpq), "*.txt", "-o", s(&out_dir)]);
    assert_eq!((code, out.as_str()), (0, "Units\\HumanUnitFunc.txt\n"));
    assert_eq!(
        std::fs::read_to_string(out_dir.join("Units").join("HumanUnitFunc.txt")).unwrap(),
        "[hfoo]\nArt=x\n"
    );
    assert!(!out_dir.join("war3map.j").exists());

    let (code, _, err) = storm(&["verify", s(&mpq)]);
    assert_eq!(code, 0, "{err}");
    let (_, info, _) = storm(&["info", s(&mpq), "--json"]);
    assert!(
        info.contains("\"named\": 4, \"unnamed\": 0, \"listfile\": true, \"attributes\": true"),
        "{info}"
    );
}

#[test]
fn add_remove_rename() {
    let dir = temp("change");
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("a.j"), "a").unwrap();
    let mpq = dir.join("a.mpq");
    assert_eq!(storm(&["create", s(&mpq), s(&src)]).0, 0);

    let file = dir.join("b.j");
    std::fs::write(&file, "bee").unwrap();
    assert_eq!(storm(&["add", s(&mpq), s(&file)]).0, 0);
    assert_eq!(storm(&["add", s(&mpq), s(&file), "Scripts/c.j"]).0, 0);
    assert_eq!(storm(&["cat", s(&mpq), "Scripts\\c.j"]).1, "bee");
    assert_eq!(storm(&["rename", s(&mpq), "b.j", "d.j"]).0, 0);
    assert_eq!(storm(&["remove", s(&mpq), "a.j"]).0, 0);
    let (_, out, _) = storm(&["list", s(&mpq), "*.j"]);
    assert_eq!(out, "d.j\nScripts\\c.j\n");
}

#[test]
fn names_from_an_external_listfile() {
    let dir = temp("listfile");
    let mpq = dir.join("p.w3x");
    MpqArchiveBuilder::new(&mpq)
        .options(MpqCreateOptions::v1().create_listfile(false))
        .add_file("war3map.j", b"x".to_vec())
        .add_file("..\\evil.j", b"x".to_vec())
        .build()
        .unwrap();
    let (code, out, err) = storm(&["list", s(&mpq)]);
    assert_eq!((code, out.as_str()), (0, ""));
    assert!(err.contains("2 more files have no known name"), "{err}");

    let names = dir.join("names.txt");
    // Junk lines and `\r\n` don't matter.
    std::fs::write(
        &names,
        b"\xff\xfe junk\r\nwar3map.j\r\n..\\evil.j\r\nnot-there.j\r\n",
    )
    .unwrap();
    let (_, out, _) = storm(&["list", s(&mpq), "--listfile", s(&names)]);
    assert_eq!(out, "..\\evil.j\nwar3map.j\n");

    // A name that would leave the folder isn't written.
    let out_dir = dir.join("out");
    let (code, out, err) = storm(&[
        "extract",
        s(&mpq),
        "--listfile",
        s(&names),
        "-o",
        s(&out_dir),
    ]);
    assert_eq!((code, out.as_str()), (1, "war3map.j\n"));
    assert!(err.contains("..\\evil.j: skipped"), "{err}");
    assert!(!dir.join("evil.j").exists());
}

#[test]
fn usage_errors() {
    assert_eq!(storm(&[]).0, 2);
    assert_eq!(storm(&["frobnicate", "x"]).0, 2);
    assert_eq!(storm(&["list"]).0, 2);
    assert_eq!(storm(&["list", "x", "--bogus"]).0, 2);
    assert_eq!(storm(&["--help"]).0, 0);
    let (code, _, err) = storm(&["list", "/nonexistent.mpq"]);
    assert_eq!(code, 1);
    assert!(err.starts_with("storm: /nonexistent.mpq: "), "{err}");
}
