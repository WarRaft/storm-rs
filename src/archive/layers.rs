//! Files from archives and folders laid over each other, the way a game
//! reads its data: each folder's archives in a given order, each over the
//! ones before, then the folder itself over them; a later folder over an
//! earlier one. Warcraft III, for one, opens `War3.mpq`, `War3x.mpq`,
//! `War3xLocal.mpq`, `War3Patch.mpq`, and a loose file in its folder wins
//! over all of them.
//!
//! A file is named the way an archive names it, `Units\UnitData.slk`; `/`
//! works too, and on disk any case matches.

use std::path::{Path, PathBuf};

use super::MpqArchive;

/// Warcraft III's archives, in the order it opens them: each over the
/// ones before. [`Layers::open`] them from a game folder.
pub const WAR3_ARCHIVES: [&str; 4] = ["War3.mpq", "War3x.mpq", "War3xLocal.mpq", "War3Patch.mpq"];

/// One place a file can come from.
#[derive(Debug)]
enum Layer {
    Archive(Box<MpqArchive>),
    Folder(PathBuf),
}

/// Where a file was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// In this archive.
    Archive(PathBuf),
    /// This file on disk.
    File(PathBuf),
}

/// Archives and folders over each other: see the module docs.
#[derive(Debug, Default)]
pub struct Layers {
    /// Lowest first; a lookup walks them from the top.
    layers: Vec<Layer>,
}

impl Layers {
    /// Opens `folders`, lowest first: in each, the archives named
    /// `archives` (in that order, matched in any case), then the folder.
    /// Never fails: an archive that can't be opened is left out and
    /// reported (`path: error`), and the rest still apply. A folder that
    /// doesn't exist adds nothing.
    pub fn open(folders: &[PathBuf], archives: &[&str]) -> (Layers, Vec<String>) {
        let mut out = Layers::default();
        let mut errors = Vec::new();
        for folder in folders {
            for name in archives {
                let Some(path) = find_entry(folder, name) else { continue };
                if !path.is_file() {
                    continue;
                }
                match MpqArchive::open(&path) {
                    Ok(archive) => out.layers.push(Layer::Archive(Box::new(archive))),
                    Err(e) => errors.push(format!("{}: {e}", path.display())),
                }
            }
            if folder.is_dir() {
                out.layers.push(Layer::Folder(folder.clone()));
            }
        }
        (out, errors)
    }

    /// Whether nothing was opened.
    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }

    /// Where `name` comes from: the topmost layer that has it.
    pub fn find(&self, name: &str) -> Option<Source> {
        let name = clean_name(name)?;
        self.layers.iter().rev().find_map(|layer| match layer {
            Layer::Archive(a) => a.has_file(&name).then(|| Source::Archive(PathBuf::from(&a.path))),
            Layer::Folder(dir) => find_file(dir, &name).map(Source::File),
        })
    }

    /// The contents of `name` from the topmost layer that has it, and
    /// where it came from. A layer that has the file but can't read it is
    /// skipped, so the layer below it answers.
    pub fn read(&self, name: &str) -> Option<(Vec<u8>, Source)> {
        let name = clean_name(name)?;
        self.layers.iter().rev().find_map(|layer| match layer {
            Layer::Archive(a) => {
                if !a.has_file(&name) {
                    return None;
                }
                let data = a.read_file(&name).ok()?;
                Some((data, Source::Archive(PathBuf::from(&a.path))))
            }
            Layer::Folder(dir) => {
                let path = find_file(dir, &name)?;
                let data = std::fs::read(&path).ok()?;
                Some((data, Source::File(path)))
            }
        })
    }
}

/// `name` as an archive names it: `\`-separated, without empty, `.` or
/// `..` parts. `None` when nothing is left or it tries to climb out.
fn clean_name(name: &str) -> Option<String> {
    let mut parts = Vec::new();
    for part in name.split(['\\', '/']) {
        match part {
            "" | "." => {}
            ".." => return None,
            p => parts.push(p),
        }
    }
    (!parts.is_empty()).then(|| parts.join("\\"))
}

/// The file `name` (`\`-separated) under `dir`, matching each part in
/// any case.
fn find_file(dir: &Path, name: &str) -> Option<PathBuf> {
    let mut path = dir.to_path_buf();
    for part in name.split('\\') {
        path = find_entry(&path, part)?;
    }
    path.is_file().then_some(path)
}

/// The entry `name` of `dir`, under its name on disk: that exact name, or
/// else the entry whose name matches it in any case. Read from the folder,
/// not checked with `exists`, which on a case-insensitive disk would say
/// yes under the name asked for.
pub fn find_entry(dir: &Path, name: &str) -> Option<PathBuf> {
    let names: Vec<std::ffi::OsString> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.file_name())
        .collect();
    let found = names
        .iter()
        .find(|n| n.to_str() == Some(name))
        .or_else(|| names.iter().find(|n| n.to_str().is_some_and(|n| n.eq_ignore_ascii_case(name))))?;
    Some(dir.join(found))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::MpqArchiveBuilder;

    #[test]
    fn layers_stack_and_a_folder_wins() {
        let dir = std::env::temp_dir().join(format!("storm-layers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let game = dir.join("game");
        std::fs::create_dir_all(game.join("Units")).unwrap();
        MpqArchiveBuilder::new(game.join("base.mpq"))
            .add_file("a.txt", b"base".to_vec())
            .add_file("Units\\b.txt", b"base".to_vec())
            .build()
            .unwrap();
        MpqArchiveBuilder::new(game.join("PATCH.mpq"))
            .add_file("a.txt", b"patch".to_vec())
            .build()
            .unwrap();
        std::fs::write(game.join("Units").join("b.txt"), "loose").unwrap();
        let (layers, errors) = Layers::open(std::slice::from_ref(&game), &["base.mpq", "patch.mpq", "missing.mpq"]);
        assert!(errors.is_empty(), "{errors:?}");
        let text = |n: &str| layers.read(n).map(|(d, _)| String::from_utf8(d).unwrap());
        assert_eq!(text("a.txt").as_deref(), Some("patch"));
        assert_eq!(text("units/B.TXT").as_deref(), Some("loose"));
        assert_eq!(layers.find("Units/b.txt"), Some(Source::File(game.join("Units").join("b.txt"))));
        assert_eq!(text("..\\a.txt"), None);
        assert_eq!(text("nope.txt"), None);
        assert!(Layers::open(&[dir.join("none")], &["base.mpq"]).0.is_empty());
    }
}
