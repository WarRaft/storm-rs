//! Files from archives and folders laid over each other, the way a game
//! reads its data: each folder's archives in a given order, each over the
//! ones before, then the folder itself over them; a later folder over an
//! earlier one. Warcraft III, for one, opens `War3.mpq`, `War3x.mpq`,
//! `War3xLocal.mpq`, `War3Patch.mpq`, and a loose file in its folder wins
//! over all of them.
//!
//! More layers go on top with [`Layers::push`]: a folder, or an archive
//! (a map), each over everything before it; a map's files over the
//! game's, the way the game loads a map.
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

    /// Puts `path` on top of the layers: a folder as it is, a file as an
    /// archive (a map: `.w3x`, `.w3m`, any MPQ). Fails, adding nothing,
    /// when it's neither or the archive can't be opened.
    pub fn push(&mut self, path: &Path) -> Result<(), String> {
        if path.is_dir() {
            self.layers.push(Layer::Folder(path.to_path_buf()));
            return Ok(());
        }
        if !path.is_file() {
            return Err(format!("{}: no such folder or archive", path.display()));
        }
        let archive = MpqArchive::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        self.layers.push(Layer::Archive(Box::new(archive)));
        Ok(())
    }

    /// Whether nothing was opened.
    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }

    /// Where `name` comes from: the topmost layer that has it.
    pub fn find(&self, name: &str) -> Option<Source> {
        let name = clean_name(name)?;
        self.layers.iter().rev().find_map(|layer| layer.find(&name))
    }

    /// The contents of `name` from the topmost layer that has it, and
    /// where it came from. A layer that has the file but can't read it is
    /// skipped, so the layer below it answers.
    pub fn read(&self, name: &str) -> Option<(Vec<u8>, Source)> {
        let name = clean_name(name)?;
        self.layers.iter().rev().find_map(|layer| layer.read(&name))
    }

    /// Every layer that has `name`, lowest first, by its place in the
    /// stack (for [`read_in`](Self::read_in)). For a caller that reads
    /// more than the topmost copy: a file and the changes to it that
    /// layers add, say.
    pub fn holders(&self, name: &str) -> Vec<usize> {
        let Some(name) = clean_name(name) else { return Vec::new() };
        (0..self.layers.len()).filter(|&i| self.layers[i].find(&name).is_some()).collect()
    }

    /// The contents of `name` from layer `layer` alone (a place
    /// [`holders`](Self::holders) gives), and where it came from.
    pub fn read_in(&self, layer: usize, name: &str) -> Option<(Vec<u8>, Source)> {
        self.layers.get(layer)?.read(&clean_name(name)?)
    }
}

impl Layer {
    /// Where this layer has `name` (a clean name), if it does.
    fn find(&self, name: &str) -> Option<Source> {
        match self {
            Layer::Archive(a) => a.has_file(name).then(|| Source::Archive(PathBuf::from(&a.path))),
            Layer::Folder(dir) => find_file(dir, name).map(Source::File),
        }
    }

    /// This layer's `name` (a clean name), if it has it and it reads.
    fn read(&self, name: &str) -> Option<(Vec<u8>, Source)> {
        match self {
            Layer::Archive(a) => {
                if !a.has_file(name) {
                    return None;
                }
                let data = a.read_file(name).ok()?;
                Some((data, Source::Archive(PathBuf::from(&a.path))))
            }
            Layer::Folder(dir) => {
                let path = find_file(dir, name)?;
                let data = std::fs::read(&path).ok()?;
                Some((data, Source::File(path)))
            }
        }
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
        // Each copy, by its layer: base.mpq, PATCH.mpq, the folder.
        assert_eq!(layers.holders("A.TXT"), vec![0, 1]);
        assert_eq!(layers.holders("units\\b.txt"), vec![0, 2]);
        assert!(layers.holders("nope.txt").is_empty());
        let copy = |i: usize, n: &str| layers.read_in(i, n).map(|(d, _)| String::from_utf8(d).unwrap());
        assert_eq!(copy(0, "a.txt").as_deref(), Some("base"));
        assert_eq!(copy(0, "Units/b.txt").as_deref(), Some("base"));
        assert_eq!(copy(2, "Units/b.txt").as_deref(), Some("loose"));
        assert_eq!(copy(2, "a.txt"), None);
        assert_eq!(copy(9, "a.txt"), None);
        assert!(Layers::open(&[dir.join("none")], &["base.mpq"]).0.is_empty());
    }

    #[test]
    fn pushed_roots_go_on_top() {
        let dir = std::env::temp_dir().join(format!("storm-layers-roots-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let game = dir.join("game");
        let root = dir.join("root");
        std::fs::create_dir_all(&game).unwrap();
        std::fs::create_dir_all(root.join("UI")).unwrap();
        std::fs::write(game.join("a.txt"), "game").unwrap();
        std::fs::write(game.join("b.txt"), "game").unwrap();
        std::fs::write(game.join("c.txt"), "game").unwrap();
        MpqArchiveBuilder::new(dir.join("Map.w3x"))
            .add_file("a.txt", b"map".to_vec())
            .add_file("b.txt", b"map".to_vec())
            .build()
            .unwrap();
        std::fs::write(root.join("B.TXT"), "root").unwrap();
        let (mut layers, _) = Layers::open(std::slice::from_ref(&game), &[]);
        layers.push(&dir.join("Map.w3x")).unwrap();
        layers.push(&root).unwrap();
        let text = |n: &str| layers.read(n).map(|(d, _)| String::from_utf8(d).unwrap());
        assert_eq!(text("a.txt").as_deref(), Some("map"));
        assert_eq!(text("b.txt").as_deref(), Some("root"));
        assert_eq!(text("C.txt").as_deref(), Some("game"));
        assert_eq!(layers.find("a.txt"), Some(Source::Archive(dir.join("Map.w3x"))));
        assert!(layers.push(&dir.join("none")).unwrap_err().contains("no such folder"));
        std::fs::write(dir.join("junk.w3x"), "no").unwrap();
        assert!(layers.push(&dir.join("junk.w3x")).is_err());
    }
}
