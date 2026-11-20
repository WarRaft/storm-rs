//! An archive's files as a whole, for tools (the `storm` CLI, an MCP
//! server): listing them by mask, telling how many have no known name,
//! where each goes when extracted into a folder, and building an archive
//! from a folder.
//!
//! Names inside an archive use `\` (`Units\HumanUnitFunc.txt`);
//! [`mpq_name`] turns a `/`-separated name into one. Masks are StormLib's
//! ([`check_wildcard`]): `*` and `?`, in any case, over the whole name.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use crate::constants::MPQ_FILE_EXISTS;
use crate::file::check_wildcard;
use crate::types::FileInfo;

use super::{MpqArchive, MpqArchiveBuilder};

/// The archive's own files, which no listfile names: the listfile itself,
/// the attributes (CRC32, MD5, times), the signature.
pub const SPECIAL_FILES: [&str; 3] = ["(listfile)", "(attributes)", "(signature)"];

/// `name` as an archive spells it: `\`-separated.
pub fn mpq_name(name: &str) -> String {
    name.replace('/', "\\")
}

impl MpqArchive {
    /// The files whose names are known (from its `(listfile)` or an
    /// external one, [`add_external_listfile`](Self::add_external_listfile),
    /// and the archive's own [`SPECIAL_FILES`]) and that it has, sorted by
    /// name in any case. A file known under several names is listed once.
    pub fn named_files(&self) -> Vec<FileInfo> {
        let special = SPECIAL_FILES
            .iter()
            .filter_map(|name| self.get_file_info(name));
        let mut files: Vec<FileInfo> = self
            .iter_files()
            .chain(special)
            .filter(|f| f.flags & MPQ_FILE_EXISTS != 0)
            .collect();
        files.sort_by(|a, b| {
            a.name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase())
                .then(a.name.cmp(&b.name))
        });
        let mut seen = HashSet::new();
        files.retain(|f| seen.insert(f.block_index));
        files
    }

    /// [`named_files`](Self::named_files) whose names match any of
    /// `masks` (`/` or `\`); all of them for no masks.
    pub fn find_files<S: AsRef<str>>(&self, masks: &[S]) -> Vec<FileInfo> {
        let masks: Vec<String> = masks.iter().map(|m| mpq_name(m.as_ref())).collect();
        self.named_files()
            .into_iter()
            .filter(|f| masks.is_empty() || masks.iter().any(|m| check_wildcard(&f.name, m)))
            .collect()
    }

    /// How many stored files have no known name: an archive without a
    /// `(listfile)` (most protected maps) only lets you read a file you
    /// can name.
    pub fn unnamed_count(&self) -> usize {
        let named: HashSet<u32> = self.named_files().iter().map(|f| f.block_index).collect();
        self.block_table
            .iter()
            .enumerate()
            .filter(|(i, b)| b.flags & MPQ_FILE_EXISTS != 0 && !named.contains(&(*i as u32)))
            .count()
    }
}

/// Where the file `name` goes when extracted into `dir`: its `\`- or
/// `/`-separated parts as folders. `None` for a name that would leave
/// `dir` (`..`, a root, a drive): an archive can hold one, and writing it
/// would put a file anywhere.
pub fn extract_path(dir: &Path, name: &str) -> Option<PathBuf> {
    let rel: PathBuf = name.split(['\\', '/']).filter(|p| !p.is_empty()).collect();
    let safe = rel.components().all(|c| matches!(c, Component::Normal(_)));
    (safe && rel.components().next().is_some()).then(|| dir.join(rel))
}

/// Every file under `dir` and its name in an archive (`\`-separated,
/// relative to `dir`), sorted by name.
pub fn folder_files(dir: &Path) -> std::io::Result<Vec<(PathBuf, String)>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(folder) = stack.pop() {
        for entry in std::fs::read_dir(&folder)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(rel) = path.strip_prefix(dir) {
                let parts: Vec<String> = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect();
                out.push((path.clone(), parts.join("\\")));
            }
        }
    }
    out.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(out)
}

impl MpqArchiveBuilder {
    /// Adds every file under `dir`, named by its path relative to it
    /// ([`folder_files`]).
    pub fn add_folder(mut self, dir: &Path) -> std::io::Result<Self> {
        for (path, name) in folder_files(dir)? {
            let data = std::fs::read(&path)?;
            self = self.add_file(name, data);
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(
            mpq_name("Units/HumanUnitFunc.txt"),
            "Units\\HumanUnitFunc.txt"
        );
    }

    #[test]
    fn extract_paths_stay_in_the_folder() {
        let dir = Path::new("/out");
        assert_eq!(
            extract_path(dir, "Units\\a.txt"),
            Some(dir.join("Units").join("a.txt"))
        );
        assert_eq!(extract_path(dir, "war3map.j"), Some(dir.join("war3map.j")));
        assert_eq!(extract_path(dir, "..\\evil.j"), None);
        assert_eq!(extract_path(dir, "a\\..\\..\\evil.j"), None);
        assert_eq!(extract_path(dir, "\\\\"), None);
        assert_eq!(extract_path(dir, ""), None);
    }
}
