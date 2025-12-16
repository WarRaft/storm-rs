//! File search within MPQ archives.
//! Ported from SFileFindFile.cpp

use crate::archive::MpqArchive;
use crate::constants::*;

/// Data about a found file.
#[derive(Clone, Debug)]
pub struct FileFindData {
    /// File name (relative path in archive)
    pub file_name: String,
    /// Plain file name (without directory path)
    pub plain_name: String,
    /// Hash table index
    pub hash_index: u32,
    /// Block table index
    pub block_index: u32,
    /// Uncompressed file size
    pub file_size: u32,
    /// Compressed file size
    pub compressed_size: u32,
    /// File flags
    pub file_flags: u32,
    /// File locale
    pub locale: u32,
}

impl FileFindData {
    /// Check if file is compressed
    pub fn is_compressed(&self) -> bool {
        (self.file_flags & MPQ_FILE_COMPRESS_MASK) != 0
    }

    /// Check if file is encrypted
    pub fn is_encrypted(&self) -> bool {
        (self.file_flags & MPQ_FILE_ENCRYPTED) != 0
    }

    /// Get compression ratio (1.0 = no compression)
    pub fn compression_ratio(&self) -> f32 {
        if self.compressed_size == 0 {
            1.0
        } else {
            self.file_size as f32 / self.compressed_size as f32
        }
    }
}

/// Check if a string matches a wildcard pattern.
/// Supports '*' (any characters) and '?' (single character).
/// Matching is case-insensitive.
pub fn check_wildcard(text: &str, pattern: &str) -> bool {
    let text = text.to_ascii_uppercase();
    let pattern = pattern.to_ascii_uppercase();

    check_wildcard_internal(text.as_bytes(), pattern.as_bytes())
}

fn check_wildcard_internal(text: &[u8], pattern: &[u8]) -> bool {
    let mut t = 0;
    let mut p = 0;

    while p < pattern.len() {
        match pattern[p] {
            b'?' => {
                // Match single character
                if t >= text.len() {
                    return false;
                }
                t += 1;
                p += 1;
            }
            b'*' => {
                // Skip multiple '*'
                while p < pattern.len() && pattern[p] == b'*' {
                    p += 1;
                }

                // '*' at end matches everything
                if p >= pattern.len() {
                    return true;
                }

                // Try matching rest from each position
                while t < text.len() {
                    if check_wildcard_internal(&text[t..], &pattern[p..]) {
                        return true;
                    }
                    t += 1;
                }

                return check_wildcard_internal(&text[t..], &pattern[p..]);
            }
            ch => {
                if t >= text.len() || text[t] != ch {
                    return false;
                }
                t += 1;
                p += 1;
            }
        }
    }

    t >= text.len()
}

/// Get plain filename from full path.
fn get_plain_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// Iterator for searching files in an MPQ archive.
pub struct FileSearcher<'a> {
    archive: &'a MpqArchive,
    mask: String,
    next_index: usize,
}

impl<'a> FileSearcher<'a> {
    /// Create a new file searcher.
    pub fn new(archive: &'a MpqArchive, mask: &str) -> Self {
        Self {
            archive,
            mask: mask.to_string(),
            next_index: 0,
        }
    }
}

impl<'a> Iterator for FileSearcher<'a> {
    type Item = FileFindData;

    fn next(&mut self) -> Option<Self::Item> {
        let hash_table = &self.archive.hash_table;

        while self.next_index < hash_table.len() {
            let idx = self.next_index;
            self.next_index += 1;

            let hash = &hash_table[idx];

            // Check if valid hash entry
            if hash.block_index == HASH_ENTRY_FREE || hash.block_index == HASH_ENTRY_DELETED {
                continue;
            }

            let block_idx = hash.block_index as usize;
            if block_idx >= self.archive.block_table.len() {
                continue;
            }

            let block = &self.archive.block_table[block_idx];

            // Check if file exists
            if (block.flags & MPQ_FILE_EXISTS) == 0 {
                continue;
            }

            // Get file name from listfile if available
            let file_name = self.archive.get_filename_by_block_index(block_idx);

            // If no filename, create pseudo-name
            let file_name = file_name.unwrap_or_else(|| format!("File{:08X}.xxx", block_idx));

            // Check wildcard match
            if !check_wildcard(&file_name, &self.mask) {
                continue;
            }

            let plain_name = get_plain_name(&file_name).to_string();

            return Some(FileFindData {
                file_name,
                plain_name,
                hash_index: idx as u32,
                block_index: block_idx as u32,
                file_size: block.file_size,
                compressed_size: block.compressed_size,
                file_flags: block.flags,
                locale: ((hash.locale as u32) << 16) | (hash.platform as u32),
            });
        }

        None
    }
}

/// Single function to find first matching file.
pub fn find_first_file(archive: &MpqArchive, mask: &str) -> Option<FileFindData> {
    FileSearcher::new(archive, mask).next()
}

/// Get all files matching a pattern.
pub fn find_all_files(archive: &MpqArchive, mask: &str) -> Vec<FileFindData> {
    FileSearcher::new(archive, mask).collect()
}

/// Count files matching a pattern.
pub fn count_files(archive: &MpqArchive, mask: &str) -> usize {
    FileSearcher::new(archive, mask).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_star() {
        assert!(check_wildcard("file.txt", "*"));
        assert!(check_wildcard("file.txt", "*.txt"));
        assert!(check_wildcard("file.txt", "file.*"));
        assert!(check_wildcard("path/to/file.txt", "*.txt"));
        assert!(!check_wildcard("file.txt", "*.blp"));
    }

    #[test]
    fn test_wildcard_question() {
        assert!(check_wildcard("file.txt", "fil?.txt"));
        assert!(check_wildcard("file.txt", "????.txt"));
        assert!(!check_wildcard("file.txt", "???.txt"));
    }

    #[test]
    fn test_wildcard_case_insensitive() {
        assert!(check_wildcard("FILE.TXT", "*.txt"));
        assert!(check_wildcard("file.txt", "*.TXT"));
    }

    #[test]
    fn test_wildcard_complex() {
        assert!(check_wildcard(
            "Units\\Human\\Footman.mdx",
            "Units\\*\\*.mdx"
        ));
        assert!(check_wildcard("Units\\Human\\Footman.mdx", "*Footman*"));
    }

    #[test]
    fn test_get_plain_name() {
        assert_eq!(get_plain_name("path\\to\\file.txt"), "file.txt");
        assert_eq!(get_plain_name("path/to/file.txt"), "file.txt");
        assert_eq!(get_plain_name("file.txt"), "file.txt");
    }
}
