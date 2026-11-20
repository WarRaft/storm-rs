//! Archive opening and management.
//! Ported from SFileOpenArchive.cpp

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::constants::*;
use crate::crypto::hash_string;
use crate::error::{MpqError, MpqResult};
use crate::types::*;

use super::het_bet::{find_file_entry_v4, read_bet_table, read_het_table};
use super::tables::{find_file_entry, read_block_table, read_hash_table, read_hi_block_table};

/// An opened MPQ archive.
#[derive(Debug)]
pub struct MpqArchive {
    /// Path to the archive file.
    pub path: String,
    /// Offset of the MPQ header in the file.
    pub mpq_offset: u64,
    /// MPQ header.
    pub header: MpqHeader,
    /// Hash table.
    pub hash_table: Vec<MpqHash>,
    /// Block table.
    pub block_table: Vec<MpqBlock>,
    /// Hi-block table (for 64-bit offsets).
    pub hi_block_table: Vec<u16>,
    /// Archive flags.
    pub flags: u32,
    /// Sector size in bytes.
    pub sector_size: u32,
    /// HET table (for v4 archives).
    pub het_table: Option<HetTable>,
    /// BET table (for v4 archives).
    pub bet_table: Option<BetTable>,
    /// Patch archives (applied on top of this one).
    pub patches: Vec<MpqArchive>,
    /// File attributes (CRC32, MD5, FileTime) from (attributes) file.
    /// Indexed by block index.
    pub attributes: Vec<Option<MpqFileAttribute>>,
    /// Known filenames (from (listfile) or added externally).
    pub known_filenames: std::collections::HashSet<String>,
    /// Bitmap of present blocks (for partial MPQs).
    pub bitmap: Option<Vec<u8>>,
    /// Block size for the bitmap.
    pub bitmap_block_size: u32,
}

impl MpqArchive {
    /// Open an MPQ archive from a file path.
    pub fn open<P: AsRef<Path>>(path: P) -> MpqResult<Self> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        let file = File::open(&path)?;
        let mut reader = BufReader::new(file);

        // Search for MPQ header
        let (mpq_offset, header) = find_mpq_header(&mut reader)?;

        // Read tables
        let hash_table = read_hash_table(&mut reader, &header, mpq_offset)?;
        let block_table = read_block_table(&mut reader, &header, mpq_offset)?;
        let hi_block_table = read_hi_block_table(&mut reader, &header, mpq_offset)?;
        let het_table = read_het_table(&mut reader, &header, mpq_offset)?;
        let bet_table = read_bet_table(&mut reader, &header, mpq_offset)?;

        let sector_size = header.sector_size_bytes();

        let mut archive = MpqArchive {
            path: path_str,
            mpq_offset,
            header,
            hash_table,
            block_table,
            hi_block_table,
            flags: MPQ_FLAG_READ_ONLY,
            sector_size,
            het_table,
            bet_table,
            patches: Vec::new(),
            attributes: Vec::new(),
            known_filenames: std::collections::HashSet::new(),
            bitmap: None,
            bitmap_block_size: 0,
        };

        // Try to read partial MPQ bitmap
        let _ = archive.read_bitmap();

        // Try to read attributes
        // Ignore errors here as attributes are optional
        let _ = archive.read_attributes();

        // Try to read listfile
        let _ = archive.read_listfile();

        Ok(archive)
    }

    /// Add a patch archive.
    ///
    /// The patch archive is added to the end of the patch chain.
    /// Files in the patch archive override files in the base archive (and previous patches).
    pub fn add_patch<P: AsRef<Path>>(&mut self, path: P) -> MpqResult<()> {
        let patch_archive = MpqArchive::open(path)?;
        self.patches.push(patch_archive);
        Ok(())
    }

    /// Check if the archive (or any patch) contains a file.
    pub fn has_file(&self, filename: &str) -> bool {
        // Check patches first (in reverse order)
        for patch in self.patches.iter().rev() {
            if patch.has_file(filename) {
                return true;
            }
        }

        if let (Some(het), Some(bet)) = (&self.het_table, &self.bet_table)
            && find_file_entry_v4(het, bet, filename).is_some()
        {
            return true;
        }
        find_file_entry(&self.hash_table, &self.block_table, filename, 0).is_some()
    }

    /// Get file size by name.
    pub fn get_file_size(&self, filename: &str) -> Option<u32> {
        // Check patches first
        for patch in self.patches.iter().rev() {
            if let Some(size) = patch.get_file_size(filename) {
                return Some(size);
            }
        }

        if let (Some(het), Some(bet)) = (&self.het_table, &self.bet_table)
            && let Some(info) = find_file_entry_v4(het, bet, filename)
        {
            return Some(info.file_size);
        }
        find_file_entry(&self.hash_table, &self.block_table, filename, 0)
            .map(|(_, block)| block.file_size)
    }

    /// Get file info.
    pub fn get_file_info(&self, filename: &str) -> Option<FileInfo> {
        // Check patches first
        for patch in self.patches.iter().rev() {
            if let Some(info) = patch.get_file_info(filename) {
                return Some(info);
            }
        }

        self.get_file_info_internal(filename)
    }

    /// Read a file from the archive.
    pub fn read_file(&self, filename: &str) -> MpqResult<Vec<u8>> {
        self.read_file_with_limit(filename, self.patches.len())
    }

    /// Read file with patch limit (helper for incremental patching).
    fn read_file_with_limit(&self, filename: &str, patch_limit: usize) -> MpqResult<Vec<u8>> {
        // Check patches first (in reverse order, up to limit)
        for i in (0..patch_limit).rev() {
            let patch = &self.patches[i];
            if patch.has_file(filename) {
                // Read the file from the patch archive
                // Note: patch.read_file() might recurse if the patch archive itself has patches,
                // but usually patch archives are flat.
                let patch_data = patch.read_file(filename)?;

                // Check if it is a patch file
                let file_info = patch
                    .get_file_info(filename)
                    .ok_or(MpqError::FileNotFound)?;

                if (file_info.flags & MPQ_FILE_PATCH_FILE) != 0 {
                    // It is a patch file. We need base data from the rest of the chain.
                    let base_data = self.read_file_with_limit(filename, i)?;

                    // Apply patch
                    return crate::archive::patch::apply_patch(&base_data, &patch_data);
                } else {
                    // It is a full replacement file
                    return Ok(patch_data);
                }
            }
        }

        // If not found in patches, read from base archive
        // We use read_file_internal to skip patch check (which we just did)
        // But read_file_internal errors if not found.
        // If we are here, it means it wasn't in any patch (or all patches were partial and we needed base).

        // Wait, if it wasn't in any patch, we read from base.
        // If it WAS in a patch but was a patch file, we recursed.
        // Eventually we hit this base read.

        self.read_file_internal(filename)
    }

    /// Extract a file from the archive to a local path.
    pub fn extract_file<P: AsRef<Path>>(&self, filename: &str, target_path: P) -> MpqResult<()> {
        let data = self.read_file(filename)?;
        std::fs::write(target_path, data)?;
        Ok(())
    }

    /// Get the number of files in the archive.
    pub fn file_count(&self) -> usize {
        self.block_table.iter().filter(|b| b.exists()).count()
    }

    /// Read the raw data of a file block (compressed/encrypted).
    pub fn read_raw_block(&self, block: &MpqBlock) -> MpqResult<Vec<u8>> {
        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(file);
        let offset = self.mpq_offset + block.file_pos as u64;

        // Check partial MPQ bitmap
        self.check_bitmap(offset, block.compressed_size as u64)?;

        reader.seek(SeekFrom::Start(offset))?;

        let mut buffer = vec![0u8; block.compressed_size as usize];
        reader.read_exact(&mut buffer)?;

        Ok(buffer)
    }

    /// Get filename by block index from known filenames.
    /// Returns None if filename is not known.
    pub fn get_filename_by_block_index(&self, block_index: usize) -> Option<String> {
        for filename in &self.known_filenames {
            // Check if this filename hashes to our block index
            if let Some((idx, _)) =
                find_file_entry(&self.hash_table, &self.block_table, filename, 0)
                && idx as usize == block_index
            {
                return Some(filename.clone());
            }
        }
        None
    }

    /// Get all known filenames.
    pub fn list_files(&self) -> Vec<String> {
        let mut files = self.known_filenames.clone();

        // Add files from patches
        for patch in &self.patches {
            let patch_files = patch.list_files();
            for f in patch_files {
                files.insert(f);
            }
        }

        files.into_iter().collect()
    }

    /// Iterate over all known files in the archive (including patches), yielding their metadata.
    pub fn iter_files(&self) -> impl Iterator<Item = FileInfo> + '_ {
        let mut files = self.known_filenames.clone();

        // Add files from patches
        for patch in &self.patches {
            let patch_files = patch.list_files();
            for f in patch_files {
                files.insert(f);
            }
        }

        files
            .into_iter()
            .filter_map(move |name| self.get_file_info(&name))
    }

    /// Get all available locales for a given file.
    pub fn get_file_locales(&self, name: &str) -> Vec<u16> {
        let mut locales = Vec::new();

        let hash_a = hash_string(name, MPQ_HASH_NAME_A);
        let hash_b = hash_string(name, MPQ_HASH_NAME_B);
        let start_index = hash_string(name, MPQ_HASH_TABLE_INDEX) as usize % self.hash_table.len();

        let mut index = start_index;
        loop {
            let entry = &self.hash_table[index];

            if entry.hash_check_a == hash_a
                && entry.hash_check_b == hash_b
                && entry.block_index != HASH_ENTRY_DELETED
            {
                locales.push(entry.locale);
            }

            if entry.block_index == HASH_ENTRY_FREE {
                break;
            }

            index = (index + 1) % self.hash_table.len();
            if index == start_index {
                break;
            }
        }

        // Check patches
        for patch in &self.patches {
            let patch_locales = patch.get_file_locales(name);
            for locale in patch_locales {
                if !locales.contains(&locale) {
                    locales.push(locale);
                }
            }
        }

        locales
    }

    /// Read and parse the internal (listfile).
    ///
    /// Line by line: a line that isn't UTF-8 is skipped, not the whole
    /// listfile. Some archives (Warcraft III's `War3Patch.mpq`) start it
    /// with junk bytes to put tools off.
    pub fn read_listfile(&mut self) -> MpqResult<()> {
        if let Ok(listfile_data) = self.read_file_internal("(listfile)") {
            self.add_listfile_names(&listfile_data);
        }
        Ok(())
    }

    /// Adds the names of a listfile's bytes: one per line (`\r\n`, `\n`
    /// or `;`), trimmed; lines that aren't UTF-8 are skipped.
    fn add_listfile_names(&mut self, data: &[u8]) {
        for line in data.split(|&b| b == b'\n' || b == b'\r' || b == b';') {
            if let Ok(name) = std::str::from_utf8(line) {
                let name = name.trim();
                if !name.is_empty() {
                    self.known_filenames.insert(name.to_string());
                }
            }
        }
    }

    /// Add an external listfile to the known filenames.
    pub fn add_external_listfile<P: AsRef<Path>>(&mut self, path: P) -> MpqResult<()> {
        let data = std::fs::read(path)?;
        self.add_listfile_names(&data);
        Ok(())
    }

    /// Internal read_file that skips patch check (to avoid recursion loops or specific base archive access)
    fn read_file_internal(&self, filename: &str) -> MpqResult<Vec<u8>> {
        let file_info = self
            .get_file_info_internal(filename)
            .ok_or(MpqError::FileNotFound)?;

        // Check partial MPQ bitmap
        self.check_bitmap(file_info.offset, file_info.compressed_size as u64)?;

        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(file);

        crate::file::read_file(&mut reader, self, &file_info)
    }

    fn get_file_info_internal(&self, filename: &str) -> Option<FileInfo> {
        let mut info = if let (Some(het), Some(bet)) = (&self.het_table, &self.bet_table) {
            if let Some(mut info) = find_file_entry_v4(het, bet, filename) {
                // Adjust offset to be absolute
                info.offset += self.mpq_offset;
                Some(info)
            } else {
                None
            }
        } else {
            None
        };

        if info.is_none() {
            let (block_index, block) =
                find_file_entry(&self.hash_table, &self.block_table, filename, 0)?;

            // Calculate offset
            let hi_offset = if (block_index as usize) < self.hi_block_table.len() {
                self.hi_block_table[block_index as usize] as u64
            } else {
                0
            };
            let offset = self.mpq_offset + (hi_offset << 32) + (block.file_pos as u64);

            info = Some(FileInfo {
                name: filename.to_string(),
                offset,
                compressed_size: block.compressed_size,
                file_size: block.file_size,
                flags: block.flags,
                block_index,
                crc32: 0,
                file_time: 0,
                md5: [0; 16],
            });
        }

        if let Some(ref mut info) = info {
            // Populate attributes if available
            if (info.block_index as usize) < self.attributes.len()
                && let Some(Some(attr)) = self.attributes.get(info.block_index as usize)
            {
                info.crc32 = attr.crc32;
                info.file_time = attr.file_time;
                info.md5 = attr.md5;
            }
        }

        info
    }

    /// Read and parse the (attributes) file.
    pub fn read_attributes(&mut self) -> MpqResult<()> {
        // Try to read (attributes) file
        let data = match self.read_file_internal("(attributes)") {
            Ok(data) => data,
            Err(_) => return Ok(()), // Not found, just ignore
        };

        use byteorder::{LittleEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new(&data);

        // Read header
        if data.len() < 8 {
            return Ok(()); // Corrupt or empty
        }

        let version = cursor.read_u32::<LittleEndian>()?;
        let flags = cursor.read_u32::<LittleEndian>()?;

        if version != 100 {
            return Ok(()); // Unknown version
        }

        // The (attributes) file contains arrays of values for each block in the block table.
        // The arrays are present based on the flags.
        // The size of each array is block_table.len().

        let block_count = self.block_table.len();
        let mut attributes = vec![None; block_count];

        // Initialize attributes with defaults
        for i in 0..block_count {
            attributes[i] = Some(MpqFileAttribute::default());
        }

        // Read CRC32 array
        if (flags & MPQ_ATTRIBUTE_CRC32) != 0 {
            for i in 0..block_count {
                if let Ok(val) = cursor.read_u32::<LittleEndian>() {
                    if let Some(attr) = &mut attributes[i] {
                        attr.crc32 = val;
                    }
                } else {
                    break;
                }
            }
        }

        // Read FileTime array
        if (flags & MPQ_ATTRIBUTE_FILETIME) != 0 {
            for i in 0..block_count {
                if let Ok(val) = cursor.read_u64::<LittleEndian>() {
                    if let Some(attr) = &mut attributes[i] {
                        attr.file_time = val;
                    }
                } else {
                    break;
                }
            }
        }

        // Read MD5 array
        if (flags & MPQ_ATTRIBUTE_MD5) != 0 {
            for i in 0..block_count {
                let mut buf = [0u8; 16];
                if cursor.read_exact(&mut buf).is_ok() {
                    if let Some(attr) = &mut attributes[i] {
                        attr.md5 = buf;
                    }
                } else {
                    break;
                }
            }
        }

        self.attributes = attributes;
        Ok(())
    }

    /// Read partial MPQ bitmap.
    pub fn read_bitmap(&mut self) -> MpqResult<()> {
        let file = File::open(&self.path)?;
        let file_size = file.metadata()?.len();
        let footer_size = 24; // sizeof(FileBitmapFooter)

        if file_size < footer_size {
            return Ok(());
        }

        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(file_size - footer_size))?;

        let mut signature_bytes = [0u8; 4];
        reader.read_exact(&mut signature_bytes)?;
        let signature = u32::from_le_bytes(signature_bytes);

        if signature == crate::types::ID_FILE_BITMAP_FOOTER {
            let mut version_bytes = [0u8; 4];
            reader.read_exact(&mut version_bytes)?;
            let _version = u32::from_le_bytes(version_bytes);

            let mut build_bytes = [0u8; 4];
            reader.read_exact(&mut build_bytes)?;
            let _build_number = u32::from_le_bytes(build_bytes);

            let mut map_offset_lo_bytes = [0u8; 4];
            reader.read_exact(&mut map_offset_lo_bytes)?;
            let map_offset_lo = u32::from_le_bytes(map_offset_lo_bytes);

            let mut map_offset_hi_bytes = [0u8; 4];
            reader.read_exact(&mut map_offset_hi_bytes)?;
            let map_offset_hi = u32::from_le_bytes(map_offset_hi_bytes);

            let mut block_size_bytes = [0u8; 4];
            reader.read_exact(&mut block_size_bytes)?;
            let block_size = u32::from_le_bytes(block_size_bytes);

            let map_offset = ((map_offset_hi as u64) << 32) | (map_offset_lo as u64);
            let bitmap_size = (file_size - footer_size).saturating_sub(map_offset);

            if bitmap_size > 0 {
                let mut bitmap = vec![0u8; bitmap_size as usize];
                reader.seek(SeekFrom::Start(map_offset))?;
                reader.read_exact(&mut bitmap)?;

                self.bitmap = Some(bitmap);
                self.bitmap_block_size = block_size;
            }
        }

        Ok(())
    }

    /// Check if the required file data is present in the partial MPQ bitmap.
    fn check_bitmap(&self, offset: u64, size: u64) -> MpqResult<()> {
        if let Some(bitmap) = &self.bitmap {
            let start_offset = offset;
            let end_offset = start_offset + size;

            let start_block = (start_offset / self.bitmap_block_size as u64) as usize;
            let end_block = end_offset.div_ceil(self.bitmap_block_size as u64) as usize;

            for i in start_block..end_block {
                let byte_index = i / 8;
                let bit_index = i % 8;
                if byte_index >= bitmap.len() || (bitmap[byte_index] & (1 << bit_index)) == 0 {
                    return Err(MpqError::DataMissing);
                }
            }
        }
        Ok(())
    }
}

/// Search for and read the MPQ header.
fn find_mpq_header<R: Read + Seek>(reader: &mut R) -> MpqResult<(u64, MpqHeader)> {
    // Get file size
    let file_size = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(0))?;

    // Search for MPQ header (usually at offset 0 or 512-byte boundaries)
    let mut search_offset: u64 = 0;
    let search_limit = file_size.min(0x200000); // Search first 2MB

    while search_offset < search_limit {
        reader.seek(SeekFrom::Start(search_offset))?;

        let mut id_bytes = [0u8; 4];
        if reader.read_exact(&mut id_bytes).is_err() {
            break;
        }

        let id = u32::from_le_bytes(id_bytes);

        if id == ID_MPQ {
            // Found MPQ header
            reader.seek(SeekFrom::Start(search_offset))?;
            let header = read_mpq_header(reader)?;
            return Ok((search_offset, header));
        }

        if id == ID_MPQ_USERDATA {
            // Found user data, MPQ header is after it
            let mut user_data_header = [0u8; 12];
            reader.read_exact(&mut user_data_header)?;

            let header_offset = u32::from_le_bytes([
                user_data_header[4],
                user_data_header[5],
                user_data_header[6],
                user_data_header[7],
            ]);

            let mpq_offset = search_offset + header_offset as u64;
            reader.seek(SeekFrom::Start(mpq_offset))?;

            let header = read_mpq_header(reader)?;
            return Ok((mpq_offset, header));
        }

        // Continue searching at 512-byte boundaries
        search_offset += 0x200;
    }

    Err(MpqError::InvalidArchive)
}

/// Read and parse the MPQ header.
fn read_mpq_header<R: Read + Seek>(reader: &mut R) -> MpqResult<MpqHeader> {
    let mut header = MpqHeader::default();
    let mut buf = [0u8; 4];

    // Read header ID
    reader.read_exact(&mut buf)?;
    header.id = u32::from_le_bytes(buf);

    if header.id != ID_MPQ {
        return Err(MpqError::InvalidHeader);
    }

    // Read header size
    reader.read_exact(&mut buf)?;
    header.header_size = u32::from_le_bytes(buf);

    // Read archive size
    reader.read_exact(&mut buf)?;
    header.archive_size = u32::from_le_bytes(buf);

    // Read format version and sector size
    let mut buf2 = [0u8; 2];
    reader.read_exact(&mut buf2)?;
    header.format_version = u16::from_le_bytes(buf2);

    reader.read_exact(&mut buf2)?;
    header.sector_size = u16::from_le_bytes(buf2);

    // Read table positions and sizes
    reader.read_exact(&mut buf)?;
    header.hash_table_pos = u32::from_le_bytes(buf);

    reader.read_exact(&mut buf)?;
    header.block_table_pos = u32::from_le_bytes(buf);

    reader.read_exact(&mut buf)?;
    header.hash_table_size = u32::from_le_bytes(buf);

    reader.read_exact(&mut buf)?;
    header.block_table_size = u32::from_le_bytes(buf);

    // Read v2+ fields if present
    if header.format_version >= MPQ_FORMAT_VERSION_2 && header.header_size >= MPQ_HEADER_SIZE_V2 {
        let mut buf8 = [0u8; 8];
        reader.read_exact(&mut buf8)?;
        header.hi_block_table_pos64 = u64::from_le_bytes(buf8);

        reader.read_exact(&mut buf2)?;
        header.hash_table_pos_hi = u16::from_le_bytes(buf2);

        reader.read_exact(&mut buf2)?;
        header.block_table_pos_hi = u16::from_le_bytes(buf2);
    }

    // Read v3+ fields if present
    if header.format_version >= MPQ_FORMAT_VERSION_3 && header.header_size >= MPQ_HEADER_SIZE_V3 {
        let mut buf8 = [0u8; 8];
        reader.read_exact(&mut buf8)?;
        header.archive_size64 = u64::from_le_bytes(buf8);

        reader.read_exact(&mut buf8)?;
        header.bet_table_pos64 = u64::from_le_bytes(buf8);

        reader.read_exact(&mut buf8)?;
        header.het_table_pos64 = u64::from_le_bytes(buf8);
    }

    // Read v4+ fields if present
    if header.format_version >= MPQ_FORMAT_VERSION_4 && header.header_size >= MPQ_HEADER_SIZE_V4 {
        let mut buf8 = [0u8; 8];

        reader.read_exact(&mut buf8)?;
        header.hash_table_size64 = u64::from_le_bytes(buf8);

        reader.read_exact(&mut buf8)?;
        header.block_table_size64 = u64::from_le_bytes(buf8);

        reader.read_exact(&mut buf8)?;
        header.hi_block_table_size64 = u64::from_le_bytes(buf8);

        reader.read_exact(&mut buf8)?;
        header.het_table_size64 = u64::from_le_bytes(buf8);

        reader.read_exact(&mut buf8)?;
        header.bet_table_size64 = u64::from_le_bytes(buf8);

        reader.read_exact(&mut buf)?;
        header.raw_chunk_size = u32::from_le_bytes(buf);

        // Read MD5 hashes
        reader.read_exact(&mut header.md5_block_table)?;
        reader.read_exact(&mut header.md5_hash_table)?;
        reader.read_exact(&mut header.md5_hi_block_table)?;
        reader.read_exact(&mut header.md5_bet_table)?;
        reader.read_exact(&mut header.md5_het_table)?;
        reader.read_exact(&mut header.md5_mpq_header)?;
    }

    Ok(header)
}
