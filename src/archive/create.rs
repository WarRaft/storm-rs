//! MPQ archive creation.
//! Ported from SFileCreateArchive.cpp
//!
//! This module provides functions for creating new MPQ archives.

use std::fs::File;
use std::io::{BufWriter, Seek, Write};
use std::path::Path;

use crate::archive::het_bet::{write_bet_table, write_het_table};
use crate::compression::auto_compress;
use crate::constants::*;
use crate::crypto::{calculate_file_key, encrypt_block, hash_string, hash_string_jenkins};
use crate::error::{MpqError, MpqResult};
use crate::types::{MpqBlock, MpqHash};

use crc32fast::Hasher as Crc32Hasher;
use md5::{Digest, Md5};
use std::time::{SystemTime, UNIX_EPOCH};
/// Entry for a file being added to the archive.
struct BuilderFileEntry {
    name: String,
    data: Vec<u8>,
    flags: u32,
    crc32: u32,
    file_time: u64,
    md5: [u8; 16],
    locale: u16,
}

/// Options for creating a new MPQ archive.
#[derive(Debug, Clone)]
pub struct MpqCreateOptions {
    /// MPQ format version (0-4)
    pub format_version: u16,
    /// Maximum number of files the archive can hold
    pub max_file_count: u32,
    /// Sector size (must be power of 2, typically 4096)
    pub sector_size: u32,
    /// Create listfile
    pub create_listfile: bool,
    /// Create attributes file
    pub create_attributes: bool,
}

impl Default for MpqCreateOptions {
    fn default() -> Self {
        Self {
            format_version: 0, // MPQ v1
            max_file_count: 1024,
            sector_size: 4096,
            create_listfile: true,
            create_attributes: false,
        }
    }
}

impl MpqCreateOptions {
    /// Create options for a v1 archive (most compatible)
    pub fn v1() -> Self {
        Self::default()
    }

    /// Create options for a v2 archive (larger files)
    pub fn v2() -> Self {
        Self {
            format_version: 1,
            ..Self::default()
        }
    }

    /// Create options for a v4 archive (with HET/BET tables)
    pub fn v4() -> Self {
        Self {
            format_version: 3,
            ..Self::default()
        }
    }

    /// Set maximum file count
    pub fn max_files(mut self, count: u32) -> Self {
        self.max_file_count = count;
        self
    }

    /// Set sector size
    pub fn sector_size(mut self, size: u32) -> Self {
        self.sector_size = size;
        self
    }

    /// Set whether to create (listfile)
    pub fn create_listfile(mut self, create: bool) -> Self {
        self.create_listfile = create;
        self
    }

    /// Set whether to create (attributes)
    pub fn create_attributes(mut self, create: bool) -> Self {
        self.create_attributes = create;
        self
    }
}

/// Get nearest power of two >= n
fn get_nearest_power_of_two(n: u32) -> u32 {
    if n == 0 {
        return 1;
    }
    let mut v = n - 1;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v + 1
}

/// Get sector size shift from sector size
fn get_sector_size_shift(sector_size: u32) -> u16 {
    let mut shift = 0u16;
    let mut size = sector_size;
    while size > 0x200 {
        size >>= 1;
        shift += 1;
    }
    shift
}

/// Header sizes for different MPQ versions
const HEADER_SIZES: [u32; 5] = [
    MPQ_HEADER_SIZE_V1,
    MPQ_HEADER_SIZE_V2,
    MPQ_HEADER_SIZE_V3,
    MPQ_HEADER_SIZE_V4,
    MPQ_HEADER_SIZE_V4,
];

/// Create a new empty MPQ archive.
pub fn create_archive<P: AsRef<Path>>(path: P, options: &MpqCreateOptions) -> MpqResult<()> {
    let path = path.as_ref();

    // Validate options
    if options.format_version > 4 {
        return Err(MpqError::InvalidParameter);
    }
    if !options.sector_size.is_power_of_two() || options.sector_size < 512 {
        return Err(MpqError::InvalidParameter);
    }

    // Calculate hash table size (must be power of 2)
    let reserved_files =
        if options.create_listfile { 1 } else { 0 } + if options.create_attributes { 1 } else { 0 };
    let hash_table_size = get_nearest_power_of_two(options.max_file_count + reserved_files);

    // Create file
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);

    // Calculate positions
    let header_size = HEADER_SIZES[options.format_version as usize];
    let hash_table_pos = header_size;
    let block_table_pos = hash_table_pos + hash_table_size * 16; // sizeof(MpqHash) = 16
    let archive_size = block_table_pos; // Initially no files

    // Write MPQ header
    write_mpq_header(
        &mut writer,
        options,
        header_size,
        hash_table_size,
        hash_table_pos,
        block_table_pos,
        0, // block_table_size (placeholder)
        archive_size,
        0, // het_table_pos
        0, // het_table_size
        0, // bet_table_pos
        0, // bet_table_size
    )?;

    // Write empty hash table (all 0xFF = free entries)
    write_empty_hash_table(&mut writer, hash_table_size)?;

    // Flush and finish
    writer.flush()?;

    Ok(())
}

/// Write MPQ header to file.
#[allow(clippy::too_many_arguments)]
pub fn write_mpq_header<W: Write + Seek>(
    writer: &mut W,
    options: &MpqCreateOptions,
    header_size: u32,
    hash_table_size: u32,
    hash_table_pos: u32,
    block_table_pos: u32,
    block_table_size: u32,
    archive_size: u32,
    het_table_pos: u64,
    het_table_size: u64,
    bet_table_pos: u64,
    bet_table_size: u64,
) -> MpqResult<()> {
    // ID "MPQ\x1A"
    writer.write_all(&ID_MPQ.to_le_bytes())?;

    // Header size
    writer.write_all(&header_size.to_le_bytes())?;

    // Archive size
    writer.write_all(&archive_size.to_le_bytes())?;

    // Format version and sector size
    writer.write_all(&options.format_version.to_le_bytes())?;
    writer.write_all(&get_sector_size_shift(options.sector_size).to_le_bytes())?;

    // Hash table position and size
    writer.write_all(&hash_table_pos.to_le_bytes())?;
    writer.write_all(&block_table_pos.to_le_bytes())?;
    writer.write_all(&hash_table_size.to_le_bytes())?;

    // Block table size
    writer.write_all(&block_table_size.to_le_bytes())?;

    // v2+ fields (extended offsets)
    if options.format_version >= 1 {
        writer.write_all(&0u64.to_le_bytes())?; // hi_block_table_pos64
        writer.write_all(&0u16.to_le_bytes())?; // hash_table_pos_hi
        writer.write_all(&0u16.to_le_bytes())?; // block_table_pos_hi
    }

    // v3+ fields
    if options.format_version >= 2 {
        writer.write_all(&(archive_size as u64).to_le_bytes())?; // archive_size64
        writer.write_all(&bet_table_pos.to_le_bytes())?; // bet_table_pos64
        writer.write_all(&het_table_pos.to_le_bytes())?; // het_table_pos64
    }

    // v4+ fields
    if options.format_version >= 3 {
        // In v4, hash_table_size and block_table_size are compressed sizes?
        // Or just extended sizes? StormLib writes them as u64.
        // For standard MPQ, they are just the sizes * 16.
        writer.write_all(&((hash_table_size * 16) as u64).to_le_bytes())?; // hash_table_size64
        writer.write_all(&((block_table_size * 16) as u64).to_le_bytes())?; // block_table_size64
        writer.write_all(&0u64.to_le_bytes())?; // hi_block_table_size64
        writer.write_all(&het_table_size.to_le_bytes())?; // het_table_size64
        writer.write_all(&bet_table_size.to_le_bytes())?; // bet_table_size64
        writer.write_all(&0u32.to_le_bytes())?; // raw_chunk_size
    }

    // Pad remaining header with zeros
    let current_pos = writer.stream_position()? as u32;
    if current_pos < header_size {
        let remaining = header_size - current_pos;
        let zeros = vec![0u8; remaining as usize];
        writer.write_all(&zeros)?;
    }

    Ok(())
}

/// Write empty hash table.
fn write_empty_hash_table<W: Write>(writer: &mut W, size: u32) -> MpqResult<()> {
    // Create empty hash entries (all 0xFF means free)
    let mut hash_table = Vec::with_capacity((size * 16) as usize);

    for _ in 0..size {
        // MpqHash: name1, name2, locale/platform, block_index
        hash_table.extend_from_slice(&HASH_ENTRY_FREE.to_le_bytes()); // name1
        hash_table.extend_from_slice(&HASH_ENTRY_FREE.to_le_bytes()); // name2
        hash_table.extend_from_slice(&0u16.to_le_bytes()); // locale
        hash_table.extend_from_slice(&0u16.to_le_bytes()); // platform
        hash_table.extend_from_slice(&HASH_ENTRY_FREE.to_le_bytes()); // block_index
    }

    // Encrypt hash table
    let key = hash_string("(hash table)", MPQ_HASH_FILE_KEY);
    encrypt_block(&mut hash_table, key);

    // Write encrypted hash table
    writer.write_all(&hash_table)?;

    Ok(())
}

pub struct MpqArchiveBuilder {
    path: String,
    options: MpqCreateOptions,
    files: Vec<BuilderFileEntry>,
}

impl MpqArchiveBuilder {
    /// Create a new archive builder.
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_string_lossy().to_string(),
            options: MpqCreateOptions::default(),
            files: Vec::new(),
        }
    }

    /// Set creation options.
    pub fn options(mut self, options: MpqCreateOptions) -> Self {
        self.options = options;
        self
    }

    /// Add a file to the archive.
    pub fn add_file<S: Into<String>>(self, name: S, data: Vec<u8>) -> Self {
        let flags = MPQ_FILE_EXISTS | MPQ_FILE_COMPRESS;
        self.add_file_with_flags(name, data, flags)
    }

    /// Add a file with specific flags.
    pub fn add_file_with_flags<S: Into<String>>(
        mut self,
        name: S,
        data: Vec<u8>,
        flags: u32,
    ) -> Self {
        // Calculate attributes
        let mut crc32_hasher = Crc32Hasher::new();
        crc32_hasher.update(&data);
        let crc32 = crc32_hasher.finalize();

        let mut md5_hasher = Md5::new();
        md5_hasher.update(&data);
        let md5_result = md5_hasher.finalize();
        let mut md5 = [0u8; 16];
        md5.copy_from_slice(&md5_result);

        // File time: current time
        let file_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            * 10_000_000
            + 116444736000000000;

        self.files.push(BuilderFileEntry {
            name: name.into(),
            data,
            flags,
            crc32,
            file_time,
            md5,
            locale: 0,
        });
        self
    }

    /// Add a file with specific flags and locale.
    pub fn add_file_localized<S: Into<String>>(
        mut self,
        name: S,
        data: Vec<u8>,
        flags: u32,
        locale: u16,
    ) -> Self {
        // Calculate attributes
        let mut crc32_hasher = Crc32Hasher::new();
        crc32_hasher.update(&data);
        let crc32 = crc32_hasher.finalize();

        let mut md5_hasher = Md5::new();
        md5_hasher.update(&data);
        let md5_result = md5_hasher.finalize();
        let mut md5 = [0u8; 16];
        md5.copy_from_slice(&md5_result);

        // File time: current time
        let file_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            * 10_000_000
            + 116444736000000000;

        self.files.push(BuilderFileEntry {
            name: name.into(),
            data,
            flags,
            crc32,
            file_time,
            md5,
            locale,
        });
        self
    }

    /// Build and write the archive.
    pub fn build(mut self) -> MpqResult<()> {
        // 1. Calculate archive parameters
        let reserved_files = if self.options.create_listfile { 1 } else { 0 }
            + if self.options.create_attributes { 1 } else { 0 };
        let total_files = self.files.len() as u32 + reserved_files;

        if self.options.max_file_count < total_files {
            self.options.max_file_count = get_nearest_power_of_two(total_files);
        }
        let hash_table_size = get_nearest_power_of_two(self.options.max_file_count);

        // 2. Create file and writer
        let file = File::create(&self.path)?;
        let mut writer = BufWriter::new(file);

        // 3. Write initial header (with placeholders)
        let header_size = HEADER_SIZES[self.options.format_version as usize];
        let mut current_pos = header_size; // We start writing files after header

        write_mpq_header(
            &mut writer,
            &self.options,
            header_size,
            hash_table_size,
            0, // hash_table_pos (placeholder)
            0, // block_table_pos (placeholder)
            0, // block_table_size (placeholder)
            0, // archive_size (placeholder)
            0, // het_table_pos (placeholder)
            0, // het_table_size (placeholder)
            0, // bet_table_pos (placeholder)
            0, // bet_table_size (placeholder)
        )?;

        // 4. Initialize tables
        let mut hash_table = vec![MpqHash::new_empty(); hash_table_size as usize];
        let mut block_table = Vec::with_capacity(total_files as usize);

        // Keep track of file names for HET/BET generation
        let mut file_names: Vec<String> = Vec::with_capacity(total_files as usize);

        // 5. Process and write user files
        // We need to keep the file list for (listfile) generation, so we iterate instead of drain
        for entry in &self.files {
            Self::add_file_internal(
                &mut writer,
                &entry.name,
                &entry.data,
                entry.flags,
                entry.locale,
                &mut current_pos,
                &mut hash_table,
                &mut block_table,
                hash_table_size,
            )?;
            file_names.push(entry.name.clone());
        }

        // 6. Generate and write (listfile)
        let mut listfile_attributes = None;
        if self.options.create_listfile {
            let mut listfile_content = Vec::new();
            for entry in &self.files {
                listfile_content.extend_from_slice(entry.name.as_bytes());
                listfile_content.push(b'\r');
                listfile_content.push(b'\n');
            }

            // Calculate attributes for (listfile)
            let mut crc32_hasher = Crc32Hasher::new();
            crc32_hasher.update(&listfile_content);
            let crc32 = crc32_hasher.finalize();

            let mut md5_hasher = Md5::new();
            md5_hasher.update(&listfile_content);
            let md5_result = md5_hasher.finalize();
            let mut md5 = [0u8; 16];
            md5.copy_from_slice(&md5_result);

            let file_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                * 10_000_000
                + 116444736000000000;

            listfile_attributes = Some((crc32, file_time, md5));

            Self::add_file_internal(
                &mut writer,
                "(listfile)",
                &listfile_content,
                MPQ_FILE_COMPRESS | MPQ_FILE_EXISTS,
                0, // Neutral locale
                &mut current_pos,
                &mut hash_table,
                &mut block_table,
                hash_table_size,
            )?;
            file_names.push("(listfile)".to_string());
        }

        // 7. Generate and write (attributes)
        if self.options.create_attributes {
            let mut attributes_content = Vec::new();
            let version = 100u32; // MPQ_ATTRIBUTES_V1
            let flags = MPQ_ATTRIBUTE_CRC32 | MPQ_ATTRIBUTE_FILETIME | MPQ_ATTRIBUTE_MD5;

            attributes_content.extend_from_slice(&version.to_le_bytes());
            attributes_content.extend_from_slice(&flags.to_le_bytes());

            // We need attributes for: User Files + (listfile) + (attributes)
            // User files
            for entry in &self.files {
                attributes_content.extend_from_slice(&entry.crc32.to_le_bytes());
            }
            // (listfile)
            if let Some((crc, _, _)) = listfile_attributes {
                attributes_content.extend_from_slice(&crc.to_le_bytes());
            }
            // (attributes) - placeholder 0
            attributes_content.extend_from_slice(&0u32.to_le_bytes());

            // FileTimes
            for entry in &self.files {
                attributes_content.extend_from_slice(&entry.file_time.to_le_bytes());
            }
            if let Some((_, time, _)) = listfile_attributes {
                attributes_content.extend_from_slice(&time.to_le_bytes());
            }
            attributes_content.extend_from_slice(&0u64.to_le_bytes());

            // MD5s
            for entry in &self.files {
                attributes_content.extend_from_slice(&entry.md5);
            }
            if let Some((_, _, md5)) = listfile_attributes {
                attributes_content.extend_from_slice(&md5);
            }
            attributes_content.extend_from_slice(&[0u8; 16]);

            Self::add_file_internal(
                &mut writer,
                "(attributes)",
                &attributes_content,
                MPQ_FILE_COMPRESS | MPQ_FILE_EXISTS,
                0, // Neutral locale
                &mut current_pos,
                &mut hash_table,
                &mut block_table,
                hash_table_size,
            )?;
            file_names.push("(attributes)".to_string());
        }

        // 7. Write Hash Table
        let hash_table_pos = current_pos;
        write_hash_table(&mut writer, &mut hash_table, hash_table_size)?;
        current_pos += hash_table_size * 16;

        // 8. Write Block Table
        let block_table_pos = current_pos;
        write_block_table(&mut writer, &mut block_table)?;
        current_pos += (block_table.len() as u32) * 16;

        // 9. Write HET/BET Tables (v4 only)
        let mut het_table_pos = 0u64;
        let mut het_table_size = 0u64;
        let mut bet_table_pos = 0u64;
        let mut bet_table_size = 0u64;

        if self.options.format_version >= 3 {
            // Prepare files list for HET table
            // We need to map filenames to block indexes.
            // Since we added files sequentially to block_table, we can just zip them.
            // Note: block_table order matches file_names order.
            let mut het_files: Vec<(&str, u32)> = Vec::new();
            for (i, name) in file_names.iter().enumerate() {
                het_files.push((name, i as u32));
            }

            let het_data = write_het_table(&het_files, hash_table_size)?;

            // Prepare BET hashes
            let mut bet_hashes = Vec::new();
            for name in &file_names {
                bet_hashes.push(hash_string_jenkins(name));
            }

            let bet_data = write_bet_table(&block_table, &bet_hashes)?;

            // Write HET table
            het_table_pos = current_pos as u64;
            het_table_size = het_data.len() as u64;
            writer.write_all(&het_data)?;
            current_pos += het_data.len() as u32;

            // Write BET table
            bet_table_pos = current_pos as u64;
            bet_table_size = bet_data.len() as u64;
            writer.write_all(&bet_data)?;
            current_pos += bet_data.len() as u32;
        }

        // 10. Finalize Header
        let archive_size = current_pos;
        writer.seek(std::io::SeekFrom::Start(0))?;
        write_mpq_header(
            &mut writer,
            &self.options,
            header_size,
            hash_table_size,
            hash_table_pos,
            block_table_pos,
            block_table.len() as u32,
            archive_size,
            het_table_pos,
            het_table_size,
            bet_table_pos,
            bet_table_size,
        )?;

        writer.flush()?;
        Ok(())
    }

    // Helper to add a single file
    #[allow(clippy::too_many_arguments)]
    fn add_file_internal<W: Write + Seek>(
        writer: &mut W,
        name: &str,
        data: &[u8],
        flags: u32,
        locale: u16,
        current_pos: &mut u32,
        hash_table: &mut [MpqHash],
        block_table: &mut Vec<MpqBlock>,
        hash_table_size: u32,
    ) -> MpqResult<()> {
        // Compress
        let (compressed_data, compression_flags) = if (flags & MPQ_FILE_COMPRESS) != 0 {
            auto_compress(data)?
        } else {
            (data.to_vec(), 0)
        };

        // If compression failed or wasn't worth it, unset the compress flag
        let mut final_flags = flags;
        if compression_flags == 0 {
            final_flags &= !MPQ_FILE_COMPRESS;
        } else {
            final_flags |= compression_flags;
        }

        // Encrypt
        let mut final_data = compressed_data;
        if (flags & MPQ_FILE_ENCRYPTED) != 0 {
            // Calculate key
            let key = calculate_file_key(name, *current_pos as u64, data.len() as u32, flags);
            encrypt_block(&mut final_data, key);
        }

        // Write data
        writer.write_all(&final_data)?;

        // Update tables
        let file_pos = *current_pos;
        let compressed_size = final_data.len() as u32;
        let file_size = data.len() as u32;

        // Add block entry
        let block_index = block_table.len() as u32;
        block_table.push(MpqBlock {
            file_pos,
            compressed_size,
            file_size,
            flags: final_flags,
        });

        // Add hash entry
        let hash_index = hash_string(name, MPQ_HASH_TABLE_INDEX) & (hash_table_size - 1);
        // Handle collisions (linear probing)
        let mut index = hash_index;
        loop {
            if hash_table[index as usize].block_index == HASH_ENTRY_FREE {
                break;
            }
            index = (index + 1) & (hash_table_size - 1);
            if index == hash_index {
                return Err(MpqError::DiskFull); // Hash table full
            }
        }

        let hash_a = hash_string(name, MPQ_HASH_NAME_A);
        let hash_b = hash_string(name, MPQ_HASH_NAME_B);

        hash_table[index as usize] = MpqHash {
            hash_check_a: hash_a,
            hash_check_b: hash_b,
            locale,
            platform: 0,
            flags: 0,
            block_index,
        };

        *current_pos += compressed_size;
        Ok(())
    }
}

/// Write hash table to file.
pub fn write_hash_table<W: Write>(
    writer: &mut W,
    hash_table: &mut [MpqHash],
    size: u32,
) -> MpqResult<()> {
    let mut data = Vec::with_capacity((size * 16) as usize);

    for entry in hash_table.iter() {
        data.extend_from_slice(&entry.hash_check_a.to_le_bytes());
        data.extend_from_slice(&entry.hash_check_b.to_le_bytes());
        data.extend_from_slice(&entry.locale.to_le_bytes());
        data.extend_from_slice(&entry.platform.to_le_bytes());
        data.extend_from_slice(&entry.flags.to_le_bytes());
        data.extend_from_slice(&entry.block_index.to_le_bytes());
    }

    // Encrypt hash table
    let key = hash_string("(hash table)", MPQ_HASH_FILE_KEY);
    encrypt_block(&mut data, key);

    writer.write_all(&data)?;
    Ok(())
}

/// Write block table to file.
pub fn write_block_table<W: Write>(writer: &mut W, block_table: &mut [MpqBlock]) -> MpqResult<()> {
    let mut data = Vec::with_capacity(block_table.len() * 16);

    for entry in block_table.iter() {
        data.extend_from_slice(&entry.file_pos.to_le_bytes());
        data.extend_from_slice(&entry.compressed_size.to_le_bytes());
        data.extend_from_slice(&entry.file_size.to_le_bytes());
        data.extend_from_slice(&entry.flags.to_le_bytes());
    }

    // Encrypt block table
    let key = hash_string("(block table)", MPQ_HASH_FILE_KEY);
    encrypt_block(&mut data, key);

    writer.write_all(&data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_nearest_power_of_two() {
        assert_eq!(get_nearest_power_of_two(0), 1);
        assert_eq!(get_nearest_power_of_two(1), 1);
        assert_eq!(get_nearest_power_of_two(2), 2);
        assert_eq!(get_nearest_power_of_two(3), 4);
        assert_eq!(get_nearest_power_of_two(5), 8);
        assert_eq!(get_nearest_power_of_two(1000), 1024);
    }

    #[test]
    fn test_sector_size_shift() {
        assert_eq!(get_sector_size_shift(512), 0);
        assert_eq!(get_sector_size_shift(1024), 1);
        assert_eq!(get_sector_size_shift(4096), 3);
    }
}
