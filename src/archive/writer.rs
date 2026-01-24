//! File writing to MPQ archives.
//! Simplified version based on SFileAddFile.cpp
//!
//! This module provides functions for adding files to MPQ archives.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use log::debug;

use crate::archive::MpqArchive;
use crate::compression::compress;
use crate::constants::*;
use crate::crypto::{encrypt_block, hash_string};
use crate::error::{MpqError, MpqResult};
use crate::types::*;
use crate::verify::{calculate_crc32, calculate_md5};
use md5::{Digest, Md5};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, pkcs1::DecodeRsaPrivateKey};

const BLIZZARD_WEAK_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
    MIIBOQIBAAJBAJJidwS/uILMBSO5DLGsBFknIXWWjQJe2kfdfEk3G/j66w4KkhZ1\n\
    V61Rt4zLaMVCYpDun7FLwRjkMDSepO1q2DcCAwEAAQJANtiztVDMJh2hE1hjPDKy\n\
    UmEJ9U/aN3gomuKOjbQbQ/bWWcM/WfhSVHmPqtqh/bQI2UXFr0rnXngeteZHLr/b\n\
    8QIhAMuWriSKGMACw18/rVVfUrThs915odKBH1Alr3vMVVzZAiEAuBHPSQkgwcb6\n\
    L4MWaiKuOzq08mSyNqPeN8oSy18q848CIHeMn+3s+eOmu7su1UYQl6yH7OrdBd1q\n\
    3UxfFNEJiAbhAiAqxdCyOxHGlbM7aS3DOg3cq5ayoN2cvtV7h1R4t8OmVwIgF+5z\n\
    /6vkzBUsZhd8Nwyis+MeQYH0rpFpMKdTlqmPF2Q=\n\
    -----END PRIVATE KEY-----";

/// Options for adding a file to an archive.
#[derive(Debug, Clone)]
pub struct AddFileOptions {
    /// Compress the file
    pub compress: bool,
    /// Compression type (default: ZLIB)
    pub compression: u8,
    /// Encrypt the file
    pub encrypt: bool,
    /// File locale
    pub locale: u16,
    /// Store as single unit (no sectors)
    pub single_unit: bool,
    /// Compression for subsequent sectors (if different from first)
    pub compression_next: Option<u8>,
}

impl Default for AddFileOptions {
    fn default() -> Self {
        Self {
            compress: true,
            compression: MPQ_COMPRESSION_ZLIB,
            encrypt: false,
            locale: 0,
            single_unit: false,
            compression_next: None,
        }
    }
}

/// Metadata for a file (for (attributes) file).
#[derive(Debug, Clone)]
struct FileMetadata {
    crc32: u32,
    md5: [u8; 16],
    file_time: u64,
}

/// Writable MPQ archive.
pub struct MpqArchiveWriter {
    #[allow(dead_code)]
    path: String,
    file: BufWriter<File>,
    header: MpqHeader,
    hash_table: Vec<MpqHash>,
    block_table: Vec<MpqBlock>,
    #[allow(dead_code)]
    sector_size: u32,
    mpq_offset: u64,
    /// Current position for next file data (relative to MPQ start)
    data_pos: u64,
    /// List of files added in this session
    new_files: Vec<String>,
    /// List of files deleted in this session
    deleted_files: Vec<String>,
    /// Metadata for new files
    file_metadata: HashMap<String, FileMetadata>,
    /// Cached content of (listfile)
    listfile_content: Vec<u8>,
    /// Cached content of (attributes)
    attributes_content: Vec<u8>,
    /// Whether to sign the archive with a weak signature on close
    sign_weak: bool,
    /// Number of blocks when archive was opened
    initial_block_count: usize,
    /// Metadata for new blocks (by block index)
    new_blocks: HashMap<u32, FileMetadata>,
}

impl MpqArchiveWriter {
    /// Open an existing archive for writing.
    pub fn open<P: AsRef<Path>>(path: P) -> MpqResult<Self> {
        let path_ref = path.as_ref();
        let path_str = path_ref.to_string_lossy().to_string();

        // First, read the archive to get metadata
        let archive = MpqArchive::open(path_ref)?;

        // Calculate file data position:
        // hash_table and block_table follow the header
        // We reserve space for max block entries = hash_table_size
        let hash_table_end =
            archive.header.hash_table_pos as u64 + (archive.header.hash_table_size as u64 * 16);

        let max_block_entries = archive.header.hash_table_size;
        let block_table_reserved_end =
            archive.header.block_table_pos as u64 + (max_block_entries as u64 * 16);

        // File data starts after both tables
        let data_pos = hash_table_end.max(block_table_reserved_end);

        debug!(
            "MpqArchiveWriter::open: hash_table_pos={}, block_table_pos={}, data_pos={}",
            archive.header.hash_table_pos, archive.header.block_table_pos, data_pos
        );

        // Cache (listfile) content
        let listfile_content = match archive.read_file("(listfile)") {
            Ok(data) => data,
            Err(_) => Vec::new(),
        };

        // Cache (attributes) content
        let attributes_content = match archive.read_file("(attributes)") {
            Ok(data) => data,
            Err(_) => Vec::new(),
        };

        let initial_block_count = archive.block_table.len();

        // Now open for writing
        let file = OpenOptions::new().read(true).write(true).open(path_ref)?;

        Ok(Self {
            path: path_str,
            file: BufWriter::new(file),
            header: archive.header,
            hash_table: archive.hash_table,
            block_table: archive.block_table,
            sector_size: archive.sector_size,
            mpq_offset: archive.mpq_offset,
            data_pos,
            new_files: Vec::new(),
            deleted_files: Vec::new(),
            file_metadata: HashMap::new(),
            listfile_content,
            attributes_content,
            sign_weak: false,
            initial_block_count,
            new_blocks: HashMap::new(),
        })
    }

    /// Add a file to the archive.
    pub fn add_file(&mut self, name: &str, data: &[u8], options: &AddFileOptions) -> MpqResult<()> {
        self.add_file_raw(name, data, options)?;
        self.new_files.push(name.to_string());
        Ok(())
    }

    /// Add a WAV file with specific compression settings based on quality.
    /// Quality: 0 = High (Lossless), 1 = Medium, 2 = Low.
    pub fn add_wave(&mut self, name: &str, data: &[u8], quality: u8) -> MpqResult<()> {
        let (compression, compression_next) = match quality {
            0 => (MPQ_COMPRESSION_PKWARE, MPQ_COMPRESSION_PKWARE),
            1 | 2 => (
                MPQ_COMPRESSION_PKWARE,
                MPQ_COMPRESSION_ADPCM_STEREO | MPQ_COMPRESSION_HUFFMANN,
            ),
            _ => return Err(MpqError::InvalidParameter),
        };

        let options = AddFileOptions {
            compress: true,
            compression,
            compression_next: Some(compression_next),
            ..Default::default()
        };

        self.add_file(name, data, &options)
    }

    /// Remove a file from the archive.
    /// This marks the hash entry as deleted and removes it from the (listfile).
    /// It does NOT reclaim the space in the archive (requires compaction).
    pub fn remove_file(&mut self, name: &str) -> MpqResult<()> {
        let hash_a = hash_string(name, MPQ_HASH_NAME_A);
        let hash_b = hash_string(name, MPQ_HASH_NAME_B);
        let start_index = hash_string(name, MPQ_HASH_TABLE_INDEX) as usize % self.hash_table.len();

        let mut index = start_index;
        loop {
            let entry = &mut self.hash_table[index];

            if entry.hash_check_a == hash_a
                && entry.hash_check_b == hash_b
                && entry.block_index != HASH_ENTRY_DELETED
            {
                // Found the file
                entry.block_index = HASH_ENTRY_DELETED;
                entry.hash_check_a = 0xFFFFFFFF;
                entry.hash_check_b = 0xFFFFFFFF;
                entry.locale = 0xFFFF;
                entry.platform = 0xFF;
                entry.flags = 0xFF;

                self.deleted_files.push(name.to_string());

                // Also remove from new_files if it was just added
                if let Some(pos) = self.new_files.iter().position(|x| x == name) {
                    self.new_files.remove(pos);
                }

                return Ok(());
            }

            if entry.block_index == HASH_ENTRY_FREE {
                return Err(MpqError::FileNotFound);
            }

            index = (index + 1) % self.hash_table.len();
            if index == start_index {
                return Err(MpqError::FileNotFound);
            }
        }
    }

    /// Rename a file in the archive.
    pub fn rename_file(&mut self, old_name: &str, new_name: &str) -> MpqResult<()> {
        // 1. Find old entry
        let old_hash_a = hash_string(old_name, MPQ_HASH_NAME_A);
        let old_hash_b = hash_string(old_name, MPQ_HASH_NAME_B);
        let old_start_index =
            hash_string(old_name, MPQ_HASH_TABLE_INDEX) as usize % self.hash_table.len();

        let mut old_index = old_start_index;
        let mut found_index = None;

        loop {
            let entry = &self.hash_table[old_index];
            if entry.hash_check_a == old_hash_a
                && entry.hash_check_b == old_hash_b
                && entry.block_index != HASH_ENTRY_DELETED
            {
                found_index = Some(old_index);
                break;
            }
            if entry.block_index == HASH_ENTRY_FREE {
                break;
            }
            old_index = (old_index + 1) % self.hash_table.len();
            if old_index == old_start_index {
                break;
            }
        }

        let old_entry_index = found_index.ok_or(MpqError::FileNotFound)?;
        let old_entry = self.hash_table[old_entry_index];

        // Check if file is encrypted
        let block_index = old_entry.block_index as usize;
        if block_index >= self.block_table.len() {
            return Err(MpqError::InvalidParameter);
        }
        let block = &self.block_table[block_index];

        if (block.flags & MPQ_FILE_ENCRYPTED) != 0 {
            // Re-encryption required
            use crate::crypto::{calculate_file_key, decrypt_block, encrypt_block};
            use std::io::{Read, Seek, SeekFrom, Write};

            let old_key = calculate_file_key(
                old_name,
                block.file_pos as u64,
                block.file_size,
                block.flags,
            );
            let new_key = calculate_file_key(
                new_name,
                block.file_pos as u64,
                block.file_size,
                block.flags,
            );

            if old_key != new_key {
                // Read the raw data
                let mut data = vec![0u8; block.compressed_size as usize];

                // Flush buffer before accessing underlying file
                self.file.flush()?;
                let file = self.file.get_mut();

                file.seek(SeekFrom::Start(block.file_pos as u64))?;
                file.read_exact(&mut data)?;

                let is_compressed = (block.flags & (MPQ_FILE_COMPRESS | MPQ_FILE_IMPLODE)) != 0;

                if (block.flags & MPQ_FILE_SINGLE_UNIT) != 0 || !is_compressed {
                    // Single unit (or uncompressed): simple decrypt/encrypt
                    decrypt_block(&mut data, old_key);
                    encrypt_block(&mut data, new_key);
                } else {
                    // Sectored: need to handle sector table
                    // Sector table is at the beginning of data
                    let sector_size = self.sector_size as usize;
                    let num_sectors = (block.file_size as usize).div_ceil(sector_size);
                    let table_size = (num_sectors + 1) * 4;

                    if data.len() < table_size {
                        return Err(MpqError::InvalidParameter);
                    }

                    // Decrypt sector table
                    let mut sector_offsets_bytes = data[0..table_size].to_vec();
                    decrypt_block(&mut sector_offsets_bytes, old_key.wrapping_sub(1));

                    // Parse sector offsets
                    let mut sector_offsets = Vec::with_capacity(num_sectors + 1);
                    for i in 0..=num_sectors {
                        let offset = u32::from_le_bytes([
                            sector_offsets_bytes[i * 4],
                            sector_offsets_bytes[i * 4 + 1],
                            sector_offsets_bytes[i * 4 + 2],
                            sector_offsets_bytes[i * 4 + 3],
                        ]);
                        sector_offsets.push(offset);
                    }

                    // Re-encrypt sectors
                    for i in 0..num_sectors {
                        let start = sector_offsets[i] as usize;
                        let end = sector_offsets[i + 1] as usize;

                        if start > data.len() || end > data.len() || start > end {
                            return Err(MpqError::InvalidParameter);
                        }

                        let sector_data = &mut data[start..end];

                        // Decrypt with old key
                        decrypt_block(sector_data, old_key.wrapping_add(i as u32));

                        // Encrypt with new key
                        encrypt_block(sector_data, new_key.wrapping_add(i as u32));
                    }

                    // Re-encrypt sector table
                    encrypt_block(&mut sector_offsets_bytes, new_key.wrapping_sub(1));
                    data[0..table_size].copy_from_slice(&sector_offsets_bytes);
                }

                // Write back
                file.seek(SeekFrom::Start(block.file_pos as u64))?;
                file.write_all(&data)?;
            }
        }

        // 2. Find new free entry
        let new_index = self.find_free_hash_entry(new_name)?;

        // 3. Copy data to new entry
        self.hash_table[new_index].hash_check_a = hash_string(new_name, MPQ_HASH_NAME_A);
        self.hash_table[new_index].hash_check_b = hash_string(new_name, MPQ_HASH_NAME_B);
        self.hash_table[new_index].locale = old_entry.locale;
        self.hash_table[new_index].platform = old_entry.platform;
        self.hash_table[new_index].block_index = old_entry.block_index;

        // 4. Mark old entry as deleted
        self.hash_table[old_entry_index].block_index = HASH_ENTRY_DELETED;
        self.hash_table[old_entry_index].hash_check_a = 0xFFFFFFFF;
        self.hash_table[old_entry_index].hash_check_b = 0xFFFFFFFF;
        self.hash_table[old_entry_index].locale = 0xFFFF;
        self.hash_table[old_entry_index].platform = 0xFF;
        self.hash_table[old_entry_index].flags = 0xFF;

        // 5. Update lists
        self.deleted_files.push(old_name.to_string());
        self.new_files.push(new_name.to_string());

        // Update metadata map if exists
        if let Some(metadata) = self.file_metadata.remove(old_name) {
            self.file_metadata.insert(new_name.to_string(), metadata);
        }

        // If we are renaming a file we just added, we should remove it from new_files?
        // Yes, but we just added new_name to new_files.
        // We should remove old_name from new_files if it's there.
        if let Some(pos) = self.new_files.iter().position(|x| x == old_name) {
            self.new_files.remove(pos);
        }

        Ok(())
    }

    /// Set the locale of a file.
    pub fn set_file_locale(&mut self, name: &str, new_locale: u16) -> MpqResult<()> {
        let hash_a = hash_string(name, MPQ_HASH_NAME_A);
        let hash_b = hash_string(name, MPQ_HASH_NAME_B);
        let start_index = hash_string(name, MPQ_HASH_TABLE_INDEX) as usize % self.hash_table.len();

        let mut index = start_index;
        let mut found_index = None;

        // 1. Find the file entry
        loop {
            let entry = &self.hash_table[index];
            if entry.hash_check_a == hash_a
                && entry.hash_check_b == hash_b
                && entry.block_index != HASH_ENTRY_DELETED
                && entry.block_index != HASH_ENTRY_FREE
            {
                found_index = Some(index);
                break;
            }

            if entry.block_index == HASH_ENTRY_FREE {
                break;
            }

            index = (index + 1) % self.hash_table.len();
            if index == start_index {
                break;
            }
        }

        let entry_index = found_index.ok_or(MpqError::FileNotFound)?;

        // 2. Check for collision with new locale
        let mut collision_index = start_index;
        loop {
            let entry = &self.hash_table[collision_index];

            if collision_index != entry_index
                && entry.hash_check_a == hash_a
                && entry.hash_check_b == hash_b
                && entry.block_index != HASH_ENTRY_DELETED
                && entry.block_index != HASH_ENTRY_FREE
                && entry.locale == new_locale
            {
                return Err(MpqError::AlreadyExists);
            }

            if entry.block_index == HASH_ENTRY_FREE {
                break;
            }

            collision_index = (collision_index + 1) % self.hash_table.len();
            if collision_index == start_index {
                break;
            }
        }

        // 3. Update locale
        self.hash_table[entry_index].locale = new_locale;

        Ok(())
    }

    /// Add a file to the archive (internal version, doesn't track new_files).
    fn add_file_raw(&mut self, name: &str, data: &[u8], options: &AddFileOptions) -> MpqResult<()> {
        // Find free hash entry
        let hash_index = self.find_free_hash_entry(name)?;

        // Calculate attributes for the new file (on uncompressed data)
        let crc32 = calculate_crc32(data);
        let md5 = calculate_md5(data);
        let file_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            * 10_000_000
            + 116444736000000000; // Convert to Windows FILETIME (approx)

        self.file_metadata.insert(
            name.to_string(),
            FileMetadata {
                crc32,
                md5,
                file_time,
            },
        );

        // Calculate file position (relative to MPQ start)
        let file_pos = self.data_pos as u32;

        // Prepare file data
        let (file_data, flags) = self.prepare_file_data(name, data, file_pos, options)?;

        debug!(
            "add_file_raw '{}': pos=0x{:X}, size={}, compressed={}, flags=0x{:08X}",
            name,
            file_pos,
            data.len(),
            file_data.len(),
            flags
        );

        // Write file data to archive
        let write_pos = self.mpq_offset + self.data_pos;
        self.file.seek(SeekFrom::Start(write_pos))?;
        self.file.write_all(&file_data)?;

        // Create block entry
        let block = MpqBlock {
            file_pos,
            compressed_size: file_data.len() as u32,
            file_size: data.len() as u32,
            flags,
        };

        // Add to block table
        let block_index = self.block_table.len() as u32;
        self.block_table.push(block);

        // Track metadata for this block
        if let Some(metadata) = self.file_metadata.get(name) {
            self.new_blocks.insert(block_index, metadata.clone());
        }

        // Update hash entry
        self.hash_table[hash_index].hash_check_a = hash_string(name, MPQ_HASH_NAME_A);
        self.hash_table[hash_index].hash_check_b = hash_string(name, MPQ_HASH_NAME_B);
        self.hash_table[hash_index].locale = options.locale;
        self.hash_table[hash_index].platform = 0;
        self.hash_table[hash_index].block_index = block_index;

        // Update data position for next file
        self.data_pos += file_data.len() as u64;

        Ok(())
    }

    /// Find a free hash entry for the given filename.
    fn find_free_hash_entry(&self, name: &str) -> MpqResult<usize> {
        let hash_a = hash_string(name, MPQ_HASH_NAME_A);
        let hash_b = hash_string(name, MPQ_HASH_NAME_B);
        let start_index = hash_string(name, MPQ_HASH_TABLE_INDEX) as usize % self.hash_table.len();

        let mut index = start_index;
        loop {
            let entry = &self.hash_table[index];

            // Check if this is the same file
            if entry.hash_check_a == hash_a && entry.hash_check_b == hash_b {
                // Found existing entry, reuse it (overwrite)
                return Ok(index);
            }

            // Found free entry
            if entry.block_index == HASH_ENTRY_FREE {
                return Ok(index);
            }

            index = (index + 1) % self.hash_table.len();
            if index == start_index {
                return Err(MpqError::BufferTooSmall);
            }
        }
    }

    /// Prepare file data (compress and encrypt).
    fn prepare_file_data(
        &self,
        name: &str,
        data: &[u8],
        file_pos: u32,
        options: &AddFileOptions,
    ) -> MpqResult<(Vec<u8>, u32)> {
        let mut flags = MPQ_FILE_EXISTS;

        // Determine if we should use single unit
        // If not compressed, usually single unit (unless we want to support uncompressed sectored, which is rare)
        // If compressed, usually sectored (unless single_unit is true)
        let use_single_unit = options.single_unit || !options.compress;

        if use_single_unit {
            flags |= MPQ_FILE_SINGLE_UNIT;
        }

        if options.encrypt {
            flags |= MPQ_FILE_ENCRYPTED;
        }

        if options.compress && !data.is_empty() {
            flags |= MPQ_FILE_COMPRESS;
        }

        // Calculate file key if encrypted
        let file_key = if options.encrypt {
            use crate::crypto::calculate_file_key;
            calculate_file_key(name, file_pos as u64, data.len() as u32, flags)
        } else {
            0
        };

        if use_single_unit {
            // Single Unit: Compress whole file, then encrypt whole file
            let mut file_data = if options.compress && !data.is_empty() {
                let compressed = compress(data, options.compression)?;
                // Only use compression if it actually saves space
                if compressed.len() < data.len() {
                    compressed
                } else {
                    flags &= !MPQ_FILE_COMPRESS; // Clear compress flag if not effective
                    data.to_vec()
                }
            } else {
                data.to_vec()
            };

            if options.encrypt {
                encrypt_block(&mut file_data, file_key);
            }

            Ok((file_data, flags))
        } else {
            // Sectored: Split into sectors, compress each, encrypt each
            let sector_size = self.sector_size as usize;
            let num_sectors = data.len().div_ceil(sector_size);

            // Sector offset table (num_sectors + 1 entries)
            let mut sector_offsets = vec![0u32; num_sectors + 1];
            let mut dest_data = Vec::new();

            // Reserve space for sector offset table at the beginning
            // Size = (num_sectors + 1) * 4
            let table_size = (num_sectors + 1) * 4;
            dest_data.resize(table_size, 0);

            let mut current_offset = table_size as u32;

            for i in 0..num_sectors {
                sector_offsets[i] = current_offset;

                let start = i * sector_size;
                let end = std::cmp::min(start + sector_size, data.len());
                let sector_raw = &data[start..end];

                // Compress sector
                let mut sector_data = if options.compress {
                    let compression_to_use = if i == 0 {
                        options.compression
                    } else {
                        options.compression_next.unwrap_or(options.compression)
                    };

                    let compressed = compress(sector_raw, compression_to_use)?;
                    // If compressed size >= uncompressed size, store uncompressed
                    // But we still need to handle the "compression mask" byte if we use `compress` function?
                    // `compress` function prepends the mask.
                    // If we store uncompressed, we just store raw data?
                    // StormLib: If compressed size < uncompressed size, store compressed.
                    // Else store uncompressed.

                    if compressed.len() < sector_raw.len() {
                        compressed
                    } else {
                        sector_raw.to_vec()
                    }
                } else {
                    sector_raw.to_vec()
                };

                // Encrypt sector
                if options.encrypt {
                    let sector_key = file_key.wrapping_add(i as u32);
                    encrypt_block(&mut sector_data, sector_key);
                }

                dest_data.extend_from_slice(&sector_data);
                current_offset += sector_data.len() as u32;
            }

            sector_offsets[num_sectors] = current_offset;

            // Write sector offsets to the beginning of dest_data
            let mut offset_bytes = Vec::with_capacity(table_size);
            for offset in &sector_offsets {
                // StormLib expects sector offsets stored in Little Endian (on LE platforms like Windows).
                // BSWAP_ARRAY32_UNSIGNED is a no-op on LE platforms.
                offset_bytes.extend_from_slice(&offset.to_le_bytes());
            }

            // Encrypt sector offset table
            if options.encrypt {
                encrypt_block(&mut offset_bytes, file_key.wrapping_sub(1));
            }

            // Copy back to dest_data
            dest_data[0..table_size].copy_from_slice(&offset_bytes);

            Ok((dest_data, flags))
        }
    }

    /// Request to sign the archive with a weak signature on close.
    pub fn sign_archive(&mut self) {
        self.sign_weak = true;
    }

    /// Change the maximum number of files (hash table size).
    /// This rebuilds the hash table.
    pub fn set_max_file_count(&mut self, max_file_count: u32) -> MpqResult<()> {
        // 1. Calculate new size (power of 2)
        let mut new_size = 4;
        while new_size < max_file_count {
            new_size *= 2;
        }

        if new_size == self.hash_table.len() as u32 {
            return Ok(());
        }

        // 2. Collect all known names
        let mut known_names = Vec::new();

        // From listfile
        let listfile_str = String::from_utf8_lossy(&self.listfile_content);
        for line in listfile_str.lines() {
            let name = line.trim();
            if !name.is_empty() {
                known_names.push(name.to_string());
            }
        }

        // From new_files
        for name in &self.new_files {
            known_names.push(name.clone());
        }

        // 3. Create new table
        let mut new_hash_table = vec![MpqHash::new_empty(); new_size as usize];

        // 4. Re-hash
        for entry in &self.hash_table {
            if entry.block_index != HASH_ENTRY_FREE && entry.block_index != HASH_ENTRY_DELETED {
                // Find name
                let mut found_name = None;
                for name in &known_names {
                    let ha = hash_string(name, MPQ_HASH_NAME_A);
                    let hb = hash_string(name, MPQ_HASH_NAME_B);
                    if ha == entry.hash_check_a && hb == entry.hash_check_b {
                        found_name = Some(name);
                        break;
                    }
                }

                let name = found_name
                    .ok_or(MpqError::Mpq(crate::error::MpqErrorKind::UnknownFileNames))?;

                // Insert into new table
                let start_index =
                    hash_string(name, MPQ_HASH_TABLE_INDEX) as usize % new_size as usize;
                let mut index = start_index;
                loop {
                    if new_hash_table[index].block_index == HASH_ENTRY_FREE {
                        new_hash_table[index] = *entry;
                        break;
                    }
                    index = (index + 1) % new_size as usize;
                    if index == start_index {
                        return Err(MpqError::BufferTooSmall);
                    }
                }
            }
        }

        // 5. Update
        self.hash_table = new_hash_table;
        self.header.hash_table_size = new_size;

        Ok(())
    }

    /// Finalize and close the archive.
    pub fn finish(mut self) -> MpqResult<()> {
        // Update (listfile) and (attributes) if we added new files or deleted files
        if !self.new_files.is_empty() || !self.deleted_files.is_empty() {
            self.update_internal_files()?;

            // Invalidate (signature) file if it exists, as the archive content has changed
            // But ONLY if we didn't just add a new signature!
            let added_signature = self
                .new_files
                .iter()
                .any(|f| f.eq_ignore_ascii_case("(signature)"));

            if !added_signature {
                let signature_hash_a = hash_string("(signature)", MPQ_HASH_NAME_A);
                let signature_hash_b = hash_string("(signature)", MPQ_HASH_NAME_B);

                for hash in &mut self.hash_table {
                    if hash.hash_check_a == signature_hash_a
                        && hash.hash_check_b == signature_hash_b
                        && hash.block_index != HASH_ENTRY_DELETED
                        && hash.block_index != HASH_ENTRY_FREE
                    {
                        debug!("Invalidating (signature) file due to modification");
                        hash.block_index = HASH_ENTRY_DELETED;
                        hash.hash_check_a = 0xFFFFFFFF;
                        hash.hash_check_b = 0xFFFFFFFF;
                        hash.locale = 0xFFFF;
                        hash.platform = 0xFF;
                        hash.flags = 0xFF;
                        break;
                    }
                }
            }
        }

        let block_table_size = self.block_table.len() as u32;

        debug!(
            "finish: writing {} hash entries, {} block entries",
            self.hash_table.len(),
            block_table_size
        );

        // Move tables to the end of the archive to avoid overwriting data
        // and to ensure data_pos calculation in open() remains correct (end of tables = end of file).

        // Current data_pos is the end of file data.
        // We write hash table then block table.

        let new_hash_table_pos = self.data_pos as u32;
        let hash_table_size_bytes = self.hash_table.len() as u32 * 16;
        let new_block_table_pos = new_hash_table_pos + hash_table_size_bytes;

        // Update header with new positions
        self.header.hash_table_pos = new_hash_table_pos;
        self.header.block_table_pos = new_block_table_pos;

        // Write tables at new positions
        self.write_hash_table()?;
        self.write_block_table()?;

        // Update archive size to include tables
        let block_table_size_bytes = block_table_size * 16;
        let new_archive_size = new_block_table_pos + block_table_size_bytes;

        // Update header and flush
        self.update_header(block_table_size, new_archive_size)?;
        self.file.flush()?;

        // If signing, calculate signature and write it
        if self.sign_weak {
            // Find (signature) file position
            let signature_entry = self.hash_table.iter().find(|h| {
                h.hash_check_a == hash_string("(signature)", MPQ_HASH_NAME_A)
                    && h.hash_check_b == hash_string("(signature)", MPQ_HASH_NAME_B)
                    && h.block_index != HASH_ENTRY_DELETED
                    && h.block_index != HASH_ENTRY_FREE
            });

            if let Some(entry) = signature_entry {
                let block = &self.block_table[entry.block_index as usize];
                let signature_pos = self.mpq_offset + block.file_pos as u64;

                // Calculate MD5 of the archive
                // Read the whole archive from mpq_offset to end
                // We need to flush first (already done)
                // We need to read exactly new_archive_size bytes
                let total_size = new_archive_size as u64;
                let mut buffer = vec![0u8; 16384];
                let mut hasher = Md5::new();

                self.file.seek(SeekFrom::Start(self.mpq_offset))?;

                let mut remaining = total_size;
                while remaining > 0 {
                    let to_read = std::cmp::min(remaining, buffer.len() as u64) as usize;
                    // Use get_mut() to access the underlying File for reading, ensuring we flushed first
                    let n = self.file.get_mut().read(&mut buffer[0..to_read])?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buffer[0..n]);
                    remaining -= n as u64;
                }

                let digest = hasher.finalize();

                // Sign the hash
                let priv_key = RsaPrivateKey::from_pkcs1_pem(BLIZZARD_WEAK_PRIVATE_KEY)
                    .map_err(|_| MpqError::InvalidParameter)?;

                // Manually construct DigestInfo for MD5 because rsa crate might not support MD5 OID automatically
                // MD5 OID: 1.2.840.113549.2.5
                // DigestInfo prefix: 30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00 04 10
                let mut digest_info = vec![
                    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02,
                    0x05, 0x05, 0x00, 0x04, 0x10,
                ];
                digest_info.extend_from_slice(&digest);

                let signing_key = Pkcs1v15Sign::new_unprefixed();
                let signature = priv_key
                    .sign(signing_key, &digest_info)
                    .map_err(|_| MpqError::InvalidParameter)?;

                // Reverse the signature (StormLib does memrev)
                let mut signature_rev = signature;
                signature_rev.reverse();

                // Construct the signature file content
                let mut sig_file_content = vec![0u8; 72];
                sig_file_content[4] = 2; // SIGNATURE_TYPE_WEAK
                sig_file_content[8..72].copy_from_slice(&signature_rev);

                // Write to file at signature_pos
                self.file.seek(SeekFrom::Start(signature_pos))?;
                self.file.write_all(&sig_file_content)?;
            }
        }

        Ok(())
    }

    fn update_internal_files(&mut self) -> MpqResult<()> {
        // 1. Update (listfile)
        let current_listfile_str = String::from_utf8_lossy(&self.listfile_content).to_string();

        // Split into lines
        let mut lines: Vec<String> = current_listfile_str
            .lines()
            .map(|s| s.trim().to_string())
            .collect();

        // Remove deleted files
        if !self.deleted_files.is_empty() {
            lines.retain(|line| {
                !self
                    .deleted_files
                    .iter()
                    .any(|deleted| line.eq_ignore_ascii_case(deleted))
            });
        }

        // Add new files
        for name in &self.new_files {
            // Avoid duplicates
            if !lines.iter().any(|line| line.eq_ignore_ascii_case(name)) {
                lines.push(name.clone());
            }
        }

        // Reconstruct content
        let mut new_listfile = Vec::new();
        for line in lines {
            if !line.is_empty() {
                new_listfile.extend_from_slice(line.as_bytes());
                new_listfile.push(b'\r');
                new_listfile.push(b'\n');
            }
        }

        // Write new (listfile)
        // We use add_file_raw to avoid adding (listfile) to new_files (infinite recursion)
        self.add_file_raw(
            "(listfile)",
            &new_listfile,
            &AddFileOptions {
                compress: true,
                encrypt: true, // (listfile) is usually encrypted
                ..Default::default()
            },
        )?;

        debug!(
            "Updated (listfile) with {} new entries",
            self.new_files.len()
        );

        // 2. Update (attributes)
        // Only if it existed before or if we want to force create it (StormLib usually creates it if not present but we'll stick to updating for now)
        // Actually, if we add files, we SHOULD have attributes if we want to be modern.
        // But for now, let's only update if it exists to avoid complexity of creating from scratch if user didn't want it.
        // 2. Update (attributes)
        // If attributes don't exist, create them with default flags
        if self.attributes_content.is_empty() {
            use byteorder::{LittleEndian, WriteBytesExt};
            let mut header = Vec::new();
            header.write_u32::<LittleEndian>(100).unwrap(); // Version
            // Default flags: CRC32 | FILETIME | MD5
            header
                .write_u32::<LittleEndian>(
                    MPQ_ATTRIBUTE_CRC32 | MPQ_ATTRIBUTE_FILETIME | MPQ_ATTRIBUTE_MD5,
                )
                .unwrap();
            self.attributes_content = header;
        }

        self.update_attributes()?;

        Ok(())
    }

    fn update_attributes(&mut self) -> MpqResult<()> {
        use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new(&self.attributes_content);

        // Read header
        if self.attributes_content.len() < 8 {
            return Ok(()); // Corrupt or empty
        }

        let version = cursor.read_u32::<LittleEndian>()?;
        let flags = cursor.read_u32::<LittleEndian>()?;

        if version != 100 {
            return Ok(()); // Unknown version
        }

        // We need to reconstruct the arrays.
        // The arrays correspond to the OLD block table.
        // Create buffers for new attributes
        let mut crc32s = Vec::with_capacity(self.block_table.len());
        let mut filetimes = Vec::with_capacity(self.block_table.len());
        let mut md5s = Vec::with_capacity(self.block_table.len());

        // Parse existing attributes to preserve them for old blocks
        let mut old_crc32s = Vec::new();
        let mut old_filetimes = Vec::new();
        let mut old_md5s = Vec::new();

        if !self.attributes_content.is_empty() {
            // Re-read flags from content to know what to parse
            // We already read version and flags above, but let's just use the cursor
            // Cursor position is at 8 (after version and flags)

            // Wait, we need to check if the flags in the file match what we expect?
            // We will use the flags read from the file to parse the file.
            // But we will write back using the SAME flags (or maybe we should upgrade to ALL flags?)
            // For now, let's respect the flags in the file.

            if (flags & MPQ_ATTRIBUTE_CRC32) != 0 {
                for _ in 0..self.initial_block_count {
                    if let Ok(val) = cursor.read_u32::<LittleEndian>() {
                        old_crc32s.push(val);
                    } else {
                        break;
                    }
                }
            }

            if (flags & MPQ_ATTRIBUTE_FILETIME) != 0 {
                for _ in 0..self.initial_block_count {
                    if let Ok(val) = cursor.read_u64::<LittleEndian>() {
                        old_filetimes.push(val);
                    } else {
                        break;
                    }
                }
            }

            if (flags & MPQ_ATTRIBUTE_MD5) != 0 {
                for _ in 0..self.initial_block_count {
                    let mut buf = [0u8; 16];
                    if cursor.read_exact(&mut buf).is_ok() {
                        old_md5s.push(buf);
                    } else {
                        break;
                    }
                }
            }
        }

        // Iterate over ALL blocks
        for i in 0..self.block_table.len() {
            let mut crc32 = 0;
            let mut file_time = 0;
            let mut md5 = [0u8; 16];

            if i < self.initial_block_count {
                // Old block: use existing attributes if available
                if i < old_crc32s.len() {
                    crc32 = old_crc32s[i];
                }
                if i < old_filetimes.len() {
                    file_time = old_filetimes[i];
                }
                if i < old_md5s.len() {
                    md5 = old_md5s[i];
                }
            } else {
                // New block: look up metadata
                // We stored metadata in `new_blocks` keyed by block index
                if let Some(metadata) = self.new_blocks.get(&(i as u32)) {
                    crc32 = metadata.crc32;
                    file_time = metadata.file_time;
                    md5 = metadata.md5;
                }
            }

            if (flags & MPQ_ATTRIBUTE_CRC32) != 0 {
                crc32s.push(crc32);
            }
            if (flags & MPQ_ATTRIBUTE_FILETIME) != 0 {
                filetimes.push(file_time);
            }
            if (flags & MPQ_ATTRIBUTE_MD5) != 0 {
                md5s.push(md5);
            }
        }

        // Re-serialize
        let mut new_data = Vec::new();
        new_data.write_u32::<LittleEndian>(version)?;
        new_data.write_u32::<LittleEndian>(flags)?;

        if (flags & MPQ_ATTRIBUTE_CRC32) != 0 {
            for val in crc32s {
                new_data.write_u32::<LittleEndian>(val)?;
            }
        }

        if (flags & MPQ_ATTRIBUTE_FILETIME) != 0 {
            for val in filetimes {
                new_data.write_u64::<LittleEndian>(val)?;
            }
        }

        if (flags & MPQ_ATTRIBUTE_MD5) != 0 {
            for val in md5s {
                new_data.write_all(&val)?;
            }
        }

        // Write (attributes) file
        self.add_file_raw(
            "(attributes)",
            &new_data,
            &AddFileOptions {
                compress: true,
                compression: MPQ_COMPRESSION_ZLIB,
                encrypt: true, // Attributes are encrypted
                locale: 0,
                single_unit: false,
                compression_next: None,
            },
        )?;

        debug!("Updated (attributes)");

        Ok(())
    }

    fn write_hash_table(&mut self) -> MpqResult<()> {
        let hash_table_pos = self.mpq_offset + self.header.hash_table_pos as u64;
        self.file.seek(SeekFrom::Start(hash_table_pos))?;

        let mut data = Vec::with_capacity(self.hash_table.len() * 16);
        for hash in &self.hash_table {
            data.extend_from_slice(&hash.hash_check_a.to_le_bytes());
            data.extend_from_slice(&hash.hash_check_b.to_le_bytes());
            data.extend_from_slice(&hash.locale.to_le_bytes());
            data.extend_from_slice(&[hash.platform, hash.flags]);
            data.extend_from_slice(&hash.block_index.to_le_bytes());
        }

        let key = hash_string("(hash table)", MPQ_HASH_FILE_KEY);
        encrypt_block(&mut data, key);
        self.file.write_all(&data)?;

        Ok(())
    }

    fn write_block_table(&mut self) -> MpqResult<()> {
        let block_table_pos = self.mpq_offset + self.header.block_table_pos as u64;
        self.file.seek(SeekFrom::Start(block_table_pos))?;

        let mut data = Vec::with_capacity(self.block_table.len() * 16);
        for block in &self.block_table {
            data.extend_from_slice(&block.file_pos.to_le_bytes());
            data.extend_from_slice(&block.compressed_size.to_le_bytes());
            data.extend_from_slice(&block.file_size.to_le_bytes());
            data.extend_from_slice(&block.flags.to_le_bytes());
        }

        let key = hash_string("(block table)", MPQ_HASH_FILE_KEY);
        encrypt_block(&mut data, key);
        self.file.write_all(&data)?;

        Ok(())
    }

    fn update_header(&mut self, block_table_size: u32, archive_size: u32) -> MpqResult<()> {
        self.file.seek(SeekFrom::Start(self.mpq_offset))?;

        self.file.write_all(&ID_MPQ.to_le_bytes())?;
        self.file
            .write_all(&self.header.header_size.to_le_bytes())?;
        self.file.write_all(&archive_size.to_le_bytes())?;
        self.file
            .write_all(&self.header.format_version.to_le_bytes())?;
        self.file
            .write_all(&self.header.sector_size.to_le_bytes())?;
        self.file
            .write_all(&self.header.hash_table_pos.to_le_bytes())?;
        self.file
            .write_all(&self.header.block_table_pos.to_le_bytes())?;
        self.file
            .write_all(&self.header.hash_table_size.to_le_bytes())?;
        self.file.write_all(&block_table_size.to_le_bytes())?;

        Ok(())
    }
}

/// High-level function to add a file to an existing archive.
pub fn add_file_to_archive<P: AsRef<Path>>(
    archive_path: P,
    file_name: &str,
    data: &[u8],
) -> MpqResult<()> {
    let mut writer = MpqArchiveWriter::open(archive_path)?;
    writer.add_file(file_name, data, &AddFileOptions::default())?;
    writer.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_file_options_default() {
        let options = AddFileOptions::default();
        assert!(options.compress);
        assert!(!options.encrypt);
    }

    #[test]
    fn test_set_file_locale() {
        // Mock hash table
        let mut writer = MpqArchiveWriter {
            path: "test.mpq".to_string(),
            file: BufWriter::new(File::create("test_set_locale.tmp").unwrap()),
            header: MpqHeader::default(),
            hash_table: vec![MpqHash::new_empty(); 16],
            block_table: Vec::new(),
            sector_size: 4096,
            mpq_offset: 0,
            data_pos: 0,
            new_files: Vec::new(),
            deleted_files: Vec::new(),
            file_metadata: HashMap::new(),
            listfile_content: Vec::new(),
            attributes_content: Vec::new(),
            sign_weak: false,
            initial_block_count: 0,
            new_blocks: HashMap::new(),
        };

        // Add a file manually to hash table
        let name = "test.txt";
        let hash_index = writer.find_free_hash_entry(name).unwrap();
        writer.hash_table[hash_index].hash_check_a = hash_string(name, MPQ_HASH_NAME_A);
        writer.hash_table[hash_index].hash_check_b = hash_string(name, MPQ_HASH_NAME_B);
        writer.hash_table[hash_index].locale = 0;
        writer.hash_table[hash_index].block_index = 0;

        // Set locale
        writer.set_file_locale(name, 1).unwrap();
        assert_eq!(writer.hash_table[hash_index].locale, 1);

        // Add another file with same name but different locale (simulated)
        // Note: find_free_hash_entry will return the SAME index if name matches,
        // so we can't easily simulate collision with current helper unless we manually pick another slot.
        // But let's try to set locale to 1 again (should succeed as it's the same file)
        writer.set_file_locale(name, 1).unwrap();

        // Clean up
        std::fs::remove_file("test_set_locale.tmp").ok();
    }

    #[test]
    fn test_sign_archive() {
        let path = "test_sign.mpq";
        let mut writer = MpqArchiveWriter {
            path: path.to_string(),
            file: BufWriter::new(File::create(path).unwrap()),
            header: MpqHeader::default(),
            hash_table: vec![MpqHash::new_empty(); 16],
            block_table: Vec::new(),
            sector_size: 4096,
            mpq_offset: 0,
            data_pos: 0,
            new_files: Vec::new(),
            deleted_files: Vec::new(),
            file_metadata: HashMap::new(),
            listfile_content: Vec::new(),
            attributes_content: Vec::new(),
            sign_weak: false,
            initial_block_count: 0,
            new_blocks: HashMap::new(),
        };

        writer.sign_archive();
        assert!(writer.sign_weak);

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_set_max_file_count() {
        let path = "test_resize.mpq";
        let mut writer = MpqArchiveWriter {
            path: path.to_string(),
            file: BufWriter::new(File::create(path).unwrap()),
            header: MpqHeader::default(),
            hash_table: vec![MpqHash::new_empty(); 4],
            block_table: Vec::new(),
            sector_size: 4096,
            mpq_offset: 0,
            data_pos: 0,
            new_files: Vec::new(),
            deleted_files: Vec::new(),
            file_metadata: HashMap::new(),
            listfile_content: Vec::new(),
            attributes_content: Vec::new(),
            sign_weak: false,
            initial_block_count: 0,
            new_blocks: HashMap::new(),
        };

        let name = "test.txt";
        let ha = hash_string(name, MPQ_HASH_NAME_A);
        let hb = hash_string(name, MPQ_HASH_NAME_B);
        let idx = hash_string(name, MPQ_HASH_TABLE_INDEX) as usize % 4;

        writer.hash_table[idx] = MpqHash {
            hash_check_a: ha,
            hash_check_b: hb,
            locale: 0,
            platform: 0,
            flags: 0,
            block_index: 0,
        };

        writer.new_files.push(name.to_string());

        writer.set_max_file_count(8).unwrap();

        assert_eq!(writer.hash_table.len(), 8);
        assert_eq!(writer.header.hash_table_size, 8);

        let new_idx = hash_string(name, MPQ_HASH_TABLE_INDEX) as usize % 8;
        assert_eq!(writer.hash_table[new_idx].hash_check_a, ha);

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_attributes_new_file() {
        let path = "test_attributes.mpq";

        // Create empty archive
        crate::archive::create::MpqArchiveBuilder::new(path)
            .build()
            .unwrap();

        // Open for writing
        let mut writer = MpqArchiveWriter::open(path).unwrap();

        let content = b"Hello Attributes";
        writer
            .add_file("test.txt", content, &AddFileOptions::default())
            .unwrap();
        writer.finish().unwrap();

        // Re-open and check attributes
        let archive = MpqArchive::open(path).unwrap();
        let info = archive.get_file_info("test.txt").unwrap();

        assert_ne!(info.crc32, 0);
        assert_eq!(info.crc32, crate::verify::calculate_crc32(content));

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_rename_file_encrypted() -> MpqResult<()> {
        let path = "test_rename_encrypted.mpq";

        // Create empty archive
        crate::archive::create::MpqArchiveBuilder::new(path).build()?;

        let mut archive = MpqArchiveWriter::open(path)?;
        // Ensure sectored by setting sector size if needed, but default is usually sectored.
        // Let's just use default.

        let file_name = "encrypted.txt";
        let content = b"This is an encrypted file content.";

        // Add encrypted file
        let options = AddFileOptions {
            encrypt: true,
            compress: false,
            ..Default::default()
        };
        archive.add_file(file_name, content, &options)?;
        archive.finish()?;

        // Re-open and rename
        let mut archive = MpqArchiveWriter::open(path)?;

        // Rename
        let new_name = "renamed_encrypted.txt";
        archive.rename_file(file_name, new_name)?;
        archive.finish()?;

        // Verify
        let archive_reader = MpqArchive::open(path)?;

        // Check new file
        let read_content = archive_reader.read_file(new_name)?;
        assert_eq!(read_content, content);

        // Check old file (should be missing)
        assert!(archive_reader.read_file(file_name).is_err());

        std::fs::remove_file(path).ok();

        Ok(())
    }
}
