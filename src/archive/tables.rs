//! Archive table parsing and management.
//! Ported from SBaseFileTable.cpp

use std::io::{Read, Seek, SeekFrom};

use crate::constants::*;
use crate::crypto::{decrypt_block, hash_string};
use crate::error::MpqResult;
use crate::types::*;

/// Read and parse the hash table from an MPQ archive.
pub fn read_hash_table<R: Read + Seek>(
    reader: &mut R,
    header: &MpqHeader,
    mpq_offset: u64,
) -> MpqResult<Vec<MpqHash>> {
    let table_size = header.hash_table_size as usize;
    if table_size == 0 {
        return Ok(Vec::new());
    }

    // Calculate table position
    let table_pos = mpq_offset + header.hash_table_pos64();

    // Read raw table data
    let byte_size = table_size * MpqHash::SIZE;
    let mut data = vec![0u8; byte_size];

    reader.seek(SeekFrom::Start(table_pos))?;
    reader.read_exact(&mut data)?;

    // Decrypt the hash table
    decrypt_block(&mut data, MPQ_KEY_HASH_TABLE);

    // Parse entries
    let mut entries = Vec::with_capacity(table_size);
    for i in 0..table_size {
        let offset = i * MpqHash::SIZE;
        let entry = MpqHash {
            hash_check_a: u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]),
            hash_check_b: u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]),
            locale: u16::from_le_bytes([data[offset + 8], data[offset + 9]]),
            platform: data[offset + 10],
            flags: data[offset + 11],
            block_index: u32::from_le_bytes([
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]),
        };
        entries.push(entry);
    }

    Ok(entries)
}

/// Read and parse the block table from an MPQ archive.
pub fn read_block_table<R: Read + Seek>(
    reader: &mut R,
    header: &MpqHeader,
    mpq_offset: u64,
) -> MpqResult<Vec<MpqBlock>> {
    let table_size = header.block_table_size as usize;
    if table_size == 0 {
        return Ok(Vec::new());
    }

    // Calculate table position
    let table_pos = mpq_offset + header.block_table_pos64();

    // Read raw table data
    let byte_size = table_size * MpqBlock::SIZE;
    let mut data = vec![0u8; byte_size];

    reader.seek(SeekFrom::Start(table_pos))?;
    reader.read_exact(&mut data)?;

    // Decrypt the block table
    decrypt_block(&mut data, MPQ_KEY_BLOCK_TABLE);

    // Parse entries
    let mut entries = Vec::with_capacity(table_size);
    for i in 0..table_size {
        let offset = i * MpqBlock::SIZE;
        let entry = MpqBlock {
            file_pos: u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]),
            compressed_size: u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]),
            file_size: u32::from_le_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
            ]),
            flags: u32::from_le_bytes([
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]),
        };
        entries.push(entry);
    }

    Ok(entries)
}

/// Read the hi-block table (for large archives with 64-bit file offsets).
pub fn read_hi_block_table<R: Read + Seek>(
    reader: &mut R,
    header: &MpqHeader,
    mpq_offset: u64,
) -> MpqResult<Vec<u16>> {
    // Only present in v2+ archives
    if header.format_version < MPQ_FORMAT_VERSION_2 {
        return Ok(Vec::new());
    }

    if header.hi_block_table_pos64 == 0 {
        return Ok(Vec::new());
    }

    let table_size = header.block_table_size as usize;
    let table_pos = mpq_offset + header.hi_block_table_pos64;

    let mut data = vec![0u8; table_size * 2];
    reader.seek(SeekFrom::Start(table_pos))?;
    reader.read_exact(&mut data)?;

    let mut entries = Vec::with_capacity(table_size);
    for i in 0..table_size {
        let offset = i * 2;
        entries.push(u16::from_le_bytes([data[offset], data[offset + 1]]));
    }

    Ok(entries)
}

/// Find a hash entry for a given file name.
pub fn get_hash_entry<'a>(
    hash_table: &'a [MpqHash],
    filename: &str,
    locale: u16,
) -> Option<&'a MpqHash> {
    if hash_table.is_empty() {
        return None;
    }

    let hash_index = hash_string(filename, MPQ_HASH_TABLE_INDEX);
    let hash_a = hash_string(filename, MPQ_HASH_NAME_A);
    let hash_b = hash_string(filename, MPQ_HASH_NAME_B);

    let table_size = hash_table.len() as u32;
    let start_index = hash_index & (table_size - 1);
    let mut index = start_index;

    loop {
        let entry = &hash_table[index as usize];

        // Check if this is a matching entry
        if entry.hash_check_a == hash_a && entry.hash_check_b == hash_b {
            // Check locale (0 is neutral, matches any)
            if (entry.locale == locale || entry.locale == 0 || locale == 0)
                && !entry.is_free()
                && !entry.is_deleted()
            {
                return Some(entry);
            }
        }

        // Free entry means file doesn't exist
        if entry.is_free() {
            return None;
        }

        // Move to next entry
        index = (index + 1) & (table_size - 1);

        // Wrapped around - not found
        if index == start_index {
            return None;
        }
    }
}

/// Build file entries from hash and block tables.
pub fn build_file_table(
    _hash_table: &[MpqHash],
    block_table: &[MpqBlock],
    hi_block_table: &[u16],
    mpq_offset: u64,
) -> Vec<FileEntry> {
    let mut entries = Vec::with_capacity(block_table.len());

    for (i, block) in block_table.iter().enumerate() {
        // Skip entries that don't exist
        if !block.exists() {
            continue;
        }

        // Calculate 64-bit file offset
        let hi_offset = if i < hi_block_table.len() {
            hi_block_table[i] as u64
        } else {
            0
        };
        let byte_offset = (hi_offset << 32) | (block.file_pos as u64);

        let entry = FileEntry {
            file_name_hash: 0,
            byte_offset: mpq_offset + byte_offset,
            file_time: 0,
            file_size: block.file_size,
            compressed_size: block.compressed_size,
            flags: block.flags,
            crc32: 0,
            md5: [0; MD5_DIGEST_SIZE],
            file_name: None,
        };

        entries.push(entry);
    }

    entries
}

/// Find a file entry by name.
pub fn find_file_entry<'a>(
    hash_table: &[MpqHash],
    block_table: &'a [MpqBlock],
    filename: &str,
    locale: u16,
) -> Option<(u32, &'a MpqBlock)> {
    let hash_entry = get_hash_entry(hash_table, filename, locale)?;
    let block_index = hash_entry.masked_block_index();

    if (block_index as usize) < block_table.len() {
        let block = &block_table[block_index as usize];
        if block.exists() {
            return Some((block_index, block));
        }
    }

    None
}
