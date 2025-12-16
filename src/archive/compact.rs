//! Archive compaction.
//!
//! This module provides functions for compacting MPQ archives.
//! Compaction removes deleted files and reclaims space.

use std::fs::{self, File};
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::Path;

use crate::archive::{MpqArchive, write_block_table, write_hash_table, write_mpq_header};
use crate::constants::*;
use crate::error::MpqResult;
use crate::types::{MpqBlock, MpqHash};

/// Compact an MPQ archive.
/// This creates a new archive with only valid files, then replaces the original.
pub fn compact_archive<P: AsRef<Path>>(path: P) -> MpqResult<()> {
    let path_ref = path.as_ref();
    let _path_str = path_ref.to_string_lossy().to_string();

    // 1. Open source archive
    let archive = MpqArchive::open(path_ref)?;

    // 2. Create temp file
    let temp_path = path_ref.with_extension("tmp");
    let file = File::create(&temp_path)?;
    let mut writer = BufWriter::new(file);

    // 3. Write MPQ Header (placeholder)
    let header_size = archive.header.header_size;
    let mut current_pos = header_size;

    // Write placeholder header
    write_mpq_header(
        &mut writer,
        &crate::archive::MpqCreateOptions {
            format_version: archive.header.format_version,
            sector_size: archive.sector_size,
            ..Default::default()
        },
        header_size,
        archive.header.hash_table_size,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )?;

    // 4. Initialize new tables
    // We keep the same hash table size to avoid rehashing collisions complexity for now,
    // although we could resize if we wanted to be fancy.
    let hash_table_size = archive.header.hash_table_size;
    let mut new_hash_table = vec![MpqHash::new_empty(); hash_table_size as usize];
    let mut new_block_table = Vec::new();

    // 5. Iterate source hash table and copy valid files
    for (i, hash) in archive.hash_table.iter().enumerate() {
        if hash.block_index != HASH_ENTRY_DELETED && hash.block_index != HASH_ENTRY_FREE {
            let block_index = hash.block_index as usize;
            if block_index < archive.block_table.len() {
                let block = &archive.block_table[block_index];

                // Read raw data
                let data = archive.read_raw_block(block)?;

                // Write data to temp file
                writer.seek(SeekFrom::Start(current_pos as u64))?;
                writer.write_all(&data)?;

                // Create new block
                let new_block = MpqBlock {
                    file_pos: current_pos,
                    compressed_size: block.compressed_size,
                    file_size: block.file_size,
                    flags: block.flags,
                };

                let new_block_index = new_block_table.len() as u32;
                new_block_table.push(new_block);

                // Update hash entry
                let mut new_hash = *hash;
                new_hash.block_index = new_block_index;
                new_hash_table[i] = new_hash;

                current_pos += data.len() as u32;
            }
        }
    }

    // 6. Write new Hash and Block tables
    // Write at the end of data
    let hash_table_pos = current_pos;
    write_hash_table(&mut writer, &mut new_hash_table, hash_table_size)?;
    current_pos += hash_table_size * 16;

    let block_table_pos = current_pos;
    write_block_table(&mut writer, &mut new_block_table)?;
    current_pos += (new_block_table.len() as u32) * 16;

    // 7. Update Header
    let archive_size = current_pos;
    writer.seek(SeekFrom::Start(0))?;
    write_mpq_header(
        &mut writer,
        &crate::archive::MpqCreateOptions {
            format_version: archive.header.format_version,
            sector_size: archive.sector_size,
            ..Default::default()
        },
        header_size,
        hash_table_size,
        hash_table_pos,
        block_table_pos,
        new_block_table.len() as u32,
        archive_size,
        0,
        0,
        0,
        0, // TODO: Handle HET/BET if present (for now we strip them or they are lost)
    )?;

    writer.flush()?;
    drop(writer); // Close file
    drop(archive); // Close source archive

    // 8. Replace original file
    fs::remove_file(path_ref)?;
    fs::rename(temp_path, path_ref)?;

    Ok(())
}
