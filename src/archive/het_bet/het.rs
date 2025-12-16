//! HET table parsing and writing.

use std::io::{Read, Seek};

use super::common::{BitWriter, read_ext_table};
use crate::constants::*;
use crate::crypto::{encrypt_block, hash_string_jenkins};
use crate::error::{MpqError, MpqResult};
use crate::types::{HetTable, MpqHeader};

/// Signature for HET table ('HET\x1A')
pub const HET_TABLE_SIGNATURE: u32 = 0x1A544548;

/// Read and parse the HET table.
pub fn read_het_table<R: Read + Seek>(
    reader: &mut R,
    mpq_header: &MpqHeader,
    mpq_offset: u64,
) -> MpqResult<Option<HetTable>> {
    if mpq_header.het_table_pos64 == 0 || mpq_header.het_table_size64 == 0 {
        return Ok(None);
    }

    let data = read_ext_table(
        reader,
        mpq_offset,
        mpq_header.het_table_pos64,
        mpq_header.het_table_size64,
        HET_TABLE_SIGNATURE,
        MPQ_KEY_HASH_TABLE,
    )?;

    if data.is_empty() {
        return Ok(None);
    }

    if data.len() < 32 {
        return Err(MpqError::InvalidHeader);
    }

    let _table_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let entry_count = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let total_count = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let name_hash_bit_size = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let index_size_total = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
    let index_size_extra = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
    let index_size = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
    let index_table_size = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);

    let header_size = 32;
    let name_hashes_start = header_size;
    let name_hashes_end = name_hashes_start + total_count as usize;

    if data.len() < name_hashes_end {
        return Err(MpqError::InvalidArchive);
    }

    let name_hashes = data[name_hashes_start..name_hashes_end].to_vec();

    let index_table_start = name_hashes_end;
    let index_table_end = index_table_start + index_table_size as usize;

    if data.len() < index_table_end {
        return Err(MpqError::InvalidArchive);
    }

    let bet_indexes = data[index_table_start..index_table_end].to_vec();

    let and_mask = if name_hash_bit_size != 0x40 {
        ((1u64) << name_hash_bit_size) - 1
    } else {
        u64::MAX
    };
    let or_mask = 1u64 << (name_hash_bit_size - 1);

    Ok(Some(HetTable {
        name_hashes,
        bet_indexes,
        and_mask,
        or_mask,
        entry_count,
        total_count,
        name_hash_bit_size,
        index_size_total,
        index_size_extra,
        index_size,
    }))
}

/// Write HET table.
pub fn write_het_table(files: &[(&str, u32)], hash_table_size: u32) -> MpqResult<Vec<u8>> {
    let total_count = hash_table_size;
    let entry_count = files.len() as u32;
    let name_hash_bit_size: u32 = 0x40; // StormLib uses 0x40 (64 bits)

    let mut index_size: u32 = 0;
    let mut max_index = entry_count;
    while max_index > 0 {
        max_index >>= 1;
        index_size += 1;
    }
    if index_size == 0 {
        index_size = 1;
    }

    let index_size_total: u32 = index_size;
    let index_size_extra: u32 = 0;

    let mut name_hashes = vec![0u8; total_count as usize];
    let mut bet_indexes = BitWriter::new();

    // Initialize with HET_ENTRY_FREE (0)
    // StormLib uses 0 as free entry marker?
    // In SBaseFileTable.cpp: #define HET_ENTRY_FREE 0x00
    // So 0 is correct.

    let mut het_entries: Vec<Option<(u32, u8)>> = vec![None; total_count as usize];

    for (name, block_index) in files {
        let hash = hash_string_jenkins(name);
        let hash_high = (hash >> (name_hash_bit_size - 8)) as u8;
        let start_index = (hash % total_count as u64) as usize;
        let mut index = start_index;

        loop {
            if het_entries[index].is_none() {
                het_entries[index] = Some((*block_index, hash_high));
                break;
            }

            index = (index + 1) % total_count as usize;
            if index == start_index {
                return Err(MpqError::DiskFull);
            }
        }
    }

    for (i, entry) in het_entries.iter().enumerate() {
        if let Some((block_index, hash_high)) = entry {
            name_hashes[i] = *hash_high;
            bet_indexes.write_bits(*block_index as u64, index_size as usize);
        } else {
            bet_indexes.write_bits(0, index_size as usize);
        }
    }

    let packed_indexes = bet_indexes.finish();

    // Calculate table size
    // Size of TMPQHetHeader (minus ExtHdr) + hashes + indexes
    // TMPQHetHeader (minus ExtHdr) is 8 * 4 = 32 bytes
    let header_body_size = 32;
    let table_size = header_body_size + name_hashes.len() + packed_indexes.len();

    let mut header_data = Vec::new();
    let index_table_size = packed_indexes.len() as u32;

    header_data.extend_from_slice(&(table_size as u32).to_le_bytes());
    header_data.extend_from_slice(&entry_count.to_le_bytes());
    header_data.extend_from_slice(&total_count.to_le_bytes());
    header_data.extend_from_slice(&name_hash_bit_size.to_le_bytes());
    header_data.extend_from_slice(&index_size_total.to_le_bytes());
    header_data.extend_from_slice(&index_size_extra.to_le_bytes());
    header_data.extend_from_slice(&index_size.to_le_bytes());
    header_data.extend_from_slice(&index_table_size.to_le_bytes());

    let mut raw_data = Vec::new();
    raw_data.extend_from_slice(&header_data);
    raw_data.extend_from_slice(&name_hashes);
    raw_data.extend_from_slice(&packed_indexes);

    // Compress data
    let compressed_data = crate::compression::compress(&raw_data, MPQ_COMPRESSION_ZLIB)?;
    let mut encrypted_data = compressed_data.clone();
    encrypt_block(&mut encrypted_data, MPQ_KEY_HASH_TABLE);

    let mut final_data = Vec::new();
    final_data.extend_from_slice(&HET_TABLE_SIGNATURE.to_le_bytes());
    final_data.extend_from_slice(&1u32.to_le_bytes());
    final_data.extend_from_slice(&(raw_data.len() as u32).to_le_bytes());
    final_data.extend_from_slice(&encrypted_data);

    Ok(final_data)
}
