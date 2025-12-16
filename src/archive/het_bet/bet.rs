//! BET table parsing and writing.

use std::io::{Read, Seek};

use super::common::{BitWriter, read_ext_table};
use crate::constants::*;
use crate::crypto::encrypt_block;
use crate::error::{MpqError, MpqResult};
use crate::types::{BetTable, MpqBlock, MpqHeader};

/// Signature for BET table ('BET\x1A')
pub const BET_TABLE_SIGNATURE: u32 = 0x1A544542;

/// Read and parse the BET table.
pub fn read_bet_table<R: Read + Seek>(
    reader: &mut R,
    mpq_header: &MpqHeader,
    mpq_offset: u64,
) -> MpqResult<Option<BetTable>> {
    if mpq_header.bet_table_pos64 == 0 || mpq_header.bet_table_size64 == 0 {
        return Ok(None);
    }

    let data = read_ext_table(
        reader,
        mpq_offset,
        mpq_header.bet_table_pos64,
        mpq_header.bet_table_size64,
        BET_TABLE_SIGNATURE,
        MPQ_KEY_BLOCK_TABLE,
    )?;

    if data.is_empty() {
        return Ok(None);
    }

    if data.len() < 76 {
        return Err(MpqError::InvalidHeader);
    }

    let _table_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let entry_count = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let _unknown_08 = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let table_entry_size = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);

    let bit_index_file_pos = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
    let bit_index_file_size = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
    let bit_index_cmp_size = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
    let bit_index_flag_index = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);
    let bit_index_unknown = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);

    let bit_count_file_pos = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);
    let bit_count_file_size = u32::from_le_bytes([data[40], data[41], data[42], data[43]]);
    let bit_count_cmp_size = u32::from_le_bytes([data[44], data[45], data[46], data[47]]);
    let bit_count_flag_index = u32::from_le_bytes([data[48], data[49], data[50], data[51]]);
    let bit_count_unknown = u32::from_le_bytes([data[52], data[53], data[54], data[55]]);

    let bit_total_name_hash2 = u32::from_le_bytes([data[56], data[57], data[58], data[59]]);
    let bit_extra_name_hash2 = u32::from_le_bytes([data[60], data[61], data[62], data[63]]);
    let bit_count_name_hash2 = u32::from_le_bytes([data[64], data[65], data[66], data[67]]);

    let name_hash_array_size = u32::from_le_bytes([data[68], data[69], data[70], data[71]]);
    let flag_count = u32::from_le_bytes([data[72], data[73], data[74], data[75]]);

    let header_size = 76;

    let flags_start = header_size;
    let flags_end = flags_start + (flag_count as usize * 4);

    if data.len() < flags_end {
        return Err(MpqError::InvalidArchive);
    }

    let mut file_flags = Vec::with_capacity(flag_count as usize);
    for i in 0..flag_count as usize {
        let offset = flags_start + i * 4;
        let flag = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        file_flags.push(flag);
    }

    let file_table_bits = entry_count as usize * table_entry_size as usize;
    let file_table_bytes = file_table_bits.div_ceil(8);

    let file_table_start = flags_end;
    let file_table_end = file_table_start + file_table_bytes;

    if data.len() < file_table_end {
        return Err(MpqError::InvalidArchive);
    }

    let file_table = data[file_table_start..file_table_end].to_vec();

    let name_hashes_start = file_table_end;
    let name_hashes_end = name_hashes_start + name_hash_array_size as usize;

    if data.len() < name_hashes_end {
        return Err(MpqError::InvalidArchive);
    }

    let name_hashes = data[name_hashes_start..name_hashes_end].to_vec();

    Ok(Some(BetTable {
        name_hashes,
        file_table,
        file_flags,
        table_entry_size,
        bit_index_file_pos,
        bit_index_file_size,
        bit_index_cmp_size,
        bit_index_flag_index,
        bit_index_unknown,
        bit_count_file_pos,
        bit_count_file_size,
        bit_count_cmp_size,
        bit_count_flag_index,
        bit_count_unknown,
        bit_total_name_hash2,
        bit_extra_name_hash2,
        bit_count_name_hash2,
        entry_count,
        flag_count,
    }))
}

/// Write BET table.
pub fn write_bet_table(block_table: &[MpqBlock], name_hashes: &[u64]) -> MpqResult<Vec<u8>> {
    let entry_count = block_table.len() as u32;

    let mut max_file_pos: u32 = 0;
    let mut max_file_size: u32 = 0;
    let mut max_cmp_size: u32 = 0;

    let mut unique_flags: Vec<u32> = Vec::new();
    for block in block_table {
        if !unique_flags.contains(&block.flags) {
            unique_flags.push(block.flags);
        }
        max_file_pos = std::cmp::max(max_file_pos, block.file_pos);
        max_file_size = std::cmp::max(max_file_size, block.file_size);
        max_cmp_size = std::cmp::max(max_cmp_size, block.compressed_size);
    }

    let flag_count = unique_flags.len() as u32;

    fn get_bit_count(mut val: u64) -> u32 {
        let mut bits = 0;
        while val > 0 {
            val >>= 1;
            bits += 1;
        }
        if bits == 0 { 1 } else { bits }
    }

    let bit_count_file_pos = get_bit_count(max_file_pos as u64);
    let bit_count_file_size = get_bit_count(max_file_size as u64);
    let bit_count_cmp_size = get_bit_count(max_cmp_size as u64);
    let bit_count_flag_index = get_bit_count(flag_count as u64);
    let bit_count_unknown: u32 = 0;

    let table_entry_size =
        bit_count_file_pos + bit_count_file_size + bit_count_cmp_size + bit_count_flag_index;

    let mut header_data = Vec::new();

    // Placeholder for table_size, will be calculated later
    // But wait, in HET we calculated it.
    // In BET, header structure is:
    // ExtHdr (12 bytes)
    // dwTableSize (4)
    // dwEntryCount (4)
    // ...
    // So header_data should start with dwTableSize.

    // We need to calculate sizes first.
    let flags_size = flag_count * 4;
    let file_table_bits = entry_count * table_entry_size;
    let file_table_bytes = file_table_bits.div_ceil(8);

    // Name hashes?
    // In StormLib `CreateBetHeader`:
    // pBetHeader->dwBitTotal_NameHash2 = ha->pHetTable->dwNameHashBitSize - 0x08;
    // pBetHeader->dwNameHashArraySize  = ((pBetHeader->dwBitTotal_NameHash2 * pBetHeader->dwEntryCount) + 7) / 8;

    // We assume HET hash bit size is 0x40 (64). So NameHash2 is 56 bits.
    let bit_total_name_hash2: u32 = 56;
    let bit_extra_name_hash2: u32 = 0;
    let bit_count_name_hash2: u32 = 56;
    let name_hash_array_size = (bit_total_name_hash2 * entry_count).div_ceil(8);

    // Header body size (TMPQBetHeader minus ExtHdr)
    // 76 - 12 = 64 bytes?
    // Let's count fields in `read_bet_table`:
    // table_size (4) + entry_count (4) + unknown_08 (4) + table_entry_size (4) = 16
    // bit_index_... (5 * 4) = 20
    // bit_count_... (5 * 4) = 20
    // bit_..._name_hash2 (3 * 4) = 12
    // name_hash_array_size (4) + flag_count (4) = 8
    // Total: 16 + 20 + 20 + 12 + 8 = 76 bytes.
    // This matches `read_bet_table` header size.

    let header_body_size = 76;
    let table_size = header_body_size + flags_size + file_table_bytes + name_hash_array_size;

    header_data.extend_from_slice(&table_size.to_le_bytes());
    header_data.extend_from_slice(&entry_count.to_le_bytes());
    header_data.extend_from_slice(&0x10u32.to_le_bytes()); // unknown_08
    header_data.extend_from_slice(&table_entry_size.to_le_bytes());

    let mut current_bit_index: u32 = 0;
    header_data.extend_from_slice(&current_bit_index.to_le_bytes()); // bit_index_file_pos
    current_bit_index += bit_count_file_pos;
    header_data.extend_from_slice(&current_bit_index.to_le_bytes()); // bit_index_file_size
    current_bit_index += bit_count_file_size;
    header_data.extend_from_slice(&current_bit_index.to_le_bytes()); // bit_index_cmp_size
    current_bit_index += bit_count_cmp_size;
    header_data.extend_from_slice(&current_bit_index.to_le_bytes()); // bit_index_flag_index
    current_bit_index += bit_count_flag_index;
    header_data.extend_from_slice(&current_bit_index.to_le_bytes()); // bit_index_unknown

    header_data.extend_from_slice(&bit_count_file_pos.to_le_bytes());
    header_data.extend_from_slice(&bit_count_file_size.to_le_bytes());
    header_data.extend_from_slice(&bit_count_cmp_size.to_le_bytes());
    header_data.extend_from_slice(&bit_count_flag_index.to_le_bytes());
    header_data.extend_from_slice(&bit_count_unknown.to_le_bytes());

    header_data.extend_from_slice(&bit_total_name_hash2.to_le_bytes());
    header_data.extend_from_slice(&bit_extra_name_hash2.to_le_bytes());
    header_data.extend_from_slice(&bit_count_name_hash2.to_le_bytes());

    header_data.extend_from_slice(&name_hash_array_size.to_le_bytes());
    header_data.extend_from_slice(&flag_count.to_le_bytes());

    let mut flags_data = Vec::new();
    for flag in &unique_flags {
        flags_data.extend_from_slice(&flag.to_le_bytes());
    }

    let mut bit_writer = BitWriter::new();
    for block in block_table {
        bit_writer.write_bits(block.file_pos as u64, bit_count_file_pos as usize);
        bit_writer.write_bits(block.file_size as u64, bit_count_file_size as usize);
        bit_writer.write_bits(block.compressed_size as u64, bit_count_cmp_size as usize);

        let flag_index = unique_flags.iter().position(|&f| f == block.flags).unwrap() as u32;
        bit_writer.write_bits(flag_index as u64, bit_count_flag_index as usize);
    }

    let packed_table = bit_writer.finish();

    // Name hashes
    let mut name_hashes_writer = BitWriter::new();
    for hash in name_hashes {
        name_hashes_writer.write_bits(*hash, bit_total_name_hash2 as usize);
    }
    let name_hashes_data = name_hashes_writer.finish();

    let mut raw_data = Vec::new();
    raw_data.extend_from_slice(&header_data);
    raw_data.extend_from_slice(&flags_data);
    raw_data.extend_from_slice(&packed_table);
    raw_data.extend_from_slice(&name_hashes_data);

    // Compress data
    let compressed_data = crate::compression::compress(&raw_data, MPQ_COMPRESSION_ZLIB)?;
    let mut encrypted_data = compressed_data.clone();
    encrypt_block(&mut encrypted_data, MPQ_KEY_BLOCK_TABLE);

    let mut final_data = Vec::new();
    final_data.extend_from_slice(&BET_TABLE_SIGNATURE.to_le_bytes());
    final_data.extend_from_slice(&1u32.to_le_bytes());
    final_data.extend_from_slice(&(raw_data.len() as u32).to_le_bytes());
    final_data.extend_from_slice(&encrypted_data);

    Ok(final_data)
}
