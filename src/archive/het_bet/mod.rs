pub mod bet;
pub mod common;
pub mod het;

pub use bet::*;
pub use het::*;

use self::common::BitReader;
use crate::crypto::hash_string_jenkins;
use crate::types::{BetTable, FileInfo, HetTable};

/// Find a file entry using HET and BET tables.
pub fn find_file_entry_v4(
    het_table: &HetTable,
    bet_table: &BetTable,
    filename: &str,
) -> Option<FileInfo> {
    let hash = hash_string_jenkins(filename);
    let hash_high = (hash >> (het_table.name_hash_bit_size - 8)) as u8;
    let start_index = (hash % het_table.total_count as u64) as usize;
    let mut index = start_index;

    loop {
        if index >= het_table.name_hashes.len() {
            break;
        }

        let entry_hash = het_table.name_hashes[index];

        if entry_hash == 0 {
            return None;
        }

        if entry_hash == hash_high {
            let bet_reader = BitReader::new(&het_table.bet_indexes);
            let bet_index = bet_reader.read_bits(
                index * het_table.index_size_total as usize,
                het_table.index_size as usize,
            ) as usize;

            if bet_index < bet_table.entry_count as usize {
                let bit_reader_file_table = BitReader::new(&bet_table.file_table);
                let base_bit_pos = bet_index * bet_table.table_entry_size as usize;

                let file_pos = bit_reader_file_table.read_bits(
                    base_bit_pos + bet_table.bit_index_file_pos as usize,
                    bet_table.bit_count_file_pos as usize,
                );

                let file_size = bit_reader_file_table.read_bits(
                    base_bit_pos + bet_table.bit_index_file_size as usize,
                    bet_table.bit_count_file_size as usize,
                );

                let compressed_size = bit_reader_file_table.read_bits(
                    base_bit_pos + bet_table.bit_index_cmp_size as usize,
                    bet_table.bit_count_cmp_size as usize,
                );

                let flag_index = bit_reader_file_table.read_bits(
                    base_bit_pos + bet_table.bit_index_flag_index as usize,
                    bet_table.bit_count_flag_index as usize,
                );

                let flags = if (flag_index as usize) < bet_table.file_flags.len() {
                    bet_table.file_flags[flag_index as usize]
                } else {
                    0
                };

                return Some(FileInfo {
                    name: filename.to_string(),
                    offset: file_pos,
                    compressed_size: compressed_size as u32,
                    file_size: file_size as u32,
                    flags,
                    block_index: bet_index as u32,
                    crc32: 0,
                    file_time: 0,
                    md5: [0; 16],
                });
            }
        }

        index = (index + 1) % het_table.total_count as usize;
        if index == start_index {
            break;
        }
    }

    None
}
