//! Huffman decompression module.
//! Ported from StormLib/src/huffman/huff.cpp

mod bitstream;
mod constants;
mod tree;
mod types;

use bitstream::BitStream;
use tree::HuffmanTree;

pub const HUFF_DECOMPRESS_ERROR: u32 = 0x1FF;

/// Decompress Huffman-encoded data.
/// Corresponds to THuffmannTree::Decompress in StormLib.
pub fn decompress_huffman(input: &[u8], output_size: usize) -> Result<Vec<u8>, &'static str> {
    if input.is_empty() {
        return Err("Huffman: empty input");
    }

    if output_size == 0 {
        return Ok(Vec::new());
    }

    let mut stream = BitStream::new(input);
    let mut output = Vec::with_capacity(output_size);

    // Get compression type
    let compression_type = match stream.get_8_bits() {
        Some(v) => v as u8,
        None => return Err("Huffman: failed to read compression type"),
    };
    log::trace!("Huffman: compression_type={}", compression_type);
    if input.len() > 5 {
        log::trace!("Huffman: input prefix: {:02X?}", &input[0..5]);
    }

    let mut tree = HuffmanTree::new(false);
    if !tree.build_tree(compression_type) {
        return Err("Huffman: failed to build tree");
    }

    tree.is_cmp0 = compression_type == 0;

    while output.len() < output_size {
        let value = match tree.decode_one_byte(&mut stream) {
            Some(v) => v,
            None => {
                log::trace!(
                    "Huffman: decode_one_byte returned None at output pos {}",
                    output.len()
                );
                return Err("Huffman: decode error");
            }
        };

        if value == 0x100 {
            break; // End of stream
        }

        if value == HUFF_DECOMPRESS_ERROR {
            return Err("Huffman: decode error (invalid value)");
        }

        if value == 0x101 {
            // Huffman tree needs to be modified
            let literal = match stream.get_8_bits() {
                Some(v) => v,
                None => return Err("Huffman: failed to read literal after 0x101"),
            };

            // Insert new branch
            // StormLib: InsertNewBranchAndRebalance(pLast->DecompressedValue, DecompressedValue)
            // pLast is the 0x101 marker node?
            // Wait, StormLib uses pLast.
            // In BuildTree, 0x101 is inserted at the end.
            // So pLast should point to 0x101 initially.

            if !tree.insert_new_branch_and_rebalance(
                tree.nodes[tree.last.unwrap() as usize].decompressed_value,
                literal,
            ) {
                return Err("Huffman: failed to insert new branch");
            }

            if let Some(idx) = tree.items_by_byte[literal as usize] {
                tree.inc_weights_and_rebalance(idx);
            }

            output.push(literal as u8);
        } else {
            output.push(value as u8);

            if tree.is_cmp0
                && let Some(idx) = tree.items_by_byte[value as usize]
            {
                tree.inc_weights_and_rebalance(idx);
            }
        }
    }

    Ok(output)
}

/// Compress data using Huffman encoding.
pub fn compress_huffman(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    // Output buffer
    let mut output = Vec::with_capacity(input.len());

    // Compression type 0 (standard)
    let compression_type = 0;
    output.push(compression_type);

    // Bit stream for writing
    let mut bit_buffer: u32 = 0;
    let mut bit_count: u32 = 0;

    // Helper to write bits
    let mut write_bits = |bits: u32, count: u32, out: &mut Vec<u8>| {
        bit_buffer |= bits << bit_count;
        bit_count += count;
        while bit_count >= 8 {
            out.push((bit_buffer & 0xFF) as u8);
            bit_buffer >>= 8;
            bit_count -= 8;
        }
    };

    let mut tree = HuffmanTree::new(true);
    if !tree.build_tree(compression_type) {
        return Err("Huffman: failed to build tree");
    }
    tree.is_cmp0 = compression_type == 0;

    for &byte in input {
        let value = byte as u32;

        // Find item for this byte
        if let Some(item_idx) = tree.items_by_byte[value as usize] {
            // Byte is already in the tree
            let (code, len) = tree.get_code(item_idx);
            write_bits(code, len, &mut output);

            if tree.is_cmp0 {
                tree.inc_weights_and_rebalance(item_idx);
            }
        } else {
            // Byte not in tree, emit 0x101 (escape) then the byte
            if let Some(esc_idx) = tree.items_by_byte[0x101] {
                let (code, len) = tree.get_code(esc_idx);
                write_bits(code, len, &mut output);
            } else {
                return Err("Huffman: escape code 0x101 not found in tree");
            }

            // Write literal byte
            write_bits(value, 8, &mut output);

            // Insert new branch
            if !tree.insert_new_branch_and_rebalance(
                tree.nodes[tree.last.unwrap() as usize].decompressed_value,
                value,
            ) {
                return Err("Huffman: failed to insert new branch");
            }

            if let Some(idx) = tree.items_by_byte[value as usize] {
                tree.inc_weights_and_rebalance(idx);
            }
        }
    }

    // Write 0x100 (EOF)
    if let Some(eof_idx) = tree.items_by_byte[0x100] {
        let (code, len) = tree.get_code(eof_idx);
        write_bits(code, len, &mut output);
    } else {
        return Err("Huffman: EOF code 0x100 not found in tree");
    }

    // Flush remaining bits
    if bit_count > 0 {
        output.push((bit_buffer & 0xFF) as u8);
    }

    Ok(output)
}
