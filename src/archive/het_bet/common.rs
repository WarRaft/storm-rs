//! Common utilities for HET/BET tables.

use std::io::{Read, Seek, SeekFrom};

use crate::constants::*;
use crate::crypto::decrypt_block;
use crate::error::{MpqError, MpqResult};

/// Read and decrypt/decompress an extended table (HET or BET).
pub fn read_ext_table<R: Read + Seek>(
    reader: &mut R,
    mpq_offset: u64,
    table_pos64: u64,
    table_size64: u64,
    signature: u32,
    key: u32,
) -> MpqResult<Vec<u8>> {
    if table_pos64 == 0 || table_size64 == 0 {
        return Ok(Vec::new());
    }

    let file_offset = mpq_offset + table_pos64;
    let size = table_size64 as usize;

    let mut data = vec![0u8; size];
    reader.seek(SeekFrom::Start(file_offset))?;
    reader.read_exact(&mut data)?;

    if data.len() < 12 {
        eprintln!("DEBUG: data.len() < 12: {}", data.len());
        return Err(MpqError::InvalidHeader);
    }

    let sig = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let ver = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let data_size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

    eprintln!(
        "DEBUG read_ext_table: sig=0x{:08X} (expected 0x{:08X}), ver={}, data_size={}",
        sig, signature, ver, data_size
    );

    if sig != signature {
        eprintln!("DEBUG: signature mismatch");
        return Err(MpqError::InvalidHeader);
    }

    if ver != 1 {
        eprintln!("DEBUG: version mismatch: {}", ver);
        return Err(MpqError::InvalidHeader);
    }

    let encrypted_slice = &mut data[12..];
    decrypt_block(encrypted_slice, key);

    if (data_size as usize + 12) > size {
        let compressed_data = &data[12..];
        let uncompressed_size = data_size as usize;

        if compressed_data.is_empty() {
            return Ok(Vec::new());
        }

        let decompressed =
            crate::compression::decompress(compressed_data, uncompressed_size, MPQ_FILE_COMPRESS)?;

        return Ok(decompressed);
    }

    Ok(data[12..].to_vec())
}

/// Helper to read bits from a byte array.
pub struct BitReader<'a> {
    data: &'a [u8],
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn read_bits(&self, bit_pos: usize, bit_len: usize) -> u64 {
        if bit_len == 0 {
            return 0;
        }

        let mut byte_pos = bit_pos / 8;
        let mut bit_offset = bit_pos % 8;
        let mut bits_left = bit_len;
        let mut result: u64 = 0;
        let mut result_offset = 0;

        while bits_left > 0 {
            if byte_pos >= self.data.len() {
                break;
            }

            let byte = self.data[byte_pos];
            let bits_to_read = std::cmp::min(8 - bit_offset, bits_left);

            let mask = ((1 << bits_to_read) - 1) as u8;
            let val = (byte >> bit_offset) & mask;

            result |= (val as u64) << result_offset;

            bits_left -= bits_to_read;
            result_offset += bits_to_read;
            bit_offset = 0;
            byte_pos += 1;
        }

        result
    }
}

/// Helper to write bits to a byte array.
pub struct BitWriter {
    data: Vec<u8>,
    current_byte: u8,
    bits_in_byte: usize,
}

impl BitWriter {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            current_byte: 0,
            bits_in_byte: 0,
        }
    }

    pub fn write_bits(&mut self, value: u64, bit_count: usize) {
        let mut bits_left = bit_count;
        let mut val = value;

        while bits_left > 0 {
            let bits_can_write = 8 - self.bits_in_byte;
            let bits_to_write = std::cmp::min(bits_can_write, bits_left);

            let mask = ((1 << bits_to_write) - 1) as u8;
            let chunk = (val & (mask as u64)) as u8;

            self.current_byte |= chunk << self.bits_in_byte;
            self.bits_in_byte += bits_to_write;
            val >>= bits_to_write;
            bits_left -= bits_to_write;

            if self.bits_in_byte == 8 {
                self.data.push(self.current_byte);
                self.current_byte = 0;
                self.bits_in_byte = 0;
            }
        }
    }

    pub fn finish(mut self) -> Vec<u8> {
        if self.bits_in_byte > 0 {
            self.data.push(self.current_byte);
        }
        self.data
    }
}

impl Default for BitWriter {
    fn default() -> Self {
        Self::new()
    }
}
