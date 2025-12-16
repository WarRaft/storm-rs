//! Input stream for Huffman decompression.
//! Ported from StormLib/src/huffman/huff.h and huff.cpp

/// Input stream for Huffman decompression.
/// Corresponds to TInputStream in StormLib.
pub struct BitStream<'a> {
    pub data: &'a [u8],
    pub byte_pos: usize,
    pub bit_buffer: u32,
    pub bit_count: u32,
}

impl<'a> BitStream<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_buffer: 0,
            bit_count: 0,
        }
    }

    /// Gets 1 bit from the stream.
    /// Returns true if successful, false if not enough data.
    pub fn get_1_bit(&mut self) -> Option<u32> {
        // If there is not enough bits to get the value,
        // we have to add 8 more bits from the input buffer
        if self.bit_count < 1 {
            if self.byte_pos >= self.data.len() {
                return None;
            }
            let byte = self.data[self.byte_pos] as u32;
            self.byte_pos += 1;
            self.bit_buffer |= byte << self.bit_count;
            self.bit_count += 8;
        }

        let bit_value = self.bit_buffer & 1;
        self.bit_buffer >>= 1;
        self.bit_count -= 1;
        Some(bit_value)
    }

    /// Gets 8 bits from the stream.
    /// Returns true if successful, false if not enough data.
    pub fn get_8_bits(&mut self) -> Option<u32> {
        // If there is not enough bits to get the value,
        // we have to add 8 more bits from the input buffer
        if self.bit_count < 8 {
            if self.byte_pos >= self.data.len() {
                return None;
            }
            let byte = self.data[self.byte_pos] as u32;
            self.byte_pos += 1;
            self.bit_buffer |= byte << self.bit_count;
            self.bit_count += 8;
        }

        let byte_value = self.bit_buffer & 0xFF;
        self.bit_buffer >>= 8;
        self.bit_count -= 8;
        Some(byte_value)
    }

    /// Gets 7 bits from the stream. DOES NOT remove the bits from input stream.
    /// Returns true if successful, false if not enough data.
    pub fn peek_7_bits(&mut self) -> Option<u32> {
        // If there is not enough bits to get the value,
        // we have to add 8 more bits from the input buffer
        if self.bit_count < 7 {
            if self.byte_pos >= self.data.len() {
                return None;
            }
            let byte = self.data[self.byte_pos] as u32;
            self.byte_pos += 1;
            self.bit_buffer |= byte << self.bit_count;
            self.bit_count += 8;
        }

        let value = self.bit_buffer & 0x7F;
        Some(value)
    }

    /// Skips bits in the stream.
    pub fn skip_bits(&mut self, bits_to_skip: u32) {
        // If there is not enough bits in the buffer,
        // we have to add 8 more bits from the input buffer
        if self.bit_count < bits_to_skip && self.byte_pos < self.data.len() {
            let byte = self.data[self.byte_pos] as u32;
            self.byte_pos += 1;
            self.bit_buffer |= byte << self.bit_count;
            self.bit_count += 8;
        }

        self.bit_buffer >>= bits_to_skip;
        if self.bit_count >= bits_to_skip {
            self.bit_count -= bits_to_skip;
        } else {
            self.bit_count = 0;
        }
    }
}
