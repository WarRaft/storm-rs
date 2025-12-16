//! ADPCM decompression logic.
//! Ported from StormLib/src/adpcm/adpcm.cpp

use super::common::*;
use super::constants::*;

struct AdpcmStream<'a> {
    buffer: &'a [u8],
    pos: usize,
}

impl<'a> AdpcmStream<'a> {
    fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, pos: 0 }
    }

    fn read_byte(&mut self) -> Option<u8> {
        if self.pos < self.buffer.len() {
            let b = self.buffer[self.pos];
            self.pos += 1;
            Some(b)
        } else {
            None
        }
    }

    fn read_word(&mut self) -> Option<i16> {
        if self.pos + 2 <= self.buffer.len() {
            let val = i16::from_le_bytes([self.buffer[self.pos], self.buffer[self.pos + 1]]);
            self.pos += 2;
            Some(val)
        } else {
            None
        }
    }
}

struct AdpcmOutputStream {
    buffer: Vec<u8>,
    capacity: usize,
}

impl AdpcmOutputStream {
    fn new(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
            capacity,
        }
    }

    fn write_word(&mut self, value: i16) -> bool {
        if self.buffer.len() + 2 <= self.capacity {
            self.buffer.extend_from_slice(&value.to_le_bytes());
            true
        } else {
            false
        }
    }
}

pub fn decompress_adpcm(
    input: &[u8],
    output_size: usize,
    channel_count: usize,
) -> Result<Vec<u8>, &'static str> {
    let mut is = AdpcmStream::new(input);
    let mut os = AdpcmOutputStream::new(output_size);

    let mut predicted_samples = [0i16; MAX_ADPCM_CHANNEL_COUNT];
    let mut step_indexes = [INITIAL_ADPCM_STEP_INDEX; MAX_ADPCM_CHANNEL_COUNT];

    // The first byte is always zero, the second one contains bit shift (compression level - 1)
    let _bit_shift_1 = is.read_byte().ok_or("ADPCM: input too short")?;
    let bit_shift = is.read_byte().ok_or("ADPCM: input too short")?;

    // Next, InitialSample value for each channel follows
    for sample in predicted_samples.iter_mut().take(channel_count) {
        let initial_sample = is.read_word().ok_or("ADPCM: missing initial sample")?;
        *sample = initial_sample;

        if !os.write_word(initial_sample) {
            return Ok(os.buffer);
        }
    }

    let mut channel_index = channel_count - 1;

    while let Some(encoded_sample) = is.read_byte() {
        channel_index = (channel_index + 1) % channel_count;

        if encoded_sample == 0x80 {
            if step_indexes[channel_index] != 0 {
                step_indexes[channel_index] -= 1;
            }

            if !os.write_word(predicted_samples[channel_index]) {
                return Ok(os.buffer);
            }
        } else if encoded_sample == 0x81 {
            step_indexes[channel_index] += 8;
            if step_indexes[channel_index] > 0x58 {
                step_indexes[channel_index] = 0x58;
            }

            channel_index = (channel_index + 1) % channel_count;
        } else {
            let step_index = step_indexes[channel_index] as usize;
            let step_size = STEP_SIZE_TABLE[step_index];

            let decoded = decode_sample(
                predicted_samples[channel_index] as i32,
                encoded_sample as i32,
                step_size,
                step_size >> bit_shift,
            );

            predicted_samples[channel_index] = decoded as i16;

            if !os.write_word(predicted_samples[channel_index]) {
                break;
            }

            step_indexes[channel_index] =
                get_next_step_index(step_indexes[channel_index], encoded_sample as u32);
        }
    }

    Ok(os.buffer)
}
