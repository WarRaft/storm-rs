//! ADPCM compression.
//!
//! Ported from StormLib/src/adpcm/adpcm.cpp

use super::common::*;
use super::constants::*;
use crate::error::{MpqError, MpqResult};

struct AdpcmOutputStream {
    buffer: Vec<u8>,
}

impl AdpcmOutputStream {
    fn new(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
        }
    }

    fn write_byte(&mut self, value: u8) {
        self.buffer.push(value);
    }

    fn write_word(&mut self, value: i16) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }
}

/// Compress data using IMA ADPCM.
pub fn compress_adpcm(input: &[u8], channels: usize) -> MpqResult<Vec<u8>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    // Input must be 16-bit PCM
    if !input.len().is_multiple_of(2) {
        return Err(MpqError::CompressionFailed);
    }

    // Compression level (StormLib defaults to 4 for mono/stereo)
    let compression_level = 4;
    let bit_shift = compression_level - 1;

    let num_samples = input.len() / 2;
    let mut os = AdpcmOutputStream::new(input.len() / 2); // Estimate output size

    // Write header
    os.write_byte(0); // Always 0
    os.write_byte(bit_shift as u8); // Compression level - 1

    // Read input samples
    let mut samples = Vec::with_capacity(num_samples);
    for i in 0..num_samples {
        let sample = i16::from_le_bytes([input[i * 2], input[i * 2 + 1]]);
        samples.push(sample);
    }

    // Write initial samples for each channel
    let mut predicted_samples = [0i16; MAX_ADPCM_CHANNEL_COUNT];
    let mut step_indexes = [INITIAL_ADPCM_STEP_INDEX; MAX_ADPCM_CHANNEL_COUNT];

    for i in 0..channels {
        if i < samples.len() {
            let initial_sample = samples[i];
            predicted_samples[i] = initial_sample;
            os.write_word(initial_sample);
        } else {
            os.write_word(0);
        }
    }

    // Compress remaining samples
    let mut channel_index = channels - 1;
    let mut i = channels; // Start after initial samples

    while i < samples.len() {
        channel_index = (channel_index + 1) % channels;
        let sample = samples[i];
        i += 1;

        let mut step_index = step_indexes[channel_index] as usize;
        let mut step_size = STEP_SIZE_TABLE[step_index];

        // Calculate difference
        let diff = sample as i32 - predicted_samples[channel_index] as i32;
        let abs_diff = diff.abs();

        // Check if we need to adjust step index (decrease)
        if abs_diff < (step_size >> compression_level) {
            if step_index != 0 {
                step_index -= 1;
                step_indexes[channel_index] = step_index as i32;
            }
            os.write_byte(0x80);
            // In StormLib, writing 0x80 effectively skips encoding this sample in the current step context,
            // but since we are iterating samples, we need to treat this as "encoded".
            // However, StormLib's loop is: while(ReadSample) { ... if (small) { write 0x80 } else { ... encode } }
            // So if 0x80 is written, the sample is CONSUMED but no PCM data is emitted other than the marker.
            // The decoder sees 0x80, adjusts step, and writes the *current* predicted sample again.
            // So we are done with this sample.
            continue;
        }

        // Check for step increase
        while abs_diff > (step_size << 1) {
            if step_index >= 0x58 {
                break;
            }
            step_index += 8;
            if step_index > 0x58 {
                step_index = 0x58;
            }
            step_indexes[channel_index] = step_index as i32;

            step_size = STEP_SIZE_TABLE[step_index];
            os.write_byte(0x81);
            // 0x81 is a modifier that does NOT consume the sample.
            // We loop back and re-evaluate with the new step size.
        }

        // Standard encoding
        let mut encoded_sample: u8;
        if diff >= 0 {
            encoded_sample = 0;
        } else {
            encoded_sample = 0x40; // Sign bit 0x40
        }

        // Quantize difference
        let mut temp_step = step_size;
        let mut current_diff = abs_diff;
        for bit in 0..3 {
            if current_diff >= temp_step {
                encoded_sample |= 1 << bit;
                current_diff -= temp_step;
            }
            temp_step >>= 1;
        }

        // Update predicted sample
        let new_predicted = decode_sample(
            predicted_samples[channel_index] as i32,
            encoded_sample as i32,
            step_size,
            step_size >> bit_shift,
        );

        predicted_samples[channel_index] = new_predicted as i16;

        os.write_byte(encoded_sample);

        step_indexes[channel_index] =
            get_next_step_index(step_indexes[channel_index], encoded_sample as u32);
    }

    Ok(os.buffer)
}
