//! ADPCM helper functions.
//! Ported from StormLib/src/adpcm/adpcm.cpp

use super::constants::*;

#[inline(always)]
pub fn get_next_step_index(step_index: i32, encoded_sample: u32) -> i32 {
    let mut step_index = step_index + NEXT_STEP_TABLE[(encoded_sample & 0x1F) as usize];

    step_index = step_index.clamp(0, 88);

    step_index
}

#[inline(always)]
pub fn update_predicted_sample(
    mut predicted_sample: i32,
    encoded_sample: i32,
    difference: i32,
    bit_mask: i32,
) -> i32 {
    if (encoded_sample & bit_mask) != 0 {
        predicted_sample -= difference;
        if predicted_sample <= -32768 {
            predicted_sample = -32768;
        }
    } else {
        predicted_sample += difference;
        if predicted_sample >= 32767 {
            predicted_sample = 32767;
        }
    }

    predicted_sample
}

#[inline(always)]
pub fn decode_sample(
    predicted_sample: i32,
    encoded_sample: i32,
    step_size: i32,
    mut difference: i32,
) -> i32 {
    if (encoded_sample & 0x01) != 0 {
        difference += step_size;
    }
    if (encoded_sample & 0x02) != 0 {
        difference += step_size >> 1;
    }
    if (encoded_sample & 0x04) != 0 {
        difference += step_size >> 2;
    }
    if (encoded_sample & 0x08) != 0 {
        difference += step_size >> 3;
    }
    if (encoded_sample & 0x10) != 0 {
        difference += step_size >> 4;
    }
    if (encoded_sample & 0x20) != 0 {
        difference += step_size >> 5;
    }

    update_predicted_sample(predicted_sample, encoded_sample, difference, 0x40)
}
