//! Cryptography functions for MPQ archives.
//! Ported from SBaseCommon.cpp

use std::sync::LazyLock;

use crate::constants::{MPQ_FILE_KEY_V2, MPQ_HASH_FILE_KEY, MPQ_HASH_KEY2_MIX};

/// Size of the Storm encryption buffer.
const STORM_BUFFER_SIZE: usize = 0x500;

/// Pre-computed encryption/decryption buffer.
/// Initialized using the same algorithm as StormLib.
static STORM_BUFFER: LazyLock<[u32; STORM_BUFFER_SIZE]> = LazyLock::new(|| {
    let mut buffer = [0u32; STORM_BUFFER_SIZE];
    let mut seed: u32 = 0x00100001;

    for index1 in 0..0x100u32 {
        let mut index2 = index1;
        for _ in 0..5 {
            seed = seed.wrapping_mul(125).wrapping_add(3) % 0x2AAAAB;
            let temp1 = (seed & 0xFFFF) << 16;

            seed = seed.wrapping_mul(125).wrapping_add(3) % 0x2AAAAB;
            let temp2 = seed & 0xFFFF;

            buffer[index2 as usize] = temp1 | temp2;
            index2 += 0x100;
        }
    }

    buffer
});

/// ASCII to uppercase table.
/// Converts slash (0x2F) to backslash (0x5C).
/// Ported from SBaseCommon.cpp.
#[rustfmt::skip]
const ASCII_TO_UPPER_TABLE: [u8; 256] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x5C,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
];

/// ASCII to uppercase table (without slash conversion).
#[rustfmt::skip]
const ASCII_TO_UPPER_TABLE_SLASH: [u8; 256] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
];

/// ASCII to lowercase table.
/// Converts slash (0x2F) to backslash (0x5C).
#[rustfmt::skip]
const ASCII_TO_LOWER_TABLE: [u8; 256] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x5C,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
];

// =============================================================================
// Hashing functions
// =============================================================================

/// Hash a string using the MPQ hash algorithm.
/// Converts characters to uppercase and replaces '/' with '\\'.
///
/// # Arguments
/// * `filename` - The file name to hash.
/// * `hash_type` - The hash type (MPQ_HASH_TABLE_INDEX, MPQ_HASH_NAME_A, MPQ_HASH_NAME_B, MPQ_HASH_FILE_KEY).
pub fn hash_string(filename: &str, hash_type: u32) -> u32 {
    let mut seed1: u32 = 0x7FED7FED;
    let mut seed2: u32 = 0xEEEEEEEE;

    for &byte in filename.as_bytes() {
        // Convert to uppercase, replace '/' with '\\'
        let ch = ASCII_TO_UPPER_TABLE[byte as usize] as u32;

        seed1 = STORM_BUFFER[(hash_type + ch) as usize] ^ seed1.wrapping_add(seed2);
        seed2 = ch
            .wrapping_add(seed1)
            .wrapping_add(seed2)
            .wrapping_add(seed2 << 5)
            .wrapping_add(3);
    }

    seed1
}

/// Hash a string using the MPQ hash algorithm.
/// Does NOT convert '/' to '\\'.
pub fn hash_string_slash(filename: &str, hash_type: u32) -> u32 {
    let mut seed1: u32 = 0x7FED7FED;
    let mut seed2: u32 = 0xEEEEEEEE;

    for &byte in filename.as_bytes() {
        // Convert to uppercase, but DON'T replace '/' with '\\'
        let ch = ASCII_TO_UPPER_TABLE_SLASH[byte as usize] as u32;

        seed1 = STORM_BUFFER[(hash_type + ch) as usize] ^ seed1.wrapping_add(seed2);
        seed2 = ch
            .wrapping_add(seed1)
            .wrapping_add(seed2)
            .wrapping_add(seed2 << 5)
            .wrapping_add(3);
    }

    seed1
}

/// Hash a string using the MPQ hash algorithm with lowercase conversion.
pub fn hash_string_lower(filename: &str, hash_type: u32) -> u32 {
    let mut seed1: u32 = 0x7FED7FED;
    let mut seed2: u32 = 0xEEEEEEEE;

    for &byte in filename.as_bytes() {
        let ch = ASCII_TO_LOWER_TABLE[byte as usize] as u32;

        seed1 = STORM_BUFFER[(hash_type + ch) as usize] ^ seed1.wrapping_add(seed2);
        seed2 = ch
            .wrapping_add(seed1)
            .wrapping_add(seed2)
            .wrapping_add(seed2 << 5)
            .wrapping_add(3);
    }

    seed1
}

// =============================================================================
// Encryption/Decryption functions
// =============================================================================

/// Decrypt a block of data in-place.
///
/// # Arguments
/// * `data` - The data to decrypt (must be aligned to 4 bytes).
/// * `key` - The decryption key.
pub fn decrypt_block(data: &mut [u8], key: u32) {
    let mut key1 = key;
    let mut key2: u32 = 0xEEEEEEEE;

    // Process 4 bytes at a time
    let chunks = data.len() / 4;

    for i in 0..chunks {
        let offset = i * 4;

        // Modify the second key
        key2 = key2.wrapping_add(STORM_BUFFER[(MPQ_HASH_KEY2_MIX + (key1 & 0xFF)) as usize]);

        // Read the encrypted value (little-endian)
        let encrypted = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

        // Decrypt
        let decrypted = encrypted ^ key1.wrapping_add(key2);

        // Write the decrypted value back (little-endian)
        let bytes = decrypted.to_le_bytes();
        data[offset] = bytes[0];
        data[offset + 1] = bytes[1];
        data[offset + 2] = bytes[2];
        data[offset + 3] = bytes[3];

        // Update keys
        key1 = ((!key1 << 0x15).wrapping_add(0x11111111)) | (key1 >> 0x0B);
        key2 = decrypted
            .wrapping_add(key2)
            .wrapping_add(key2 << 5)
            .wrapping_add(3);
    }
}

/// Decrypt a block of u32 values in-place.
///
/// # Arguments
/// * `data` - The slice of u32 values to decrypt.
/// * `key` - The decryption key.
pub fn decrypt_block_u32(data: &mut [u32], key: u32) {
    let mut key1 = key;
    let mut key2: u32 = 0xEEEEEEEE;

    for value in data.iter_mut() {
        // Modify the second key
        key2 = key2.wrapping_add(STORM_BUFFER[(MPQ_HASH_KEY2_MIX + (key1 & 0xFF)) as usize]);

        // Decrypt
        *value ^= key1.wrapping_add(key2);

        // Update keys
        key1 = ((!key1 << 0x15).wrapping_add(0x11111111)) | (key1 >> 0x0B);
        key2 = (*value)
            .wrapping_add(key2)
            .wrapping_add(key2 << 5)
            .wrapping_add(3);
    }
}

/// Encrypt a block of data in-place.
///
/// # Arguments
/// * `data` - The data to encrypt (must be aligned to 4 bytes).
/// * `key` - The encryption key.
pub fn encrypt_block(data: &mut [u8], key: u32) {
    let mut key1 = key;
    let mut key2: u32 = 0xEEEEEEEE;

    let chunks = data.len() / 4;

    for i in 0..chunks {
        let offset = i * 4;

        // Modify the second key
        key2 = key2.wrapping_add(STORM_BUFFER[(MPQ_HASH_KEY2_MIX + (key1 & 0xFF)) as usize]);

        // Read the plain value (little-endian)
        let plain = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

        // Encrypt
        let encrypted = plain ^ key1.wrapping_add(key2);

        // Write the encrypted value back (little-endian)
        let bytes = encrypted.to_le_bytes();
        data[offset] = bytes[0];
        data[offset + 1] = bytes[1];
        data[offset + 2] = bytes[2];
        data[offset + 3] = bytes[3];

        // Update keys
        key1 = ((!key1 << 0x15).wrapping_add(0x11111111)) | (key1 >> 0x0B);
        key2 = plain
            .wrapping_add(key2)
            .wrapping_add(key2 << 5)
            .wrapping_add(3);
    }
}

// =============================================================================
// Key detection functions
// =============================================================================

/// Detect file encryption key based on sector size.
///
/// This works because we know what the first DWORD should decrypt to.
/// For sector offset tables, the first value is the table size.
pub fn detect_file_key_by_sector_size(
    encrypted_data: &[u8],
    sector_size: u32,
    decrypted_0: u32,
) -> Option<u32> {
    if encrypted_data.len() < 8 {
        return None;
    }

    let encrypted_0 = u32::from_le_bytes([
        encrypted_data[0],
        encrypted_data[1],
        encrypted_data[2],
        encrypted_data[3],
    ]);
    let encrypted_1 = u32::from_le_bytes([
        encrypted_data[4],
        encrypted_data[5],
        encrypted_data[6],
        encrypted_data[7],
    ]);

    // Try subsequent values as well
    for offset in 0..4 {
        let test_decrypted_0 = decrypted_0.wrapping_add(offset);
        let decrypted_1_max = sector_size.wrapping_add(test_decrypted_0);

        // Get the value of the combined encryption key
        let key1_plus_key2 = (encrypted_0 ^ test_decrypted_0).wrapping_sub(0xEEEEEEEE);

        // Try all 256 combinations of key1
        for i in 0..0x100u32 {
            let key1 = key1_plus_key2.wrapping_sub(STORM_BUFFER[(MPQ_HASH_KEY2_MIX + i) as usize]);
            let mut key2: u32 = 0xEEEEEEEE;

            // Modify the second key and decrypt the first DWORD
            key2 = key2.wrapping_add(STORM_BUFFER[(MPQ_HASH_KEY2_MIX + (key1 & 0xFF)) as usize]);
            let data_block_0 = encrypted_0 ^ key1.wrapping_add(key2);

            if data_block_0 == test_decrypted_0 {
                // Save this key value, incremented by one for sector offset table
                let save_key1 = key1.wrapping_add(1);

                // Rotate both keys
                let key1_rotated = ((!key1 << 0x15).wrapping_add(0x11111111)) | (key1 >> 0x0B);
                key2 = data_block_0
                    .wrapping_add(key2)
                    .wrapping_add(key2 << 5)
                    .wrapping_add(3);

                // Modify the second key again and decrypt the second DWORD
                key2 = key2.wrapping_add(
                    STORM_BUFFER[(MPQ_HASH_KEY2_MIX + (key1_rotated & 0xFF)) as usize],
                );
                let data_block_1 = encrypted_1 ^ key1_rotated.wrapping_add(key2);

                if data_block_1 <= decrypted_1_max {
                    return Some(save_key1);
                }
            }
        }
    }

    None
}

/// Detect file encryption key from known content.
///
/// This works when we know what the first two DWORDs should decrypt to.
pub fn detect_file_key_by_known_content(
    encrypted_data: &[u8],
    decrypted_0: u32,
    decrypted_1: u32,
) -> Option<u32> {
    if encrypted_data.len() < 8 {
        return None;
    }

    let encrypted_0 = u32::from_le_bytes([
        encrypted_data[0],
        encrypted_data[1],
        encrypted_data[2],
        encrypted_data[3],
    ]);
    let encrypted_1 = u32::from_le_bytes([
        encrypted_data[4],
        encrypted_data[5],
        encrypted_data[6],
        encrypted_data[7],
    ]);

    // Get the value of the combined encryption key
    let key1_plus_key2 = (encrypted_0 ^ decrypted_0).wrapping_sub(0xEEEEEEEE);

    // Try all 256 combinations of key1
    for i in 0..0x100u32 {
        let key1 = key1_plus_key2.wrapping_sub(STORM_BUFFER[(MPQ_HASH_KEY2_MIX + i) as usize]);
        let mut key2: u32 = 0xEEEEEEEE;

        // Modify the second key and decrypt the first DWORD
        key2 = key2.wrapping_add(STORM_BUFFER[(MPQ_HASH_KEY2_MIX + (key1 & 0xFF)) as usize]);
        let data_block_0 = encrypted_0 ^ key1.wrapping_add(key2);

        if data_block_0 == decrypted_0 {
            // Save this key value
            let save_key1 = key1;

            // Rotate both keys
            let key1_rotated = ((!key1 << 0x15).wrapping_add(0x11111111)) | (key1 >> 0x0B);
            key2 = data_block_0
                .wrapping_add(key2)
                .wrapping_add(key2 << 5)
                .wrapping_add(3);

            // Modify the second key again and decrypt the second DWORD
            key2 = key2
                .wrapping_add(STORM_BUFFER[(MPQ_HASH_KEY2_MIX + (key1_rotated & 0xFF)) as usize]);
            let data_block_1 = encrypted_1 ^ key1_rotated.wrapping_add(key2);

            if data_block_1 == decrypted_1 {
                return Some(save_key1);
            }
        }
    }

    None
}

/// Detect file key by content type (WAVE, EXE, XML).
pub fn detect_file_key_by_content(
    encrypted_data: &[u8],
    sector_size: u32,
    file_size: u32,
) -> Option<u32> {
    // Try WAVE file signature ("RIFF")
    if sector_size >= 0x0C
        && let Some(key) =
            detect_file_key_by_known_content(encrypted_data, 0x46464952, file_size.wrapping_sub(8))
    {
        return Some(key);
    }

    // Try EXE file signature ("MZ")
    if sector_size > 0x40
        && let Some(key) = detect_file_key_by_known_content(encrypted_data, 0x00905A4D, 0x00000003)
    {
        return Some(key);
    }

    // Try XML signature ("<?xm")
    if sector_size > 0x04
        && let Some(key) = detect_file_key_by_known_content(encrypted_data, 0x6D783F3C, 0x6576206C)
    {
        return Some(key);
    }

    None
}

/// Calculate the file decryption key from the file name.
///
/// # Arguments
/// * `filename` - The file name (full path).
/// * `mpq_pos` - Position of the file in the MPQ.
/// * `file_size` - Uncompressed file size.
/// * `flags` - File flags.
pub fn calculate_file_key(filename: &str, mpq_pos: u64, file_size: u32, flags: u32) -> u32 {
    // File key is calculated from plain name (without path)
    let plain_name = get_plain_filename(filename);
    let mut file_key = hash_string(plain_name, MPQ_HASH_FILE_KEY);

    // Fix the key if needed
    if (flags & MPQ_FILE_KEY_V2) != 0 {
        file_key = (file_key.wrapping_add(mpq_pos as u32)) ^ file_size;
    }

    file_key
}

/// Extract the plain file name (without path) from a full path.
pub fn get_plain_filename(filename: &str) -> &str {
    // Find the last path separator (either '\\' or '/')
    let last_sep = filename.rfind(['\\', '/']);
    match last_sep {
        Some(pos) => &filename[pos + 1..],
        None => filename,
    }
}

// =============================================================================
// Jenkins hash (for HET/BET tables)
// =============================================================================

/// Jenkins hash lookup2 function (hashlittle2).
/// Used for file name hashing in HET/BET tables.
pub fn hash_string_jenkins(filename: &str) -> u64 {
    // Normalize filename to buffer: lowercase, '/' -> '\\'
    let mut buffer = Vec::with_capacity(filename.len());
    for &byte in filename.as_bytes() {
        buffer.push(ASCII_TO_LOWER_TABLE[byte as usize]);
    }

    let (primary, secondary) = hashlittle2(&buffer, 1, 2);

    ((primary as u64) << 32) | (secondary as u64)
}

/// Jenkins lookup2 hash implementation.
/// Returns (primary_hash, secondary_hash).
fn hashlittle2(data: &[u8], pc: u32, pb: u32) -> (u32, u32) {
    let mut a: u32 = 0xdeadbeef_u32
        .wrapping_add(data.len() as u32)
        .wrapping_add(pc);
    let mut b: u32 = a;
    let mut c: u32 = a.wrapping_add(pb);

    let mut i = 0;
    let len = data.len();

    // Main body - process 12-byte chunks
    while i + 12 <= len {
        a = a.wrapping_add(u32::from_le_bytes([
            data[i],
            data[i + 1],
            data[i + 2],
            data[i + 3],
        ]));
        b = b.wrapping_add(u32::from_le_bytes([
            data[i + 4],
            data[i + 5],
            data[i + 6],
            data[i + 7],
        ]));
        c = c.wrapping_add(u32::from_le_bytes([
            data[i + 8],
            data[i + 9],
            data[i + 10],
            data[i + 11],
        ]));

        // mix(a, b, c)
        a = a.wrapping_sub(c);
        a ^= c.rotate_left(4);
        c = c.wrapping_add(b);
        b = b.wrapping_sub(a);
        b ^= a.rotate_left(6);
        a = a.wrapping_add(c);
        c = c.wrapping_sub(b);
        c ^= b.rotate_left(8);
        b = b.wrapping_add(a);
        a = a.wrapping_sub(c);
        a ^= c.rotate_left(16);
        c = c.wrapping_add(b);
        b = b.wrapping_sub(a);
        b ^= a.rotate_left(19);
        a = a.wrapping_add(c);
        c = c.wrapping_sub(b);
        c ^= b.rotate_left(4);
        b = b.wrapping_add(a);

        i += 12;
    }

    // Handle remaining bytes
    let remaining = &data[i..];
    if !remaining.is_empty() {
        // Pad with zeros and process
        let mut temp = [0u8; 12];
        temp[..remaining.len()].copy_from_slice(remaining);

        match remaining.len() {
            12 => {
                c = c.wrapping_add(u32::from_le_bytes([temp[8], temp[9], temp[10], temp[11]]));
                b = b.wrapping_add(u32::from_le_bytes([temp[4], temp[5], temp[6], temp[7]]));
                a = a.wrapping_add(u32::from_le_bytes([temp[0], temp[1], temp[2], temp[3]]));
            }
            11 => {
                c = c.wrapping_add((temp[10] as u32) << 16);
                c = c.wrapping_add((temp[9] as u32) << 8);
                c = c.wrapping_add(temp[8] as u32);
                b = b.wrapping_add(u32::from_le_bytes([temp[4], temp[5], temp[6], temp[7]]));
                a = a.wrapping_add(u32::from_le_bytes([temp[0], temp[1], temp[2], temp[3]]));
            }
            10 => {
                c = c.wrapping_add((temp[9] as u32) << 8);
                c = c.wrapping_add(temp[8] as u32);
                b = b.wrapping_add(u32::from_le_bytes([temp[4], temp[5], temp[6], temp[7]]));
                a = a.wrapping_add(u32::from_le_bytes([temp[0], temp[1], temp[2], temp[3]]));
            }
            9 => {
                c = c.wrapping_add(temp[8] as u32);
                b = b.wrapping_add(u32::from_le_bytes([temp[4], temp[5], temp[6], temp[7]]));
                a = a.wrapping_add(u32::from_le_bytes([temp[0], temp[1], temp[2], temp[3]]));
            }
            8 => {
                b = b.wrapping_add(u32::from_le_bytes([temp[4], temp[5], temp[6], temp[7]]));
                a = a.wrapping_add(u32::from_le_bytes([temp[0], temp[1], temp[2], temp[3]]));
            }
            7 => {
                b = b.wrapping_add((temp[6] as u32) << 16);
                b = b.wrapping_add((temp[5] as u32) << 8);
                b = b.wrapping_add(temp[4] as u32);
                a = a.wrapping_add(u32::from_le_bytes([temp[0], temp[1], temp[2], temp[3]]));
            }
            6 => {
                b = b.wrapping_add((temp[5] as u32) << 8);
                b = b.wrapping_add(temp[4] as u32);
                a = a.wrapping_add(u32::from_le_bytes([temp[0], temp[1], temp[2], temp[3]]));
            }
            5 => {
                b = b.wrapping_add(temp[4] as u32);
                a = a.wrapping_add(u32::from_le_bytes([temp[0], temp[1], temp[2], temp[3]]));
            }
            4 => {
                a = a.wrapping_add(u32::from_le_bytes([temp[0], temp[1], temp[2], temp[3]]));
            }
            3 => {
                a = a.wrapping_add((temp[2] as u32) << 16);
                a = a.wrapping_add((temp[1] as u32) << 8);
                a = a.wrapping_add(temp[0] as u32);
            }
            2 => {
                a = a.wrapping_add((temp[1] as u32) << 8);
                a = a.wrapping_add(temp[0] as u32);
            }
            1 => {
                a = a.wrapping_add(temp[0] as u32);
            }
            _ => return (c, b),
        }

        // final(a, b, c)
        c ^= b;
        c = c.wrapping_sub(b.rotate_left(14));
        a ^= c;
        a = a.wrapping_sub(c.rotate_left(11));
        b ^= a;
        b = b.wrapping_sub(a.rotate_left(25));
        c ^= b;
        c = c.wrapping_sub(b.rotate_left(16));
        a ^= c;
        a = a.wrapping_sub(c.rotate_left(4));
        b ^= a;
        b = b.wrapping_sub(a.rotate_left(14));
        c ^= b;
        c = c.wrapping_sub(b.rotate_left(24));
    }

    (c, b)
}

// =============================================================================
// Utility functions
// =============================================================================

/// Returns the nearest higher power of two.
pub fn get_nearest_power_of_two(value: u32) -> u32 {
    if value == 0 {
        return 0;
    }

    let mut v = value - 1;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_string() {
        // Known hash values from StormLib
        assert_eq!(hash_string("(hash table)", MPQ_HASH_FILE_KEY), 0xC3AF3770);
        assert_eq!(hash_string("(block table)", MPQ_HASH_FILE_KEY), 0xEC83B3A3);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let original = [0x12345678u32, 0xDEADBEEF, 0xCAFEBABE, 0x00FF00FF];
        let mut data = original;

        // Convert to bytes
        let mut bytes: Vec<u8> = data.iter().flat_map(|v| v.to_le_bytes()).collect();

        encrypt_block(&mut bytes, 0x12345678);
        decrypt_block(&mut bytes, 0x12345678);

        // Convert back
        for (i, chunk) in bytes.chunks(4).enumerate() {
            data[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        assert_eq!(data, original);
    }

    #[test]
    fn test_get_plain_filename() {
        assert_eq!(
            get_plain_filename("Units\\Human\\Footman.mdx"),
            "Footman.mdx"
        );
        assert_eq!(get_plain_filename("Footman.mdx"), "Footman.mdx");
        assert_eq!(get_plain_filename("path/to/file.txt"), "file.txt");
    }

    #[test]
    fn test_power_of_two() {
        assert_eq!(get_nearest_power_of_two(1), 1);
        assert_eq!(get_nearest_power_of_two(3), 4);
        assert_eq!(get_nearest_power_of_two(5), 8);
        assert_eq!(get_nearest_power_of_two(16), 16);
        assert_eq!(get_nearest_power_of_two(17), 32);
    }
}
