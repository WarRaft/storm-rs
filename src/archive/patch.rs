use crate::constants::*;
use crate::error::{MpqError, MpqResult};
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read, Seek, SeekFrom};

/// Apply a patch to the base data.
pub fn apply_patch(base_data: &[u8], patch_data: &[u8]) -> MpqResult<Vec<u8>> {
    if patch_data.len() < 8 {
        return Err(MpqError::InvalidParameter);
    }

    let mut cursor = Cursor::new(patch_data);
    let signature = cursor.read_u32::<LittleEndian>()?;

    if signature == MPQ_PATCH_SIGNATURE {
        // PTCH header
        let _size_of_patch = cursor.read_u32::<LittleEndian>()?;
        let _size_before = cursor.read_u32::<LittleEndian>()?;
        let size_after = cursor.read_u32::<LittleEndian>()?;

        // The patch type is the next 4 bytes?
        // StormLib:
        // DWORD dwSignature; // 'PTCH'
        // DWORD dwSizeOfPatchData;
        // DWORD dwSizeBeforePatch;
        // DWORD dwSizeAfterPatch;
        // DWORD dwData[0]; // Start of patch data

        // The patch data itself starts with the specific signature (e.g. BSD0)

        let current_pos = cursor.position();
        if current_pos + 4 > patch_data.len() as u64 {
            return Err(MpqError::InvalidParameter);
        }

        let patch_type = cursor.read_u32::<LittleEndian>()?;

        // Reset cursor to start of actual patch data (after PTCH header)
        // Wait, does the patch data INCLUDE the signature?
        // StormLib: VerifyPatchHeader checks PTCH, then looks at data + 0x10.
        // So the PTCH header is 16 bytes.
        // The data follows.

        cursor.seek(SeekFrom::Start(16))?;

        if patch_type == 0x434F5059 {
            // 'COPY'
            // Just return the rest of the data?
            // COPY patch usually means "replace file".
            // But usually COPY patch is just the file content?
            // If it's wrapped in PTCH, maybe it has metadata.
            // But if it's just COPY, we should just take the data.
            // However, COPY patch is rarely used in MPQ patches (usually it's just a full file replacement which doesn't use PTCH header).
            // If PTCH header says COPY, we assume the data follows.
            let mut data = Vec::with_capacity(size_after as usize);
            cursor.read_to_end(&mut data)?;
            return Ok(data);
        } else if patch_type == 0x30445342 {
            // 'BSD0' (BSDIFF40)
            // BSDIFF40 patch
            // The signature 'BSD0' was read as u32.
            // We need to pass the patch data (starting at offset 16) to bsdiff apply.
            // But bsdiff expects "BSDIFF40" signature at the beginning of patch data.
            // Let's check if the bytes at 16 are "BSDIFF40".

            // Actually, `patch_type` read above matches `BSD0`.
            // But standard BSDIFF40 starts with "BSDIFF40".
            // Blizzard might use `BSD0` as a marker in PTCH, but the data itself is standard BSDIFF40?
            // Or maybe it's a Blizzard variant?

            // StormLib `ApplyPatch_BSDIFF` checks for "BSDIFF40" signature.
            // If `PTCH` header is present, it skips it.

            // Let's peek at bytes at 16.
            let mut sig_bytes = [0u8; 8];
            cursor.read_exact(&mut sig_bytes)?;

            if &sig_bytes == BSDIFF40_SIGNATURE {
                // It is standard BSDIFF40
                return apply_bsdiff40(base_data, &patch_data[16..], size_after as usize);
            } else {
                // Maybe it's `BSD0` + size + data?
                // Let's assume standard BSDIFF40 for now.
                return Err(MpqError::InvalidParameter);
            }
        } else {
            // Unknown patch type
            return Err(MpqError::InvalidParameter);
        }
    }

    // Check if it's a raw BSDIFF40 patch (no PTCH header)
    if patch_data.len() >= 8 && &patch_data[0..8] == BSDIFF40_SIGNATURE {
        // We don't know the expected size, so we might need to guess or rely on bsdiff header
        // BSDIFF header has `ctrl_len`, `diff_len`, `new_file_len`.
        // `new_file_len` is at offset 24 (8 bytes).

        let mut cursor = Cursor::new(patch_data);
        cursor.seek(SeekFrom::Start(24))?;
        let size_after = cursor.read_u64::<LittleEndian>()?;

        return apply_bsdiff40(base_data, patch_data, size_after as usize);
    }

    // If not a known patch format, maybe it's just a replacement file?
    // But `apply_patch` is called only if `MPQ_FILE_PATCH_FILE` flag is set.
    // If flag is set but no signature, it's weird.
    // We'll assume it's invalid.
    Err(MpqError::InvalidParameter)
}

fn apply_bsdiff40(old_data: &[u8], patch_data: &[u8], new_size: usize) -> MpqResult<Vec<u8>> {
    // BSDIFF40 Header:
    // 0   8   "BSDIFF40"
    // 8   8   ctrl_len
    // 16  8   diff_len
    // 24  8   new_file_len

    if patch_data.len() < 32 {
        return Err(MpqError::InvalidParameter);
    }

    let mut cursor = Cursor::new(patch_data);
    cursor.seek(SeekFrom::Start(8))?;

    let ctrl_len = cursor.read_u64::<LittleEndian>()? as usize;
    let diff_len = cursor.read_u64::<LittleEndian>()? as usize;
    let new_file_len = cursor.read_u64::<LittleEndian>()? as usize;

    if new_size != 0 && new_file_len != new_size {
        // Warning: Size mismatch?
    }

    let mut new_data = vec![0u8; new_file_len];

    let mut old_pos = 0;
    let mut new_pos = 0;

    // Data sections
    let ctrl_start = 32;
    let diff_start = ctrl_start + ctrl_len;
    let extra_start = diff_start + diff_len;

    if extra_start > patch_data.len() {
        return Err(MpqError::InvalidParameter);
    }

    let mut ctrl_cursor = Cursor::new(&patch_data[ctrl_start..diff_start]);
    let mut diff_cursor = Cursor::new(&patch_data[diff_start..extra_start]);
    let mut extra_cursor = Cursor::new(&patch_data[extra_start..]);

    while new_pos < new_file_len {
        // Read control block
        // 3 * 8 bytes: add_len, copy_len, seek_off

        // We need to read i64 for seek_off, u64 for lens?
        // BSDIFF uses off_t which is signed 64-bit usually.
        // But lengths are usually positive.

        // Wait, standard BSDIFF uses `off_t` for all 3.

        let add_len = match ctrl_cursor.read_i64::<LittleEndian>() {
            Ok(val) => val,
            Err(_) => break, // End of control block
        };
        let copy_len = ctrl_cursor.read_i64::<LittleEndian>()?;
        let seek_off = ctrl_cursor.read_i64::<LittleEndian>()?;

        let add_len = add_len as usize;
        let copy_len = copy_len as usize;

        // 1. Add (diff)
        // Read `add_len` from diff block and add to `old_data` at `old_pos`
        if new_pos + add_len > new_file_len {
            return Err(MpqError::InvalidParameter);
        }

        let mut diff_bytes = vec![0u8; add_len];
        diff_cursor.read_exact(&mut diff_bytes)?;

        for i in 0..add_len {
            let old_byte = if old_pos + i < old_data.len() {
                old_data[old_pos + i]
            } else {
                0
            };
            new_data[new_pos + i] = diff_bytes[i].wrapping_add(old_byte);
        }

        new_pos += add_len;
        old_pos += add_len;

        // 2. Copy (extra)
        // Read `copy_len` from extra block and copy to `new_data`
        if new_pos + copy_len > new_file_len {
            return Err(MpqError::InvalidParameter);
        }

        let mut extra_bytes = vec![0u8; copy_len];
        extra_cursor.read_exact(&mut extra_bytes)?;

        new_data[new_pos..new_pos + copy_len].copy_from_slice(&extra_bytes);

        new_pos += copy_len;
        old_pos = (old_pos as i64 + seek_off) as usize;
    }

    Ok(new_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::WriteBytesExt;

    #[test]
    fn test_apply_bsdiff40_simple() {
        let old_data = b"Hello World";
        let new_data_expected = b"Hello Patch";

        // Construct BSDIFF40 patch
        // Header: "BSDIFF40" + ctrl_len + diff_len + new_file_len
        let mut patch = Vec::new();
        patch.extend_from_slice(BSDIFF40_SIGNATURE);

        // We need to construct control, diff, and extra blocks.
        // Strategy:
        // 1. "Hello " (6 bytes): Add 6 bytes (diff=0), Copy 0 bytes.
        // 2. "Patch" (5 bytes): Add 5 bytes (diff="Patch"-"World"), Copy 0 bytes.

        let mut ctrl = Vec::new();
        let mut diff = Vec::new();
        let extra = Vec::new();

        // Block 1: "Hello "
        // Add: 6
        // Copy: 0
        // Seek: 0 (advance old_pos by 6 is implicit? No, seek_off is added AFTER copy)
        // In loop: old_pos += add_len (6). Then old_pos += seek_off.
        // So if we want to process "World" next, old_pos is already at "World" (index 6).
        // So seek_off = 0.

        ctrl.write_i64::<LittleEndian>(6).unwrap(); // add_len
        ctrl.write_i64::<LittleEndian>(0).unwrap(); // copy_len
        ctrl.write_i64::<LittleEndian>(0).unwrap(); // seek_off

        for _ in 0..6 {
            diff.push(0); // "Hello " - "Hello " = 0
        }

        // Block 2: "Patch"
        // Add: 5
        // Copy: 0
        // Seek: 0

        ctrl.write_i64::<LittleEndian>(5).unwrap(); // add_len
        ctrl.write_i64::<LittleEndian>(0).unwrap(); // copy_len
        ctrl.write_i64::<LittleEndian>(0).unwrap(); // seek_off

        let world = b"World";
        let patch_str = b"Patch";
        for i in 0..5 {
            diff.push(patch_str[i].wrapping_sub(world[i]));
        }

        // Header fields
        patch.write_u64::<LittleEndian>(ctrl.len() as u64).unwrap();
        patch.write_u64::<LittleEndian>(diff.len() as u64).unwrap();
        patch
            .write_u64::<LittleEndian>(new_data_expected.len() as u64)
            .unwrap();

        patch.extend_from_slice(&ctrl);
        patch.extend_from_slice(&diff);
        patch.extend_from_slice(&extra);

        let result = apply_bsdiff40(old_data, &patch, new_data_expected.len()).unwrap();
        assert_eq!(result, new_data_expected);
    }
}
