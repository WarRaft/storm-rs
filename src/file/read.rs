//! File reading from MPQ archives.
//! Ported from SFileReadFile.cpp

use std::io::{Read, Seek, SeekFrom};

use crate::archive::MpqArchive;
use crate::compression::decompress;
use crate::constants::*;
use crate::crypto::{calculate_file_key, decrypt_block};
use crate::error::{MpqError, MpqResult};
use crate::types::FileInfo;

/// Read a file from an MPQ archive.
pub fn read_file<R: Read + Seek>(
    reader: &mut R,
    archive: &MpqArchive,
    file_info: &FileInfo,
) -> MpqResult<Vec<u8>> {
    let flags = file_info.flags;

    // Deleted file
    if (flags & MPQ_FILE_DELETE_MARKER) != 0 {
        return Err(MpqError::FileNotFound);
    }

    // Single unit file (not split into sectors)
    if (flags & MPQ_FILE_SINGLE_UNIT) != 0 {
        return read_file_single_unit(reader, archive, file_info);
    }

    // Uncompressed file (no compression flags) - read as single unit
    // These files don't have sector offset tables
    let is_compressed = (flags & (MPQ_FILE_COMPRESS | MPQ_FILE_IMPLODE)) != 0;
    if !is_compressed {
        return read_file_single_unit(reader, archive, file_info);
    }

    // Sector-based file
    read_file_sectored(reader, archive, file_info)
}

/// Read a single-unit file (entire file compressed as one block).
fn read_file_single_unit<R: Read + Seek>(
    reader: &mut R,
    archive: &MpqArchive,
    file_info: &FileInfo,
) -> MpqResult<Vec<u8>> {
    let flags = file_info.flags;
    let compressed_size = file_info.compressed_size as usize;
    let file_size = file_info.file_size as usize;

    // Seek to file data
    reader.seek(SeekFrom::Start(file_info.offset))?;

    // Read raw data
    let mut raw_data = vec![0u8; compressed_size];
    reader.read_exact(&mut raw_data)?;

    // Decrypt if needed
    if (flags & MPQ_FILE_ENCRYPTED) != 0 {
        let file_key = calculate_file_key(
            &file_info.name,
            file_info.offset - archive.mpq_offset,
            file_info.file_size,
            flags,
        );
        decrypt_block(&mut raw_data, file_key);
    }

    // Decompress if needed
    if (flags & (MPQ_FILE_COMPRESS | MPQ_FILE_IMPLODE)) != 0 && compressed_size < file_size {
        return decompress(&raw_data, file_size, flags);
    }

    Ok(raw_data)
}

/// Read a sector-based file.
fn read_file_sectored<R: Read + Seek>(
    reader: &mut R,
    archive: &MpqArchive,
    file_info: &FileInfo,
) -> MpqResult<Vec<u8>> {
    let flags = file_info.flags;
    let file_size = file_info.file_size as usize;
    let sector_size = archive.sector_size as usize;

    // Calculate number of sectors
    let num_sectors = file_size.div_ceil(sector_size);

    // Read sector offset table
    let sector_offsets = read_sector_offsets(reader, archive, file_info, num_sectors)?;

    // Allocate output buffer
    let mut output = Vec::with_capacity(file_size);

    // Calculate file key if encrypted
    let file_key = if (flags & MPQ_FILE_ENCRYPTED) != 0 {
        calculate_file_key(
            &file_info.name,
            file_info.offset - archive.mpq_offset,
            file_info.file_size,
            flags,
        )
    } else {
        0
    };

    // Read each sector
    for i in 0..num_sectors {
        let sector_start = sector_offsets[i] as usize;
        let sector_end = sector_offsets[i + 1] as usize;

        // Check for invalid sector offsets
        if sector_end < sector_start {
            return Err(MpqError::DecompressionFailed);
        }
        let sector_compressed_size = sector_end - sector_start;

        if sector_compressed_size == 0 {
            continue; // Empty sector
        }

        // Calculate expected uncompressed size for this sector
        let bytes_remaining = file_size.saturating_sub(output.len());
        let sector_uncompressed_size = bytes_remaining.min(sector_size);

        // Read sector data
        reader.seek(SeekFrom::Start(file_info.offset + sector_start as u64))?;
        let mut sector_data = vec![0u8; sector_compressed_size];
        reader.read_exact(&mut sector_data)?;

        // Decrypt if needed
        if (flags & MPQ_FILE_ENCRYPTED) != 0 {
            let sector_key = file_key.wrapping_add(i as u32);
            decrypt_block(&mut sector_data, sector_key);
        }

        // Decompress if needed
        if (flags & (MPQ_FILE_COMPRESS | MPQ_FILE_IMPLODE)) != 0
            && sector_compressed_size < sector_uncompressed_size
        {
            let decompressed = decompress(&sector_data, sector_uncompressed_size, flags)?;
            output.extend_from_slice(&decompressed);
        } else {
            output.extend_from_slice(&sector_data);
        }
    }

    Ok(output)
}

/// Read the sector offset table.
fn read_sector_offsets<R: Read + Seek>(
    reader: &mut R,
    archive: &MpqArchive,
    file_info: &FileInfo,
    num_sectors: usize,
) -> MpqResult<Vec<u32>> {
    let flags = file_info.flags;

    // Number of offsets is sectors + 1 (to get size of last sector)
    // Plus optional CRC entries
    let has_sector_crc = (flags & MPQ_FILE_SECTOR_CRC) != 0;
    let offset_count = if has_sector_crc {
        num_sectors + 2
    } else {
        num_sectors + 1
    };

    // Read offset table
    reader.seek(SeekFrom::Start(file_info.offset))?;
    let mut offset_data = vec![0u8; offset_count * 4];
    reader.read_exact(&mut offset_data)?;

    // Decrypt if needed
    if (flags & MPQ_FILE_ENCRYPTED) != 0 {
        let file_key = calculate_file_key(
            &file_info.name,
            file_info.offset - archive.mpq_offset,
            file_info.file_size,
            flags,
        );
        // Sector offset table is encrypted with key - 1
        decrypt_block(&mut offset_data, file_key.wrapping_sub(1));
    }

    // Parse offsets
    let mut offsets = Vec::with_capacity(offset_count);
    for i in 0..offset_count {
        let offset_bytes = &offset_data[i * 4..i * 4 + 4];
        offsets.push(u32::from_le_bytes([
            offset_bytes[0],
            offset_bytes[1],
            offset_bytes[2],
            offset_bytes[3],
        ]));
    }

    Ok(offsets)
}
