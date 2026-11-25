//! Archive compaction: the space of files replaced or removed given back.
//!
//! As StormLib's `SFileCompactArchive`, and safe for maps:
//!
//! - what's before the MPQ header (a map's `HM3W` header, a user data
//!   block) is kept as it is;
//! - the hash table is kept entry for entry, and the block table index for
//!   index (`(attributes)` is by block index): only where each file's data
//!   lies changes, packed in the order it was. A block no hash entry
//!   points at is emptied;
//! - no file needs its name: the data is moved as it is, but a file
//!   encrypted with a key of its place (`MPQ_FILE_KEY_V2`), which is
//!   decrypted with its key and encrypted with the key of its new place.
//!   The key comes from its name when the archive knows it, else from its
//!   data as StormLib finds it (the sector offset table, or a known
//!   start: WAVE, EXE, XML). One whose key can't be found fails the
//!   compaction, and the archive is left as it was.
//!
//! Archives with HET/BET tables or 64-bit offsets (version 2 and later's
//! hi-block table) aren't compacted.

use std::fs::{self, File};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::archive::{MpqArchive, write_block_table, write_hash_table, write_mpq_header};
use crate::constants::*;
use crate::crypto::{
    calculate_file_key, decrypt_block, detect_file_key_by_content, detect_file_key_by_sector_size,
    encrypt_block,
};
use crate::error::{MpqError, MpqResult};
use crate::types::MpqBlock;

/// Compact the archive at `path` in place: written to a file beside it,
/// which then replaces it. On an error the archive is as it was.
pub fn compact_archive<P: AsRef<Path>>(path: P) -> MpqResult<()> {
    let path = path.as_ref();
    let temp = path.with_extension("compacting");
    match compact_to(path, &temp) {
        Ok(()) => {
            fs::rename(&temp, path)?;
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&temp);
            Err(e)
        }
    }
}

fn invalid(message: &str) -> MpqError {
    MpqError::Generic(message.to_string())
}

/// The key the file at block `index` is encrypted with, where it lies now.
fn file_key(archive: &MpqArchive, index: usize, block: &MpqBlock, raw: &[u8]) -> MpqResult<u32> {
    if let Some(name) = archive.get_filename_by_block_index(index) {
        return Ok(calculate_file_key(&name, block.file_pos as u64, block.file_size, block.flags));
    }
    let compressed = block.flags & (MPQ_FILE_COMPRESS | MPQ_FILE_IMPLODE) != 0;
    let found = if compressed && block.flags & MPQ_FILE_SINGLE_UNIT == 0 {
        let sectors = block.file_size.div_ceil(archive.sector_size);
        let entries = sectors + 1 + u32::from(block.flags & MPQ_FILE_SECTOR_CRC != 0);
        detect_file_key_by_sector_size(raw, archive.sector_size, entries * 4)
    } else {
        detect_file_key_by_content(raw, archive.sector_size, block.file_size)
    };
    found.ok_or_else(|| {
        MpqError::Generic(format!(
            "block {index} is encrypted with a key of its place, and neither its name nor its key can be found: it can't be moved"
        ))
    })
}

/// `raw` (a file's data as stored, encrypted with `old`) encrypted with
/// `new` instead, sector by sector as it's stored.
fn rekey(raw: &mut [u8], block: &MpqBlock, sector_size: u32, old: u32, new: u32) -> MpqResult<()> {
    if block.flags & MPQ_FILE_SINGLE_UNIT != 0 {
        decrypt_block(raw, old);
        encrypt_block(raw, new);
        return Ok(());
    }
    let compressed = block.flags & (MPQ_FILE_COMPRESS | MPQ_FILE_IMPLODE) != 0;
    if !compressed {
        // Sectors of `sector_size`, each with its own key.
        crate::crypto::crypt_file_data(raw, old, sector_size, false, true);
        crate::crypto::crypt_file_data(raw, new, sector_size, false, false);
        return Ok(());
    }
    // The sector offset table (key - 1), then each sector (key + i); the
    // sectors' CRCs after them aren't encrypted.
    let sectors = block.file_size.div_ceil(sector_size) as usize;
    let entries = sectors + 1 + usize::from(block.flags & MPQ_FILE_SECTOR_CRC != 0);
    let table_len = entries * 4;
    if raw.len() < table_len {
        return Err(invalid("a file shorter than its sector offset table"));
    }
    decrypt_block(&mut raw[..table_len], old.wrapping_sub(1));
    let offsets: Vec<usize> =
        raw[..table_len].chunks(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]) as usize).collect();
    encrypt_block(&mut raw[..table_len], new.wrapping_sub(1));
    for i in 0..sectors {
        let (start, end) = (offsets[i], offsets[i + 1]);
        if start > end || end > raw.len() {
            return Err(invalid("a sector offset table that doesn't fit its file"));
        }
        decrypt_block(&mut raw[start..end], old.wrapping_add(i as u32));
        encrypt_block(&mut raw[start..end], new.wrapping_add(i as u32));
    }
    Ok(())
}

/// The archive at `path` compacted, written to `temp`.
fn compact_to(path: &Path, temp: &Path) -> MpqResult<()> {
    let archive = MpqArchive::open(path)?;
    if archive.het_table.is_some() || archive.bet_table.is_some() {
        return Err(invalid("an archive with HET/BET tables isn't compacted"));
    }
    if archive.hi_block_table.iter().any(|&h| h != 0) {
        return Err(invalid("an archive with 64-bit offsets isn't compacted"));
    }
    // The header's size of its version: a protected map's says anything
    // (the game reads a version 1 header's 32 bytes whatever it says).
    let header_size: u32 = match archive.header.format_version {
        0 => 32,
        1 => 44,
        _ => 208,
    };

    // What's before the MPQ header, as it is.
    let mut prefix = vec![0u8; archive.mpq_offset as usize];
    File::open(path)?.read_exact(&mut prefix)?;

    // The blocks some hash entry points at, in the order their data lies.
    let mut used = vec![false; archive.block_table.len()];
    for h in &archive.hash_table {
        if h.block_index != HASH_ENTRY_DELETED && h.block_index != HASH_ENTRY_FREE && (h.block_index as usize) < used.len() {
            used[h.block_index as usize] = true;
        }
    }
    let mut order: Vec<usize> =
        (0..used.len()).filter(|&i| used[i] && archive.block_table[i].flags & MPQ_FILE_EXISTS != 0).collect();
    order.sort_by_key(|&i| (archive.block_table[i].file_pos, i));

    // The spans the blocks' data covers, overlapping ones (a protected
    // map's blocks sharing data) one span: each moved whole, a block with
    // its span, so data shared stays shared. Only the gaps go.
    let range = |i: usize| {
        let b = &archive.block_table[i];
        (b.file_pos as u64, b.file_pos as u64 + b.compressed_size as u64)
    };
    let mut spans: Vec<(u64, u64, Vec<usize>)> = Vec::new();
    for &i in &order {
        let (start, end) = range(i);
        match spans.last_mut() {
            Some(s) if start < s.1 || (start == s.0 && start == end) => {
                s.1 = s.1.max(end);
                s.2.push(i);
            }
            _ => spans.push((start, end, vec![i])),
        }
    }

    let mut writer = BufWriter::new(File::create(temp)?);
    writer.write_all(&prefix)?;
    // The header, written again at the end.
    writer.write_all(&vec![0u8; header_size as usize])?;
    let mut pos = header_size;
    let mut blocks: Vec<MpqBlock> =
        archive.block_table.iter().map(|_| MpqBlock { file_pos: 0, compressed_size: 0, file_size: 0, flags: 0 }).collect();
    for (start, end, members) in &spans {
        let len = u32::try_from(end - start).map_err(|_| invalid("a block past 4 GB"))?;
        let mut data = archive.read_raw_block(&MpqBlock { file_pos: *start as u32, compressed_size: len, file_size: len, flags: 0 })?;
        let shift = |p: u32| pos.wrapping_add(p - *start as u32);
        for &i in members {
            let block = archive.block_table[i];
            let new_pos = shift(block.file_pos);
            if block.flags & MPQ_FILE_ENCRYPTED != 0 && block.flags & MPQ_FILE_KEY_V2 != 0 && block.file_pos != new_pos {
                // Its bytes are its own: it's encrypted again for its place.
                if members.len() > 1 {
                    return Err(invalid("a file encrypted with a key of its place shares its data with another: it can't be moved"));
                }
                let raw = &mut data[..];
                let old = file_key(&archive, i, &block, raw)?;
                // The key without its place: (base + place) ^ size.
                let base = (old ^ block.file_size).wrapping_sub(block.file_pos);
                let new = base.wrapping_add(new_pos) ^ block.file_size;
                rekey(raw, &block, archive.sector_size, old, new)?;
            }
            blocks[i] = MpqBlock { file_pos: new_pos, ..block };
        }
        writer.write_all(&data)?;
        pos = pos.checked_add(len).ok_or_else(|| invalid("the archive would be past 4 GB"))?;
    }
    // A block nothing points at: empty, at the end of the data.
    for b in blocks.iter_mut().filter(|b| b.flags == 0) {
        b.file_pos = pos;
    }

    let mut hash_table = archive.hash_table.clone();
    let hash_table_size = archive.header.hash_table_size;
    let hash_table_pos = pos;
    write_hash_table(&mut writer, &mut hash_table, hash_table_size)?;
    pos += hash_table_size * 16;
    let block_table_pos = pos;
    let block_count = blocks.len() as u32;
    write_block_table(&mut writer, &mut blocks)?;
    pos += block_count * 16;

    writer.seek(SeekFrom::Start(archive.mpq_offset))?;
    write_mpq_header(
        &mut writer,
        &crate::archive::MpqCreateOptions {
            format_version: archive.header.format_version,
            sector_size: archive.sector_size,
            ..Default::default()
        },
        header_size,
        hash_table_size,
        hash_table_pos,
        block_table_pos,
        block_count,
        pos,
        0,
        0,
        0,
        0,
    )?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
#[path = "compact.test.rs"]
mod tests;
