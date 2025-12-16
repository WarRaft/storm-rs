//! Compression/decompression module for MPQ archives.
//! Ported from SCompression.cpp

mod adpcm;
mod huffman;
pub mod lzma;
mod pkware;
mod sparse;

pub use pkware::explode as pkware_explode;

use crate::constants::*;
use crate::error::{MpqError, MpqResult};

/// Decompress data using the specified compression method(s).
///
/// MPQ files can use multiple compression methods in sequence.
/// The first byte of compressed data indicates the compression mask.
///
/// # Arguments
/// * `input` - Compressed data (including compression type byte for multi-compression).
/// * `output_size` - Expected uncompressed size.
/// * `compression_type` - Compression type from file flags.
///
/// # Returns
/// Decompressed data.
pub fn decompress(input: &[u8], output_size: usize, compression_type: u32) -> MpqResult<Vec<u8>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    // Check if imploded (PKWARE DCL)
    if (compression_type & MPQ_FILE_IMPLODE) != 0 {
        return decompress_pkware(input, output_size);
    }

    // Multi-compression: first byte is compression mask
    if (compression_type & MPQ_FILE_COMPRESS) != 0 {
        // For general compression, first byte tells us which algorithms were used
        let cmp_type = input[0];
        let data = &input[1..];

        return decompress_multi(data, output_size, cmp_type);
    }

    // No compression, return as-is
    Ok(input.to_vec())
}

/// Decompress data with multiple compression algorithms.
///
/// The compression mask indicates which algorithms were applied, in this order:
/// 1. Sparse (0x20) - Run-length decompression
/// 2. LZMA (0x12) - LZMA decompression
/// 3. BZip2 (0x10) - BZip2 decompression  
/// 4. PKWARE (0x08) - PKWARE DCL decompression
/// 5. ZLIB (0x02) - ZLIB decompression
/// 6. Huffman (0x01) - Huffman decompression
/// 7. ADPCM Stereo (0x80) - IMA ADPCM stereo
/// 8. ADPCM Mono (0x40) - IMA ADPCM mono
fn decompress_multi(data: &[u8], output_size: usize, cmp_type: u8) -> MpqResult<Vec<u8>> {
    log::trace!(
        "decompress_multi: cmp_type=0x{:02X}, input_size={}, expected_output={}",
        cmp_type,
        data.len(),
        output_size
    );

    // Use owned data throughout the chain to avoid lifetime issues
    let mut current_data: Vec<u8> = data.to_vec();

    // LZMA (0x12) - special case, not a bitmask
    if cmp_type == MPQ_COMPRESSION_LZMA {
        log::trace!("  Applying LZMA decompression");
        return decompress_lzma(&current_data, output_size);
    }

    // Sparse decompression (0x20)
    if (cmp_type & MPQ_COMPRESSION_SPARSE) != 0 {
        log::trace!("  Applying Sparse decompression");
        current_data = decompress_sparse_internal(&current_data, output_size)?;
    }

    // BZip2 decompression (0x10)
    if (cmp_type & MPQ_COMPRESSION_BZIP2) != 0 {
        log::trace!("  Applying BZip2 decompression");
        current_data = decompress_bzip2(&current_data, output_size)?;
    }

    // PKWARE DCL decompression (0x08)
    if (cmp_type & MPQ_COMPRESSION_PKWARE) != 0 {
        log::trace!("  Applying PKWARE DCL decompression");
        current_data = decompress_pkware(&current_data, output_size)?;
    }

    // ZLIB decompression (0x02)
    if (cmp_type & MPQ_COMPRESSION_ZLIB) != 0 {
        log::trace!("  Applying ZLIB decompression");
        current_data = decompress_zlib(&current_data, output_size)?;
    }

    // Huffman decompression (0x01)
    if (cmp_type & MPQ_COMPRESSION_HUFFMANN) != 0 {
        log::trace!("  Applying Huffman decompression");
        // When ADPCM follows Huffman, we need to let Huffman decompress fully
        // because ADPCM will further expand the data (ratio ~4:1)
        let has_adpcm =
            (cmp_type & (MPQ_COMPRESSION_ADPCM_STEREO | MPQ_COMPRESSION_ADPCM_MONO)) != 0;
        let huff_output_size = if has_adpcm {
            // Huffman output is ADPCM data, which is ~1/4 of final PCM size
            // Use a larger buffer to not truncate prematurely
            output_size // Let Huffman decompress until its natural end (0x100 marker)
        } else {
            output_size
        };
        current_data = decompress_huffman_internal(&current_data, huff_output_size)?;
        if current_data.len() >= 4 {
            log::trace!(
                "Huffman output (ADPCM input) prefix: {:02X?}",
                &current_data[..4]
            );
        }
    }

    // ADPCM Stereo (0x80)
    if (cmp_type & MPQ_COMPRESSION_ADPCM_STEREO) != 0 {
        log::trace!("  Applying ADPCM Stereo decompression");
        current_data = decompress_adpcm_internal(&current_data, output_size, 2)?;
    }

    // ADPCM Mono (0x40)
    if (cmp_type & MPQ_COMPRESSION_ADPCM_MONO) != 0 {
        log::trace!("  Applying ADPCM Mono decompression");
        current_data = decompress_adpcm_internal(&current_data, output_size, 1)?;
    }

    log::trace!(
        "  Decompression complete, output_size={}",
        current_data.len()
    );
    Ok(current_data)
}

/// Decompress PKWARE DCL data.
fn decompress_pkware(input: &[u8], output_size: usize) -> MpqResult<Vec<u8>> {
    pkware::explode(input, output_size).map_err(|_| MpqError::DecompressionFailed)
}

/// Decompress ZLIB data.
fn decompress_zlib(input: &[u8], output_size: usize) -> MpqResult<Vec<u8>> {
    use std::io::Read;

    let mut decoder = flate2::read::ZlibDecoder::new(input);
    let mut output = Vec::with_capacity(output_size);
    decoder
        .read_to_end(&mut output)
        .map_err(|_| MpqError::DecompressionFailed)?;
    Ok(output)
}

/// Decompress BZip2 data.
fn decompress_bzip2(input: &[u8], output_size: usize) -> MpqResult<Vec<u8>> {
    use std::io::Read;

    let mut decoder = bzip2::read::BzDecoder::new(input);
    let mut output = Vec::with_capacity(output_size);
    decoder
        .read_to_end(&mut output)
        .map_err(|_| MpqError::DecompressionFailed)?;
    Ok(output)
}

/// Decompress LZMA data.
fn decompress_lzma(input: &[u8], output_size: usize) -> MpqResult<Vec<u8>> {
    lzma::decompress_lzma(input, output_size).map_err(|_| MpqError::DecompressionFailed)
}

/// Decompress Huffman data.
fn decompress_huffman_internal(input: &[u8], output_size: usize) -> MpqResult<Vec<u8>> {
    log::trace!(
        "Huffman: input_size={}, output_size={}",
        input.len(),
        output_size
    );
    let result = huffman::decompress_huffman(input, output_size).map_err(|e| {
        log::warn!("Huffman decompression failed: {}", e);
        MpqError::DecompressionFailed
    })?;
    log::trace!("Huffman: output={} bytes", result.len());
    Ok(result)
}

/// Decompress sparse (run-length) data.
fn decompress_sparse_internal(input: &[u8], output_size: usize) -> MpqResult<Vec<u8>> {
    sparse::decompress_sparse(input, output_size).map_err(|_| MpqError::DecompressionFailed)
}

/// Decompress IMA ADPCM audio data.
fn decompress_adpcm_internal(input: &[u8], output_size: usize, channels: u8) -> MpqResult<Vec<u8>> {
    log::trace!(
        "ADPCM: input_size={}, output_size={}, channels={}",
        input.len(),
        output_size,
        channels
    );
    adpcm::decompress_adpcm(input, output_size, channels as usize).map_err(|e| {
        log::warn!("ADPCM decompression failed: {}", e);
        MpqError::DecompressionFailed
    })
}

// =============================================================================
// Compression functions (for writing MPQs)
// =============================================================================

/// Compress data using ZLIB.
pub fn compress_zlib(input: &[u8]) -> MpqResult<Vec<u8>> {
    compress_zlib_level(input, flate2::Compression::default())
}

/// Compress data using ZLIB with specified compression level.
pub fn compress_zlib_level(input: &[u8], level: flate2::Compression) -> MpqResult<Vec<u8>> {
    use std::io::Write;

    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), level);
    encoder
        .write_all(input)
        .map_err(|_| MpqError::CompressionFailed)?;
    encoder.finish().map_err(|_| MpqError::CompressionFailed)
}

/// Compress data using BZip2.
pub fn compress_bzip2(input: &[u8]) -> MpqResult<Vec<u8>> {
    compress_bzip2_level(input, bzip2::Compression::default())
}

/// Compress data using BZip2 with specified compression level.
pub fn compress_bzip2_level(input: &[u8], level: bzip2::Compression) -> MpqResult<Vec<u8>> {
    use std::io::Write;

    let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), level);
    encoder
        .write_all(input)
        .map_err(|_| MpqError::CompressionFailed)?;
    encoder.finish().map_err(|_| MpqError::CompressionFailed)
}

/// Compress data using LZMA.
pub fn compress_lzma(input: &[u8]) -> MpqResult<Vec<u8>> {
    lzma::compress_lzma(input).map_err(|_| MpqError::CompressionFailed)
}

/// Compress data using Sparse (run-length encoding).
pub fn compress_sparse(input: &[u8]) -> Vec<u8> {
    sparse::compress_sparse(input)
}

/// Compress data with the specified compression mask.
/// Returns the compressed data with compression type byte prepended.
pub fn compress(input: &[u8], compression_mask: u8) -> MpqResult<Vec<u8>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let mut current_data = input.to_vec();

    // Apply compressions in reverse order (output is applied first during decompress)
    // ADPCM is for audio only, skip in generic compression

    // LZMA (0x12) - Special case
    // If the mask is EXACTLY LZMA, we only do LZMA and skip others that might overlap bit-wise
    // (LZMA 0x12 overlaps with ZLIB 0x02 and BZip2 0x10)
    if compression_mask == MPQ_COMPRESSION_LZMA {
        current_data = compress_lzma(&current_data)?;
    } else {
        // ZLIB (0x02)
        if (compression_mask & MPQ_COMPRESSION_ZLIB) != 0 {
            current_data = compress_zlib(&current_data)?;
        }

        // BZip2 (0x10)
        if (compression_mask & MPQ_COMPRESSION_BZIP2) != 0 {
            current_data = compress_bzip2(&current_data)?;
        }
    }

    // Sparse (0x20)
    if (compression_mask & MPQ_COMPRESSION_SPARSE) != 0 {
        current_data = compress_sparse(&current_data);
    }

    // LZMA (0x12) - already handled above if exclusive.
    // If it's mixed with others (which shouldn't happen for standard MPQ), we might have skipped it.
    // But standard practice is LZMA is exclusive or with Sparse.
    // If we want to support mixed, we need to be careful about order.
    // For now, exclusive handling fixes the bug.

    // ADPCM Stereo (0x80)
    if (compression_mask & MPQ_COMPRESSION_ADPCM_STEREO) != 0 {
        current_data = adpcm::compress_adpcm(&current_data, 2)?;
    }

    // ADPCM Mono (0x40)
    if (compression_mask & MPQ_COMPRESSION_ADPCM_MONO) != 0 {
        current_data = adpcm::compress_adpcm(&current_data, 1)?;
    }

    // Huffman (0x01)
    if (compression_mask & MPQ_COMPRESSION_HUFFMANN) != 0 {
        current_data =
            huffman::compress_huffman(&current_data).map_err(|_| MpqError::CompressionFailed)?;
    }

    // PKWARE (0x08)
    if (compression_mask & MPQ_COMPRESSION_PKWARE) != 0 {
        // Use binary mode and 4KB dictionary by default (standard for MPQ)
        current_data = pkware::implode(&current_data, pkware::CMP_BINARY, 4096)
            .map_err(|_| MpqError::CompressionFailed)?;
    }

    // Prepend compression type byte
    let mut result = Vec::with_capacity(current_data.len() + 1);
    result.push(compression_mask);
    result.extend(current_data);

    Ok(result)
}

/// Choose best compression method based on data size.
/// Returns (compressed_data, compression_flags).
pub fn auto_compress(input: &[u8]) -> MpqResult<(Vec<u8>, u32)> {
    if input.len() < 32 {
        // Too small to benefit from compression
        return Ok((input.to_vec(), 0));
    }

    // Try ZLIB compression (most common for MPQ)
    let zlib_compressed = compress(input, MPQ_COMPRESSION_ZLIB)?;

    // Only use compression if it actually made data smaller
    if zlib_compressed.len() < input.len() {
        Ok((zlib_compressed, MPQ_FILE_COMPRESS))
    } else {
        Ok((input.to_vec(), 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompress_empty() {
        let result = decompress(&[], 0, 0);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
