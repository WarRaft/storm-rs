//! LZMA compression for MPQ archives.
//! Uses lzma-rust2 for better control over dictionary size and headers.

use std::io::Cursor;
use std::io::Write;

/// Decompress LZMA data.
///
/// StormLib prepends a 1-byte filter flag (must be 0) to the standard LZMA stream.
/// The rest is a standard LZMA stream (Properties + Size + Data).
pub fn decompress_lzma(input: &[u8], expected_output_size: usize) -> Result<Vec<u8>, &'static str> {
    if input.is_empty() {
        return Err("LZMA: input too short");
    }

    // Byte 0 is the filter flag. StormLib only supports 0.
    if input[0] != 0 {
        return Err("LZMA: unsupported filter");
    }

    // The rest is a standard LZMA stream.
    let mut reader = Cursor::new(&input[1..]);
    let mut output = Vec::with_capacity(expected_output_size);

    // lzma-rust2 decompression
    // We use LzmaReader for decompression
    // new_mem_limit reads the header from the stream if props is None
    let mut decoder = lzma_rust2::LzmaReader::new_mem_limit(&mut reader, u32::MAX, None)
        .map_err(|_| "LZMA: failed to create decompressor")?;

    std::io::copy(&mut decoder, &mut output).map_err(|_| "LZMA: decompression failed")?;

    Ok(output)
}

/// Compress data using LZMA.
///
/// StormLib prepends a 1-byte filter flag (0) to the standard LZMA stream.
/// The standard LZMA stream starts with a header:
/// [Properties (1 byte)] [Dictionary Size (4 bytes)] [Uncompressed Size (8 bytes)]
pub fn compress_lzma(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut temp_output = Vec::new();

    // Configure LZMA options
    // We set dictionary size to 64KB (safer for small files, and sufficient)
    let options = lzma_rust2::LzmaOptions {
        dict_size: 16 * 1024 * 1024,
        lc: 3,
        lp: 0,
        pb: 2,
        mode: lzma_rust2::EncodeMode::Normal,
        nice_len: 32,
        mf: lzma_rust2::MfType::Bt4,
        depth_limit: 32,
        ..Default::default()
    };

    // Create encoder
    // API: new(out, options, use_header, use_end_marker, expected_uncompressed_size)
    {
        let mut encoder = lzma_rust2::LzmaWriter::new(
            &mut temp_output,
            &options,
            true,  // use_header: Write standard LZMA header [Props][Dict][Size]
            false, // use_end_marker: Enable EOS marker
            Some(input.len() as u64), // expected_uncompressed_size
        )
        .map_err(|_| "LZMA: failed to create encoder")?;

        encoder
            .write_all(input)
            .map_err(|_| "LZMA: compression failed")?;
        encoder.finish().map_err(|_| "LZMA: finish failed")?;
    }

    // temp_output now contains the standard LZMA stream.
    // We need to prepend the filter byte (0).

    if temp_output.len() < 13 {
        return Err("LZMA: output too short");
    }

    let mut final_output = Vec::with_capacity(1 + temp_output.len());
    final_output.push(0);
    final_output.extend_from_slice(&temp_output);

    Ok(final_output)
}
