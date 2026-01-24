use std::io::{Read, Write};

/// Lightweight wrapper over `lzma-rust2` to provide the exact payload layout
/// expected by StormLib/MPQ: 1 byte props + 4 bytes dict size (LE) + compressed data.

/// Compress input using lzma-rust2 and return payload in MPQ-compatible format
/// (props byte + dict size LE + compressed data).
pub fn compress_lzma_mpq(input: &[u8]) -> Result<Vec<u8>, String> {
    // Use preset level 5 and keep dict size compatible with reference (16MB)
    let mut opts = lzma_rust2::LzmaOptions::with_preset(5);
    opts.dict_size = 0x0100_0000u32;

    // Create a writer without .lzma header and WITHOUT end marker to match StormLib behavior.
    let mut writer = lzma_rust2::LzmaWriter::new_no_header(Vec::new(), &opts, false)
        .map_err(|e| format!("LzmaWriter::new_no_header failed: {:?}", e))?;
    writer
        .write_all(input)
        .map_err(|e| format!("LzmaWriter write failed: {:?}", e))?;
    let compressed = writer.finish().map_err(|e| format!("LzmaWriter finish failed: {:?}", e))?;

    // encoded props: 1 byte props + 4 bytes dict size little-endian (total 5 bytes)
    let props = opts.get_props();
    let dict_le = opts.dict_size.to_le_bytes();

    // Default MPQ-compatible payload: include MPQ-style LZMA header
    // (useFilter=0) + props(1) + dict_size LE(4) + original size (8 bytes) + compressed...
    // StormLib expects MPQ-style LZMA sectors to have the leading useFilter byte set to 0.
    let mut payload = Vec::with_capacity(1 + 5 + 8 + compressed.len());
    payload.push(0u8); // useFilter = 0
    payload.push(props);
    payload.extend_from_slice(&dict_le);
    let src_len = input.len() as u32;
    payload.extend_from_slice(&src_len.to_le_bytes());
    payload.extend_from_slice(&[0u8; 4]);
    payload.extend_from_slice(&compressed);
    Ok(payload)
}

/// Variant that includes MPQ-style LZMA header (useFilter + props + dict + 8-byte orig size)
/// Keep this helper for tests or tools that need the full LZMA header layout.
pub fn compress_lzma_mpq_with_header(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut opts = lzma_rust2::LzmaOptions::with_preset(5);
    opts.dict_size = 0x0100_0000u32;
    let mut writer = lzma_rust2::LzmaWriter::new_no_header(Vec::new(), &opts, false)
        .map_err(|e| format!("LzmaWriter::new_no_header failed: {:?}", e))?;
    writer
        .write_all(input)
        .map_err(|e| format!("LzmaWriter write failed: {:?}", e))?;
    let compressed = writer.finish().map_err(|e| format!("LzmaWriter finish failed: {:?}", e))?;

    let props = opts.get_props();
    let dict_le = opts.dict_size.to_le_bytes();

    let mut payload = Vec::with_capacity(1 + 5 + 8 + compressed.len());
    payload.push(0u8); // useFilter = 0
    payload.push(props);
    payload.extend_from_slice(&dict_le);
    let src_len = input.len() as u32;
    payload.extend_from_slice(&src_len.to_le_bytes());
    payload.extend_from_slice(&[0u8; 4]);
    payload.extend_from_slice(&compressed);
    Ok(payload)
}

/// Generic compress -> returns props+dict_size+compressed
pub fn compress_lzma(input: &[u8]) -> Result<Vec<u8>, String> {
    compress_lzma_mpq(input)
}

/// Decompress data that is in StormLib/MPQ-compatible LZMA format:
/// expects at least 5 bytes: 1 props + 4 bytes dict size LE, followed by raw compressed bytes.
pub fn decompress_lzma(input: &[u8], expected_output_size: usize) -> Result<Vec<u8>, String> {
    if input.len() < 5 {
        return Err("input too small for LZMA payload".to_string());
    }

    // Support both formats:
    // 1) Raw LZMA: props(1) + dict_size LE(4) + compressed...
    // 2) MPQ LZMA: useFilter(1==0) + props(1) + dict_size LE(4) + orig_size(8) + compressed...
    let (props, dict_size, compressed) = if input.len() >= 14 && input[0] == 0 {
        // MPQ-style header detected
        let props = input[1];
        let dict_size = u32::from_le_bytes([input[2], input[3], input[4], input[5]]);
        let compressed = &input[14..];
        (props, dict_size, compressed)
    } else {
        // Raw props-only format
        let props = input[0];
        let dict_size = u32::from_le_bytes([input[1], input[2], input[3], input[4]]);
        let compressed = &input[5..];
        (props, dict_size, compressed)
    };

    // lzma-rust2 doesn't require passing props explicitly for raw streams in reader-based API;
    // we'll attempt to use its decompression convenience function(s).
    // Try a few known APIs - prefer a direct decompress function if available.

    // 1) Try lzma_rust2::lzma::decompress (if exists)
    #[allow(unused_imports)]
    use lzma_rust2 as lr;

    // Many lzma APIs operate on readers. Use in-memory reader.
    // We construct a reader that will decode the *raw* LZMA stream (no header).

    // lzma-rust2 provides an LzmaReader in many versions. We'll try to use it if available.
    // Fallback: try lr::lzma::decompress if present (compile-time will show what's available).

    let mut out = Vec::with_capacity(expected_output_size);

    let mut errors: Vec<String> = Vec::new();

    // Attempt 1: new_with_props with expected size
    {
        let cursor = std::io::Cursor::new(compressed);
        match lr::LzmaReader::new_with_props(cursor, expected_output_size as u64, props, dict_size, None) {
            Ok(mut rdr) => {
                if let Err(e) = rdr.read_to_end(&mut out) {
                    errors.push(format!("read_to_end failed (new_with_props): {:?}", e));
                } else {
                    return Ok(out);
                }
            }
            Err(e) => errors.push(format!("new_with_props failed: {:?}", e)),
        }
    }

    // Attempt 2: new_with_props with uncomp_size = 0 (some streams omit size)
    {
        let cursor = std::io::Cursor::new(compressed);
        match lr::LzmaReader::new_with_props(cursor, 0u64, props, dict_size, None) {
            Ok(mut rdr) => {
                if let Err(e) = rdr.read_to_end(&mut out) {
                    errors.push(format!("read_to_end failed (new_with_props size=0): {:?}", e));
                } else {
                    return Ok(out);
                }
            }
            Err(e) => errors.push(format!("new_with_props(size=0) failed: {:?}", e)),
        }
    }

    // Attempt 3: parse props into lc/lp/pb and use LzmaReader::new
    {
        // decode props: props = pb*45 + lp*9 + lc
        let lc = (props % 9) as u32;
        let rem = props / 9;
        let lp = (rem % 5) as u32;
        let pb = (rem / 5) as u32;
        let cursor = std::io::Cursor::new(compressed);
        match lr::LzmaReader::new(cursor, expected_output_size as u64, lc, lp, pb, dict_size, None) {
            Ok(mut rdr) => {
                if let Err(e) = rdr.read_to_end(&mut out) {
                    errors.push(format!("read_to_end failed (new lc/lp/pb): {:?}", e));
                } else {
                    return Ok(out);
                }
            }
            Err(e) => errors.push(format!("LzmaReader::new failed (lc/lp/pb): {:?}", e)),
        }
    }

    // Attempt 4: new_mem_limit (try with some memory limit)
    {
        let cursor = std::io::Cursor::new(compressed);
        match lr::LzmaReader::new_mem_limit(cursor, 512 * 1024, None) {
            Ok(mut rdr) => {
                if let Err(e) = rdr.read_to_end(&mut out) {
                    errors.push(format!("read_to_end failed (new_mem_limit): {:?}", e));
                } else {
                    return Ok(out);
                }
            }
            Err(e) => errors.push(format!("new_mem_limit failed: {:?}", e)),
        }
    }

    // All attempts failed
    Err(format!("All decompression attempts failed: {}", errors.join("; ")))

}
