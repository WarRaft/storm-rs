//! Sparse (run-length) compression for MPQ archives.
//! Ported from StormLib/src/sparse/sparse.cpp

/// Decompress sparse data.
///
/// Sparse compression stores runs of zeros efficiently.
/// Format:
/// - First 4 bytes: original uncompressed size (big-endian)
/// - Following bytes: chunks
///   - If high bit set (0x80): (byte & 0x7F) + 1 non-zero bytes follow
///   - If high bit clear: (byte & 0x7F) + 3 zero bytes
pub fn decompress_sparse(input: &[u8], _output_size: usize) -> Result<Vec<u8>, &'static str> {
    // Need at least 5 bytes (4 for size + 1 for data)
    if input.len() < 5 {
        return Err("Sparse: input too short");
    }

    // Get original size (big-endian)
    let original_size = ((input[0] as u32) << 24)
        | ((input[1] as u32) << 16)
        | ((input[2] as u32) << 8)
        | (input[3] as u32);

    let mut output = Vec::with_capacity(original_size as usize);
    let mut remaining = original_size as usize;
    let mut pos = 4;

    // Process input
    while pos < input.len() && remaining > 0 {
        let byte = input[pos];
        pos += 1;

        if (byte & 0x80) != 0 {
            // Non-zero bytes follow
            let chunk_size = ((byte & 0x7F) + 1) as usize;

            // Check for input overflow
            if pos + chunk_size > input.len() {
                return Err("Sparse: unexpected end of input");
            }

            // Copy non-zero bytes (limit to remaining)
            let to_copy = chunk_size.min(remaining);
            output.extend_from_slice(&input[pos..pos + to_copy]);
            pos += chunk_size;
            remaining -= to_copy;
        } else {
            // Zeros
            let chunk_size = ((byte & 0x7F) + 3) as usize;
            let to_fill = chunk_size.min(remaining);
            output.resize(output.len() + to_fill, 0);
            remaining -= to_fill;
        }
    }

    Ok(output)
}

/// Compress data using sparse compression.
///
/// This is useful when data contains many zero runs.
pub fn compress_sparse(input: &[u8]) -> Vec<u8> {
    if input.is_empty() {
        return vec![0, 0, 0, 0];
    }

    let len = input.len();
    let mut output = Vec::with_capacity(len + 4);

    // Write original size (big-endian)
    output.push((len >> 24) as u8);
    output.push((len >> 16) as u8);
    output.push((len >> 8) as u8);
    output.push(len as u8);

    let mut pos = 0;

    while pos < len {
        // Count zeros
        let mut zero_count = 0;
        while pos + zero_count < len && input[pos + zero_count] == 0 && zero_count < 0x82 {
            zero_count += 1;
        }

        if zero_count >= 3 {
            // Encode zero run
            while zero_count > 0x82 {
                output.push(0x7F); // 0x82 zeros
                zero_count -= 0x82;
            }
            if zero_count >= 3 {
                output.push((zero_count - 3) as u8);
                pos += zero_count;
                continue;
            }
            // Less than 3 zeros, treat as non-zeros
        }

        // Count non-zeros
        let start = pos;
        let mut last_non_zero = pos;
        let mut zeros_in_row = 0;

        while pos < len {
            if input[pos] == 0 {
                zeros_in_row += 1;
                if zeros_in_row >= 3 {
                    pos -= zeros_in_row;
                    break;
                }
            } else {
                zeros_in_row = 0;
                last_non_zero = pos + 1;
            }
            pos += 1;

            if pos - start >= 0x80 {
                break;
            }
        }

        // We may have trailing zeros < 3, include up to last_non_zero
        let non_zero_end = last_non_zero.max(start);
        let non_zero_count = non_zero_end - start;

        if non_zero_count > 0 {
            // Encode non-zero chunk
            let mut remaining = non_zero_count;
            let mut chunk_start = start;

            while remaining > 0x80 {
                output.push(0xFF); // 0x80 non-zeros
                output.extend_from_slice(&input[chunk_start..chunk_start + 0x80]);
                chunk_start += 0x80;
                remaining -= 0x80;
            }

            if remaining > 0 {
                output.push(0x80 | ((remaining - 1) as u8));
                output.extend_from_slice(&input[chunk_start..chunk_start + remaining]);
            }

            pos = non_zero_end;
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompress_sparse_zeros() {
        // 4 bytes size (8) + marker for 5 zeros (0x02 = 5-3)
        let input = [0, 0, 0, 8, 0x02, 0x80 | 2, b'A', b'B', b'C'];
        let result = decompress_sparse(&input, 8).unwrap();
        assert_eq!(result, vec![0, 0, 0, 0, 0, b'A', b'B', b'C']);
    }

    #[test]
    fn test_roundtrip() {
        let original: Vec<u8> = vec![0, 0, 0, 0, 1, 2, 3, 0, 0, 0, 0, 0, 4, 5];
        let compressed = compress_sparse(&original);
        let decompressed = decompress_sparse(&compressed, original.len()).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_all_zeros() {
        let original = vec![0u8; 100];
        let compressed = compress_sparse(&original);
        let decompressed = decompress_sparse(&compressed, original.len()).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_no_zeros() {
        let original: Vec<u8> = (1..=100).collect();
        let compressed = compress_sparse(&original);
        let decompressed = decompress_sparse(&compressed, original.len()).unwrap();
        assert_eq!(decompressed, original);
    }
}
