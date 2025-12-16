//! PKWARE Data Compression Library (DCL) implementation.
//! Ported from StormLib pklib/explode.c

/// Compression types
pub const CMP_BINARY: u8 = 0;
pub const CMP_ASCII: u8 = 1;

/// Error codes
pub const CMP_NO_ERROR: u32 = 0;
pub const CMP_INVALID_DICTSIZE: u32 = 1;
pub const CMP_INVALID_MODE: u32 = 2;
pub const CMP_BAD_DATA: u32 = 3;
pub const CMP_ABORT: u32 = 4;

/// Internal status codes
const PKDCL_OK: u32 = 0;
const PKDCL_STREAM_END: u32 = 1;

// =============================================================================
// Tables
// =============================================================================

#[rustfmt::skip]
const DIST_BITS: [u8; 0x40] = [
    0x02, 0x04, 0x04, 0x05, 0x05, 0x05, 0x05, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
];

#[rustfmt::skip]
const DIST_CODE: [u8; 0x40] = [
    0x03, 0x0D, 0x05, 0x19, 0x09, 0x11, 0x01, 0x3E, 0x1E, 0x2E, 0x0E, 0x36, 0x16, 0x26, 0x06, 0x3A,
    0x1A, 0x2A, 0x0A, 0x32, 0x12, 0x22, 0x42, 0x02, 0x7C, 0x3C, 0x5C, 0x1C, 0x6C, 0x2C, 0x4C, 0x0C,
    0x74, 0x34, 0x54, 0x14, 0x64, 0x24, 0x44, 0x04, 0x78, 0x38, 0x58, 0x18, 0x68, 0x28, 0x48, 0x08,
    0xF0, 0x70, 0xB0, 0x30, 0xD0, 0x50, 0x90, 0x10, 0xE0, 0x60, 0xA0, 0x20, 0xC0, 0x40, 0x80, 0x00,
];

#[rustfmt::skip]
const EX_LEN_BITS: [u8; 0x10] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

#[rustfmt::skip]
const LEN_BASE: [u16; 0x10] = [
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007,
    0x0008, 0x000A, 0x000E, 0x0016, 0x0026, 0x0046, 0x0086, 0x0106,
];

#[rustfmt::skip]
const LEN_BITS: [u8; 0x10] = [
    0x03, 0x02, 0x03, 0x03, 0x04, 0x04, 0x04, 0x05, 0x05, 0x05, 0x05, 0x06, 0x06, 0x06, 0x07, 0x07,
];

#[rustfmt::skip]
const LEN_CODE: [u8; 0x10] = [
    0x05, 0x03, 0x01, 0x06, 0x0A, 0x02, 0x0C, 0x14, 0x04, 0x18, 0x08, 0x30, 0x10, 0x20, 0x40, 0x00,
];

#[rustfmt::skip]
const CH_BITS_ASC: [u8; 0x100] = [
    0x0B, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x08, 0x07, 0x0C, 0x0C, 0x07, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0D, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x04, 0x0A, 0x08, 0x0C, 0x0A, 0x0C, 0x0A, 0x08, 0x07, 0x07, 0x08, 0x09, 0x07, 0x06, 0x07, 0x08,
    0x07, 0x06, 0x07, 0x07, 0x07, 0x07, 0x08, 0x07, 0x07, 0x08, 0x08, 0x0C, 0x0B, 0x07, 0x09, 0x0B,
    0x0C, 0x06, 0x07, 0x06, 0x06, 0x05, 0x07, 0x08, 0x08, 0x06, 0x0B, 0x09, 0x06, 0x07, 0x06, 0x06,
    0x07, 0x0B, 0x06, 0x06, 0x06, 0x07, 0x09, 0x08, 0x09, 0x09, 0x0B, 0x08, 0x0B, 0x09, 0x0C, 0x08,
    0x0C, 0x05, 0x06, 0x06, 0x06, 0x05, 0x06, 0x06, 0x06, 0x05, 0x0B, 0x07, 0x05, 0x06, 0x05, 0x05,
    0x06, 0x0A, 0x05, 0x05, 0x05, 0x05, 0x08, 0x07, 0x08, 0x08, 0x0A, 0x0B, 0x0B, 0x0C, 0x0C, 0x0C,
    0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
    0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
    0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0D, 0x0C, 0x0D, 0x0D, 0x0D, 0x0C, 0x0D, 0x0D, 0x0D, 0x0C, 0x0D, 0x0D, 0x0D, 0x0D, 0x0C, 0x0D,
    0x0D, 0x0D, 0x0C, 0x0C, 0x0C, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
];

#[rustfmt::skip]
const CH_CODE_ASC: [u16; 0x100] = [
    0x0490, 0x0FE0, 0x07E0, 0x0BE0, 0x03E0, 0x0DE0, 0x05E0, 0x09E0,
    0x01E0, 0x00B8, 0x0062, 0x0EE0, 0x06E0, 0x0022, 0x0AE0, 0x02E0,
    0x0CE0, 0x04E0, 0x08E0, 0x00E0, 0x0F60, 0x0760, 0x0B60, 0x0360,
    0x0D60, 0x0560, 0x1240, 0x0960, 0x0160, 0x0E60, 0x0660, 0x0A60,
    0x000F, 0x0250, 0x0038, 0x0260, 0x0050, 0x0C60, 0x0390, 0x00D8,
    0x0042, 0x0002, 0x0058, 0x01B0, 0x007C, 0x0029, 0x003C, 0x0098,
    0x005C, 0x0009, 0x001C, 0x006C, 0x002C, 0x004C, 0x0018, 0x000C,
    0x0074, 0x00E8, 0x0068, 0x0460, 0x0090, 0x0034, 0x00B0, 0x0710,
    0x0860, 0x0031, 0x0054, 0x0011, 0x0021, 0x0017, 0x0014, 0x00A8,
    0x0028, 0x0001, 0x0310, 0x0130, 0x003E, 0x0064, 0x001E, 0x002E,
    0x0024, 0x0510, 0x000E, 0x0036, 0x0016, 0x0044, 0x0030, 0x00C8,
    0x01D0, 0x00D0, 0x0110, 0x0048, 0x0610, 0x0150, 0x0060, 0x0088,
    0x0FA0, 0x0007, 0x0026, 0x0006, 0x003A, 0x001B, 0x001A, 0x002A,
    0x000A, 0x000B, 0x0210, 0x0004, 0x0013, 0x0032, 0x0003, 0x001D,
    0x0012, 0x0190, 0x000D, 0x0015, 0x0005, 0x0019, 0x0008, 0x0078,
    0x00F0, 0x0070, 0x0290, 0x0410, 0x0010, 0x07A0, 0x0BA0, 0x03A0,
    0x0240, 0x1C40, 0x0C40, 0x1440, 0x0440, 0x1840, 0x0840, 0x1040,
    0x0040, 0x1F80, 0x0F80, 0x1780, 0x0780, 0x1B80, 0x0B80, 0x1380,
    0x0380, 0x1D80, 0x0D80, 0x1580, 0x0580, 0x1980, 0x0980, 0x1180,
    0x0180, 0x1E80, 0x0E80, 0x1680, 0x0680, 0x1A80, 0x0A80, 0x1280,
    0x0280, 0x1C80, 0x0C80, 0x1480, 0x0480, 0x1880, 0x0880, 0x1080,
    0x0080, 0x1F00, 0x0F00, 0x1700, 0x0700, 0x1B00, 0x0B00, 0x1300,
    0x0DA0, 0x05A0, 0x09A0, 0x01A0, 0x0EA0, 0x06A0, 0x0AA0, 0x02A0,
    0x0CA0, 0x04A0, 0x08A0, 0x00A0, 0x0F20, 0x0720, 0x0B20, 0x0320,
    0x0D20, 0x0520, 0x0920, 0x0120, 0x0E20, 0x0620, 0x0A20, 0x0220,
    0x0C20, 0x0420, 0x0820, 0x0020, 0x0FC0, 0x07C0, 0x0BC0, 0x03C0,
    0x0DC0, 0x05C0, 0x09C0, 0x01C0, 0x0EC0, 0x06C0, 0x0AC0, 0x02C0,
    0x0CC0, 0x04C0, 0x08C0, 0x00C0, 0x0F40, 0x0740, 0x0B40, 0x0340,
    0x0300, 0x0D40, 0x1D00, 0x0D00, 0x1500, 0x0540, 0x0500, 0x1900,
    0x0900, 0x0940, 0x1100, 0x0100, 0x1E00, 0x0E00, 0x0140, 0x1600,
    0x0600, 0x1A00, 0x0E40, 0x0640, 0x0A40, 0x0A00, 0x1200, 0x0200,
    0x1C00, 0x0C00, 0x1400, 0x0400, 0x1800, 0x0800, 0x1000, 0x0000,
];

// =============================================================================
// Decompression state
// =============================================================================

/// Decompression work structure.
struct DcmpState<'a> {
    // Input
    input: &'a [u8],
    in_pos: usize,

    // Bit buffer
    bit_buff: u32,
    extra_bits: u32,

    // Settings
    ctype: u8,
    dsize_bits: u32,
    dsize_mask: u32,

    // Output buffer (circle buffer with history)
    out_buff: Vec<u8>,
    output_pos: usize,

    // Decode tables
    dist_pos_codes: [u8; 0x100],
    length_codes: [u8; 0x100],
    dist_bits: [u8; 0x40],
    len_bits: [u8; 0x10],
    ex_len_bits: [u8; 0x10],
    len_base: [u16; 0x10],

    // ASCII tables
    ch_bits_asc: [u8; 0x100],
    offs_2c34: [u8; 0x100],
    offs_2d34: [u8; 0x100],
    offs_2e34: [u8; 0x80],
    offs_2eb4: [u8; 0x100],
}

impl<'a> DcmpState<'a> {
    fn new(input: &'a [u8]) -> Result<Self, u32> {
        if input.len() < 4 {
            return Err(CMP_BAD_DATA);
        }

        let ctype = input[0];
        let dsize_bits = input[1] as u32;

        // Validate compression type
        if ctype != CMP_BINARY && ctype != CMP_ASCII {
            return Err(CMP_INVALID_MODE);
        }

        // Validate dictionary size
        if !(4..=6).contains(&dsize_bits) {
            return Err(CMP_INVALID_DICTSIZE);
        }

        let dsize_mask = 0xFFFF >> (0x10 - dsize_bits);

        let mut state = Self {
            input,
            in_pos: 3,
            bit_buff: input[2] as u32,
            extra_bits: 0,
            ctype,
            dsize_bits,
            dsize_mask,
            out_buff: vec![0u8; 0x2204],
            output_pos: 0x1000,
            dist_pos_codes: [0; 0x100],
            length_codes: [0; 0x100],
            dist_bits: DIST_BITS,
            len_bits: LEN_BITS,
            ex_len_bits: EX_LEN_BITS,
            len_base: LEN_BASE,
            ch_bits_asc: CH_BITS_ASC,
            offs_2c34: [0; 0x100],
            offs_2d34: [0; 0x100],
            offs_2e34: [0; 0x80],
            offs_2eb4: [0; 0x100],
        };

        // Generate decode tables
        state.gen_decode_tabs(&LEN_CODE, &LEN_BITS, &mut state.length_codes.clone());
        state.gen_decode_tabs(&DIST_CODE, &DIST_BITS, &mut state.dist_pos_codes.clone());

        // Build length codes table
        for i in 0..LEN_CODE.len() {
            let length = 1u32 << LEN_BITS[i];
            let mut index = LEN_CODE[i] as u32;
            while index < 0x100 {
                state.length_codes[index as usize] = i as u8;
                index += length;
            }
        }

        // Build distance position codes table
        for i in 0..DIST_CODE.len() {
            let length = 1u32 << DIST_BITS[i];
            let mut index = DIST_CODE[i] as u32;
            while index < 0x100 {
                state.dist_pos_codes[index as usize] = i as u8;
                index += length;
            }
        }

        // Generate ASCII tables if needed
        if ctype == CMP_ASCII {
            state.gen_asc_tabs();
        }

        Ok(state)
    }

    fn gen_decode_tabs(
        &mut self,
        start_indexes: &[u8],
        length_bits: &[u8],
        positions: &mut [u8; 0x100],
    ) {
        for i in 0..start_indexes.len().min(length_bits.len()) {
            let length = 1u32 << length_bits[i];
            let mut index = start_indexes[i] as u32;
            while index < 0x100 {
                positions[index as usize] = i as u8;
                index += length;
            }
        }
    }

    fn gen_asc_tabs(&mut self) {
        let mut ch_bits_asc = CH_BITS_ASC;

        for count in (0..=0xFFu16).rev() {
            let bits_asc = ch_bits_asc[count as usize];
            let ch_code = CH_CODE_ASC[count as usize];

            if bits_asc <= 8 {
                let add = 1u32 << bits_asc;
                let mut acc = ch_code as u32;
                while acc < 0x100 {
                    self.offs_2c34[acc as usize] = count as u8;
                    acc += add;
                }
            } else {
                let acc = ch_code & 0xFF;
                if acc != 0 {
                    self.offs_2c34[acc as usize] = 0xFF;

                    if (ch_code & 0x3F) != 0 {
                        ch_bits_asc[count as usize] = bits_asc - 4;
                        let add = 1u32 << (bits_asc - 4);
                        let mut acc = (ch_code >> 4) as u32;
                        while acc < 0x100 {
                            self.offs_2d34[acc as usize] = count as u8;
                            acc += add;
                        }
                    } else {
                        ch_bits_asc[count as usize] = bits_asc - 6;
                        let add = 1u32 << (bits_asc - 6);
                        let mut acc = (ch_code >> 6) as u32;
                        while acc < 0x80 {
                            self.offs_2e34[acc as usize] = count as u8;
                            acc += add;
                        }
                    }
                } else {
                    ch_bits_asc[count as usize] = bits_asc - 8;
                    let add = 1u32 << (bits_asc - 8);
                    let mut acc = (ch_code >> 8) as u32;
                    while acc < 0x100 {
                        self.offs_2eb4[acc as usize] = count as u8;
                        acc += add;
                    }
                }
            }
        }

        self.ch_bits_asc = ch_bits_asc;
    }

    /// Remove bits from bit buffer, refilling from input as needed.
    fn waste_bits(&mut self, n_bits: u32) -> u32 {
        if n_bits <= self.extra_bits {
            self.extra_bits -= n_bits;
            self.bit_buff >>= n_bits;
            return PKDCL_OK;
        }

        self.bit_buff >>= self.extra_bits;

        if self.in_pos >= self.input.len() {
            return PKDCL_STREAM_END;
        }

        self.bit_buff |= (self.input[self.in_pos] as u32) << 8;
        self.in_pos += 1;
        self.bit_buff >>= n_bits - self.extra_bits;
        self.extra_bits = self.extra_bits.wrapping_sub(n_bits).wrapping_add(8);

        PKDCL_OK
    }

    /// Decode next literal from compressed data.
    fn decode_lit(&mut self) -> u32 {
        // Test current bit
        if (self.bit_buff & 1) != 0 {
            // Length code
            if self.waste_bits(1) != PKDCL_OK {
                return 0x306;
            }

            let length_code = self.length_codes[(self.bit_buff & 0xFF) as usize] as usize;

            if self.waste_bits(self.len_bits[length_code] as u32) != PKDCL_OK {
                return 0x306;
            }

            let extra_length_bits = self.ex_len_bits[length_code];
            if extra_length_bits != 0 {
                let extra_length = self.bit_buff & ((1 << extra_length_bits) - 1);

                if self.waste_bits(extra_length_bits as u32) != PKDCL_OK
                    && (length_code as u32 + extra_length) != 0x10E
                {
                    return 0x306;
                }

                return self.len_base[length_code] as u32 + extra_length + 0x100;
            }

            return length_code as u32 + 0x100;
        }

        // Literal byte
        if self.waste_bits(1) != PKDCL_OK {
            return 0x306;
        }

        if self.ctype == CMP_BINARY {
            let uncompressed_byte = self.bit_buff & 0xFF;
            if self.waste_bits(8) != PKDCL_OK {
                return 0x306;
            }
            return uncompressed_byte;
        }

        // ASCII mode
        let value;
        if (self.bit_buff & 0xFF) != 0 {
            value = self.offs_2c34[(self.bit_buff & 0xFF) as usize];

            if value == 0xFF {
                if (self.bit_buff & 0x3F) != 0 {
                    if self.waste_bits(4) != PKDCL_OK {
                        return 0x306;
                    }
                    let v = self.offs_2d34[(self.bit_buff & 0xFF) as usize];
                    if self.waste_bits(self.ch_bits_asc[v as usize] as u32) != PKDCL_OK {
                        return 0x306;
                    }
                    return v as u32;
                } else {
                    if self.waste_bits(6) != PKDCL_OK {
                        return 0x306;
                    }
                    let v = self.offs_2e34[(self.bit_buff & 0x7F) as usize];
                    if self.waste_bits(self.ch_bits_asc[v as usize] as u32) != PKDCL_OK {
                        return 0x306;
                    }
                    return v as u32;
                }
            }
        } else {
            if self.waste_bits(8) != PKDCL_OK {
                return 0x306;
            }
            let v = self.offs_2eb4[(self.bit_buff & 0xFF) as usize];
            if self.waste_bits(self.ch_bits_asc[v as usize] as u32) != PKDCL_OK {
                return 0x306;
            }
            return v as u32;
        }

        if self.waste_bits(self.ch_bits_asc[value as usize] as u32) != PKDCL_OK {
            return 0x306;
        }

        value as u32
    }

    /// Decode distance of repetition.
    fn decode_dist(&mut self, rep_length: u32) -> u32 {
        let dist_pos_code = self.dist_pos_codes[(self.bit_buff & 0xFF) as usize] as usize;
        let dist_pos_bits = self.dist_bits[dist_pos_code];

        if self.waste_bits(dist_pos_bits as u32) != PKDCL_OK {
            return 0;
        }

        let distance;
        if rep_length == 2 {
            distance = ((dist_pos_code as u32) << 2) | (self.bit_buff & 0x03);
            if self.waste_bits(2) != PKDCL_OK {
                return 0;
            }
        } else {
            distance =
                ((dist_pos_code as u32) << self.dsize_bits) | (self.bit_buff & self.dsize_mask);
            if self.waste_bits(self.dsize_bits) != PKDCL_OK {
                return 0;
            }
        }

        distance + 1
    }

    /// Main expansion loop.
    fn expand(&mut self, output: &mut Vec<u8>) -> u32 {
        loop {
            let next_literal = self.decode_lit();

            if next_literal >= 0x305 {
                break;
            }

            if next_literal >= 0x100 {
                // Repetition
                let rep_length = next_literal - 0xFE;
                let minus_dist = self.decode_dist(rep_length);

                if minus_dist == 0 {
                    return CMP_ABORT;
                }

                // Copy from history
                let source_pos = self.output_pos - minus_dist as usize;
                for i in 0..rep_length as usize {
                    let byte = self.out_buff[source_pos + i];
                    self.out_buff[self.output_pos] = byte;
                    self.output_pos += 1;

                    if self.output_pos >= 0x2000 {
                        // Flush output
                        output.extend_from_slice(&self.out_buff[0x1000..0x2000]);
                        self.out_buff.copy_within(0x1000..self.output_pos, 0);
                        self.output_pos -= 0x1000;
                    }
                }
            } else {
                // Literal byte
                self.out_buff[self.output_pos] = next_literal as u8;
                self.output_pos += 1;

                if self.output_pos >= 0x2000 {
                    output.extend_from_slice(&self.out_buff[0x1000..0x2000]);
                    self.out_buff.copy_within(0x1000..self.output_pos, 0);
                    self.output_pos -= 0x1000;
                }
            }
        }

        // Flush remaining bytes
        if self.output_pos > 0x1000 {
            output.extend_from_slice(&self.out_buff[0x1000..self.output_pos]);
        }

        CMP_NO_ERROR
    }
}

// =============================================================================
// Public API
// =============================================================================

/// Decompress data using PKWARE DCL algorithm.
///
/// # Arguments
/// * `input` - Compressed data.
/// * `output_size` - Expected output size.
///
/// # Returns
/// Decompressed data or error code.
pub fn explode(input: &[u8], output_size: usize) -> Result<Vec<u8>, u32> {
    let mut state = DcmpState::new(input)?;
    let mut output = Vec::with_capacity(output_size);

    let result = state.expand(&mut output);

    if result == CMP_NO_ERROR {
        Ok(output)
    } else {
        Err(result)
    }
}

/// Compress data using PKWARE DCL algorithm.
///
/// # Arguments
/// * `input` - Data to compress.
/// * `compression_type` - CMP_BINARY or CMP_ASCII.
/// * `dict_size` - Dictionary size (4096, 8192, or 16384).
///
/// # Returns
/// Compressed data or error code.
pub fn implode(input: &[u8], compression_type: u8, dict_size: u32) -> Result<Vec<u8>, u32> {
    // Basic implementation: Store literals only.
    // This produces a valid "imploded" stream but with no compression (actually slight expansion).
    // Format:
    // Header: [CompressionType] [DictSizeBits]
    // Data: [0] [LiteralByte] ...
    // End: [1] [EOF Code]

    let mut output = Vec::with_capacity(input.len() + 100);

    // 1. Write Header
    output.push(compression_type);

    let dict_size_bits = match dict_size {
        4096 => 4,
        8192 => 5,
        16384 => 6,
        _ => return Err(CMP_INVALID_DICTSIZE),
    };
    output.push(dict_size_bits);

    // 2. Write Data (Literals only)
    let mut bit_buffer: u32 = 0;
    let mut bit_count: u32 = 0;

    let mut write_bits = |bits: u32, count: u32, out: &mut Vec<u8>| {
        bit_buffer |= bits << bit_count;
        bit_count += count;
        while bit_count >= 8 {
            out.push((bit_buffer & 0xFF) as u8);
            bit_buffer >>= 8;
            bit_count -= 8;
        }
    };

    for &byte in input {
        // Literal marker (0) - 1 bit
        write_bits(0, 1, &mut output);
        // Literal byte - 8 bits
        write_bits(byte as u32, 8, &mut output);
    }

    // 3. Write EOF Code (0x305)
    // EOF is encoded as a length code.
    // 0x305 is > 0x100, so it's a repetition/special code.
    // In decode_lit:
    // if bit is 1 -> Length code.
    // We need to emit '1' first.
    write_bits(1, 1, &mut output);

    // We need to encode 0x305.
    // 0x305 - 0x100 = 0x205.
    // Wait, decode_lit returns length_code + 0x100.
    // So we need length_code corresponding to 0x205?
    // No, decode_lit returns raw value.
    // If value >= 0x305, it breaks.

    // We need to emit bits such that decode_lit returns >= 0x305.
    // decode_lit reads length_code index from bits.
    // length_code = length_codes[bits].
    // Then reads extra bits.
    // Result = len_base[length_code] + extra + 0x100.

    // We want Result = 0x305.
    // 0x305 - 0x100 = 0x205 = 517.
    // Look at LEN_BASE table.
    // Max base is 0x106 (262).
    // 0x106 + 0xFF (max extra) = 0x205?
    // Index 0xF (15) -> Base 0x106. Extra bits: LEN_BITS[15]=7? No, EX_LEN_BITS[15]=8.
    // So max value is 0x106 + 0xFF = 0x205.
    // So if we send index 15 and extra 0xFF, we get 0x205 + 0x100 = 0x305.

    // So we need to send:
    // 1. Index 15 encoded.
    //    LEN_CODE[15] = 0.
    //    Wait, LEN_CODE maps index to code?
    //    No, LEN_CODE is used to build the table.
    //    gen_decode_tabs builds `length_codes` table mapping BYTE -> INDEX.
    //    We need to find a BYTE that maps to INDEX 15.
    //    LEN_CODE[15] = 0x00.
    //    LEN_BITS[15] = 0x07.
    //    So if we send 7 bits of 0x00?
    //    Let's check gen_decode_tabs.
    //    length = 1 << LEN_BITS[i].
    //    index = LEN_CODE[i].
    //    positions[index] = i.
    //    So positions[0x00] = 15.
    //    So if we send 0x00 (7 bits), it decodes to index 15.

    // So:
    // Write 0x00 (7 bits).
    write_bits(0x00, 7, &mut output);

    // Write extra bits (0xFF, 8 bits).
    write_bits(0xFF, 8, &mut output);

    // Flush bits
    if bit_count > 0 {
        output.push((bit_buffer & 0xFF) as u8);
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_explode_too_short() {
        let result = explode(&[0, 0, 0], 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_explode_invalid_mode() {
        let result = explode(&[2, 4, 0, 0, 0], 100);
        assert_eq!(result.unwrap_err(), CMP_INVALID_MODE);
    }

    #[test]
    fn test_explode_invalid_dict_size() {
        let result = explode(&[0, 3, 0, 0, 0], 100);
        assert_eq!(result.unwrap_err(), CMP_INVALID_DICTSIZE);
    }
}
