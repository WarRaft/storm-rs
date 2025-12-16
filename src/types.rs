//! Core MPQ data structures.
//! Ported from StormLib.h

use crate::constants::MD5_DIGEST_SIZE;

// =============================================================================
// MPQ User Data structure
// Ported from TMPQUserData (StormLib.h lines 520-533)
// =============================================================================

/// MPQ User Data header.
/// Located before the MPQ header in some archives.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MpqUserData {
    /// The ID_MPQ_USERDATA ('MPQ\x1B') signature
    pub id: u32,
    /// Maximum size of the user data
    pub user_data_size: u32,
    /// Offset of the MPQ header, relative to the begin of this header
    pub header_offset: u32,
    /// Appears to be size of user data header (Starcraft II maps)
    pub user_data_header_size: u32,
}

impl MpqUserData {
    pub const SIZE: usize = 16;
}

// =============================================================================
// MPQ Header structure
// Ported from TMPQHeader (StormLib.h lines 541-628)
// =============================================================================

/// MPQ Archive header.
/// Supports all 4 format versions.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct MpqHeader {
    // -- MPQ HEADER v1 (0x20 bytes) -------------------------------------------
    /// The ID_MPQ ('MPQ\x1A') signature
    pub id: u32,
    /// Size of the archive header
    pub header_size: u32,
    /// 32-bit size of MPQ archive (deprecated in v2+)
    pub archive_size: u32,
    /// Format version (0 = v1, 1 = v2, 2 = v3, 3 = v4)
    pub format_version: u16,
    /// Power of two exponent for sector size (512 * 2^sector_size)
    pub sector_size: u16,
    /// Offset to hash table (relative to archive start)
    pub hash_table_pos: u32,
    /// Offset to block table (relative to archive start)
    pub block_table_pos: u32,
    /// Number of entries in the hash table
    pub hash_table_size: u32,
    /// Number of entries in the block table
    pub block_table_size: u32,

    // -- MPQ HEADER v2 (0x2C bytes) -------------------------------------------
    /// Offset to hi-block table (64-bit)
    pub hi_block_table_pos64: u64,
    /// High 16 bits of the hash table offset
    pub hash_table_pos_hi: u16,
    /// High 16 bits of the block table offset
    pub block_table_pos_hi: u16,

    // -- MPQ HEADER v3 (0x44 bytes) -------------------------------------------
    /// 64-bit version of the archive size
    pub archive_size64: u64,
    /// 64-bit position of the BET table
    pub bet_table_pos64: u64,
    /// 64-bit position of the HET table
    pub het_table_pos64: u64,

    // -- MPQ HEADER v4 (0xD0 bytes) -------------------------------------------
    /// Compressed size of the hash table
    pub hash_table_size64: u64,
    /// Compressed size of the block table
    pub block_table_size64: u64,
    /// Compressed size of the hi-block table
    pub hi_block_table_size64: u64,
    /// Compressed size of the HET block
    pub het_table_size64: u64,
    /// Compressed size of the BET block
    pub bet_table_size64: u64,
    /// Size of raw data chunk to calculate MD5
    pub raw_chunk_size: u32,

    /// MD5 of the block table before decryption
    pub md5_block_table: [u8; MD5_DIGEST_SIZE],
    /// MD5 of the hash table before decryption
    pub md5_hash_table: [u8; MD5_DIGEST_SIZE],
    /// MD5 of the hi-block table
    pub md5_hi_block_table: [u8; MD5_DIGEST_SIZE],
    /// MD5 of the BET table before decryption
    pub md5_bet_table: [u8; MD5_DIGEST_SIZE],
    /// MD5 of the HET table before decryption
    pub md5_het_table: [u8; MD5_DIGEST_SIZE],
    /// MD5 of the MPQ header from signature to (including) MD5_HetTable
    pub md5_mpq_header: [u8; MD5_DIGEST_SIZE],
}

impl Default for MpqHeader {
    fn default() -> Self {
        Self {
            id: 0,
            header_size: 0,
            archive_size: 0,
            format_version: 0,
            sector_size: 0,
            hash_table_pos: 0,
            block_table_pos: 0,
            hash_table_size: 0,
            block_table_size: 0,
            hi_block_table_pos64: 0,
            hash_table_pos_hi: 0,
            block_table_pos_hi: 0,
            archive_size64: 0,
            bet_table_pos64: 0,
            het_table_pos64: 0,
            hash_table_size64: 0,
            block_table_size64: 0,
            hi_block_table_size64: 0,
            het_table_size64: 0,
            bet_table_size64: 0,
            raw_chunk_size: 0,
            md5_block_table: [0; MD5_DIGEST_SIZE],
            md5_hash_table: [0; MD5_DIGEST_SIZE],
            md5_hi_block_table: [0; MD5_DIGEST_SIZE],
            md5_bet_table: [0; MD5_DIGEST_SIZE],
            md5_het_table: [0; MD5_DIGEST_SIZE],
            md5_mpq_header: [0; MD5_DIGEST_SIZE],
        }
    }
}

impl MpqHeader {
    /// Calculate the sector size in bytes from the sector_size field.
    #[inline]
    pub fn sector_size_bytes(&self) -> u32 {
        512 << self.sector_size
    }

    /// Get the 64-bit hash table position.
    #[inline]
    pub fn hash_table_pos64(&self) -> u64 {
        ((self.hash_table_pos_hi as u64) << 32) | (self.hash_table_pos as u64)
    }

    /// Get the 64-bit block table position.
    #[inline]
    pub fn block_table_pos64(&self) -> u64 {
        ((self.block_table_pos_hi as u64) << 32) | (self.block_table_pos as u64)
    }
}

// =============================================================================
// Hash table entry
// Ported from TMPQHash (StormLib.h lines 632-666)
// =============================================================================

/// Hash table entry.
/// All files in the archive are searched by their hashes.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct MpqHash {
    /// The hash of the file path, using method A.
    pub hash_check_a: u32,
    /// The hash of the file path, using method B.
    pub hash_check_b: u32,
    /// The language of the file (Windows LANGID).
    pub locale: u16,
    /// The platform (0 = default). Combined with flags in some implementations.
    pub platform: u8,
    /// Additional flags.
    pub flags: u8,
    /// Index into the block table, or HASH_ENTRY_FREE/HASH_ENTRY_DELETED.
    pub block_index: u32,
}

impl MpqHash {
    pub const SIZE: usize = 16;

    /// Check if this hash entry is free.
    #[inline]
    pub fn is_free(&self) -> bool {
        self.block_index == crate::constants::HASH_ENTRY_FREE
    }

    /// Check if this hash entry is deleted.
    #[inline]
    pub fn is_deleted(&self) -> bool {
        self.block_index == crate::constants::HASH_ENTRY_DELETED
    }

    /// Get the block index, masked appropriately.
    #[inline]
    pub fn masked_block_index(&self) -> u32 {
        self.block_index & crate::constants::BLOCK_INDEX_MASK
    }

    /// Create a new empty hash entry.
    pub fn new_empty() -> Self {
        Self {
            hash_check_a: crate::constants::HASH_ENTRY_FREE,
            hash_check_b: crate::constants::HASH_ENTRY_FREE,
            locale: 0,
            platform: 0,
            flags: 0,
            block_index: crate::constants::HASH_ENTRY_FREE,
        }
    }
}

// =============================================================================
// Block table entry
// Ported from TMPQBlock (StormLib.h lines 668-683)
// =============================================================================

/// Block table entry.
/// Contains information about the file's location and size.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct MpqBlock {
    /// Offset of the beginning of the file, relative to the beginning of the archive.
    pub file_pos: u32,
    /// Compressed file size.
    pub compressed_size: u32,
    /// Uncompressed file size. Only valid if the block is a file.
    pub file_size: u32,
    /// Flags for the file (see MPQ_FILE_* constants).
    pub flags: u32,
}

impl MpqBlock {
    pub const SIZE: usize = 16;

    /// Check if file uses PKWARE implode compression.
    #[inline]
    pub fn is_imploded(&self) -> bool {
        (self.flags & crate::constants::MPQ_FILE_IMPLODE) != 0
    }

    /// Check if file uses general compression.
    #[inline]
    pub fn is_compressed(&self) -> bool {
        (self.flags & crate::constants::MPQ_FILE_COMPRESS) != 0
    }

    /// Check if file is encrypted.
    #[inline]
    pub fn is_encrypted(&self) -> bool {
        (self.flags & crate::constants::MPQ_FILE_ENCRYPTED) != 0
    }

    /// Check if file uses key v2 encryption.
    #[inline]
    pub fn is_key_v2(&self) -> bool {
        (self.flags & crate::constants::MPQ_FILE_KEY_V2) != 0
    }

    /// Check if file is stored as a single unit (not split into sectors).
    #[inline]
    pub fn is_single_unit(&self) -> bool {
        (self.flags & crate::constants::MPQ_FILE_SINGLE_UNIT) != 0
    }

    /// Check if file is a patch file.
    #[inline]
    pub fn is_patch_file(&self) -> bool {
        (self.flags & crate::constants::MPQ_FILE_PATCH_FILE) != 0
    }

    /// Check if file is a deletion marker.
    #[inline]
    pub fn is_delete_marker(&self) -> bool {
        (self.flags & crate::constants::MPQ_FILE_DELETE_MARKER) != 0
    }

    /// Check if file has sector CRCs.
    #[inline]
    pub fn has_sector_crc(&self) -> bool {
        (self.flags & crate::constants::MPQ_FILE_SECTOR_CRC) != 0
    }

    /// Check if file exists.
    #[inline]
    pub fn exists(&self) -> bool {
        (self.flags & crate::constants::MPQ_FILE_EXISTS) != 0
    }
}

// =============================================================================
// Patch file information
// Ported from TPatchInfo (StormLib.h lines 686-694)
// =============================================================================

/// Patch file information.
/// Precedes the sector offset table in patch files.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct PatchInfo {
    /// Length of patch info header, in bytes
    pub length: u32,
    /// Flags. 0x80000000 = valid
    pub flags: u32,
    /// Uncompressed size of the patch file
    pub data_size: u32,
    /// MD5 of the entire patch file after decompression
    pub md5: [u8; 16],
}

impl PatchInfo {
    pub const SIZE: usize = 28;
}

// =============================================================================
// (attributes) file header
// =============================================================================

/// Header of the (attributes) file.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct MpqAttributesHeader {
    /// Version of the (attributes) file. Must be 100.
    pub version: u32,
    /// Flags (see MPQ_ATTRIBUTE_*).
    pub flags: u32,
}

impl MpqAttributesHeader {
    pub const SIZE: usize = 8;
}

/// Parsed attributes for a file.
#[derive(Debug, Clone, Default)]
pub struct MpqFileAttribute {
    pub crc32: u32,
    pub file_time: u64,
    pub md5: [u8; MD5_DIGEST_SIZE],
}

// =============================================================================
// Combined file entry
// Ported from TFileEntry (StormLib.h lines 699-710)
// =============================================================================

/// Combined file entry.
/// This structure combines data from block table, hi-block table,
/// (attributes) file and (listfile).
#[derive(Debug, Clone, Default)]
pub struct FileEntry {
    /// Jenkins hash of the file name (only used with BET table).
    pub file_name_hash: u64,
    /// Position of the file content in the MPQ, relative to the MPQ header.
    pub byte_offset: u64,
    /// FileTime from the (attributes) file. 0 if not present.
    pub file_time: u64,
    /// Decompressed size of the file.
    pub file_size: u32,
    /// Compressed size of the file.
    pub compressed_size: u32,
    /// File flags (from block table).
    pub flags: u32,
    /// CRC32 from (attributes) file. 0 if not present.
    pub crc32: u32,
    /// File MD5 from the (attributes) file.
    pub md5: [u8; MD5_DIGEST_SIZE],
    /// File name. None if not known.
    pub file_name: Option<String>,
}

/// Information about a file in the archive.
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub name: String,
    pub offset: u64,
    pub compressed_size: u32,
    pub file_size: u32,
    pub flags: u32,
    pub block_index: u32,
    pub crc32: u32,
    pub file_time: u64,
    pub md5: [u8; MD5_DIGEST_SIZE],
}

// =============================================================================
// HET/BET table structures
// Ported from TMPQExtHeader, TMPQHetHeader, TMPQBetHeader
// =============================================================================

/// Common header for HET and BET tables.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct MpqExtHeader {
    /// 'HET\x1A' or 'BET\x1A'
    pub signature: u32,
    /// Version. Seems to be always 1
    pub version: u32,
    /// Size of the contained table
    pub data_size: u32,
}

impl MpqExtHeader {
    pub const SIZE: usize = 12;
}

/// HET table header.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct MpqHetHeader {
    pub ext_hdr: MpqExtHeader,
    /// Size of the entire HET table, including header (in bytes)
    pub table_size: u32,
    /// Number of occupied entries in the HET table
    pub entry_count: u32,
    /// Total number of entries in the HET table
    pub total_count: u32,
    /// Size of the name hash entry (in bits)
    pub name_hash_bit_size: u32,
    /// Total size of file index (in bits)
    pub index_size_total: u32,
    /// Extra bits in the file index
    pub index_size_extra: u32,
    /// Effective size of the file index (in bits)
    pub index_size: u32,
    /// Size of the block index subtable (in bytes)
    pub index_table_size: u32,
}

/// BET table header.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct MpqBetHeader {
    pub ext_hdr: MpqExtHeader,
    /// Size of the entire BET table, including the header (in bytes)
    pub table_size: u32,
    /// Number of entries in the BET table
    pub entry_count: u32,
    pub unknown_08: u32,
    /// Size of one table entry (in bits)
    pub table_entry_size: u32,
    /// Bit index of the file position (within the entry record)
    pub bit_index_file_pos: u32,
    /// Bit index of the file size (within the entry record)
    pub bit_index_file_size: u32,
    /// Bit index of the compressed size (within the entry record)
    pub bit_index_cmp_size: u32,
    /// Bit index of the flag index (within the entry record)
    pub bit_index_flag_index: u32,
    /// Bit index of the ??? (within the entry record)
    pub bit_index_unknown: u32,
    /// Bit size of file position (in the entry record)
    pub bit_count_file_pos: u32,
    /// Bit size of file size (in the entry record)
    pub bit_count_file_size: u32,
    /// Bit size of compressed file size (in the entry record)
    pub bit_count_cmp_size: u32,
    /// Bit size of flags index (in the entry record)
    pub bit_count_flag_index: u32,
    /// Bit size of ??? (in the entry record)
    pub bit_count_unknown: u32,
    /// Total bit size of the NameHash2
    pub bit_total_name_hash2: u32,
    /// Extra bits in the NameHash2
    pub bit_extra_name_hash2: u32,
    /// Effective size of NameHash2 (in bits)
    pub bit_count_name_hash2: u32,
    /// Size of NameHash2 table, in bytes
    pub name_hash_array_size: u32,
    /// Number of flags in the following array
    pub flag_count: u32,
}

// =============================================================================
// Parsed HET/BET tables
// =============================================================================

/// Parsed HET table.
#[derive(Debug, Clone)]
pub struct HetTable {
    /// Array of NameHash1 values (upper 8 bits of file name hash)
    pub name_hashes: Vec<u8>,
    /// Bit array of file index values
    pub bet_indexes: Vec<u8>,
    /// AND mask for calculating file name hash
    pub and_mask: u64,
    /// OR mask for setting the highest bit of the file name hash
    pub or_mask: u64,
    /// Number of occupied entries
    pub entry_count: u32,
    /// Total number of entries
    pub total_count: u32,
    /// Size of the name hash entry (in bits)
    pub name_hash_bit_size: u32,
    /// Total size of one entry in bet_indexes (in bits)
    pub index_size_total: u32,
    /// Extra bits in the entry
    pub index_size_extra: u32,
    /// Effective size of one entry (in bits)
    pub index_size: u32,
}

/// Parsed BET table.
#[derive(Debug, Clone)]
pub struct BetTable {
    /// Array of NameHash2 entries (bit array)
    pub name_hashes: Vec<u8>,
    /// Bit-based file table
    pub file_table: Vec<u8>,
    /// Array of file flags
    pub file_flags: Vec<u32>,

    pub table_entry_size: u32,
    pub bit_index_file_pos: u32,
    pub bit_index_file_size: u32,
    pub bit_index_cmp_size: u32,
    pub bit_index_flag_index: u32,
    pub bit_index_unknown: u32,
    pub bit_count_file_pos: u32,
    pub bit_count_file_size: u32,
    pub bit_count_cmp_size: u32,
    pub bit_count_flag_index: u32,
    pub bit_count_unknown: u32,
    pub bit_total_name_hash2: u32,
    pub bit_extra_name_hash2: u32,
    pub bit_count_name_hash2: u32,
    pub entry_count: u32,
    pub flag_count: u32,
}

/// Signature for file bitmap footer ('ptv3')
pub const ID_FILE_BITMAP_FOOTER: u32 = 0x33767470;

/// Footer for partial MPQ files (at the end of the file).
#[derive(Debug, Clone, Copy, Default)]
pub struct FileBitmapFooter {
    pub signature: u32,
    pub version: u32,
    pub build_number: u32,
    pub map_offset_lo: u32,
    pub map_offset_hi: u32,
    pub block_size: u32,
}

impl FileBitmapFooter {
    pub fn map_offset(&self) -> u64 {
        ((self.map_offset_hi as u64) << 32) | (self.map_offset_lo as u64)
    }
}
