//! Constants for MPQ archives.
//! Ported from StormLib.h

/// MPQ archive header ID ('MPQ\x1A')
pub const ID_MPQ: u32 = 0x1A51504D;

/// MPQ userdata entry ('MPQ\x1B')
pub const ID_MPQ_USERDATA: u32 = 0x1B51504D;

/// MPK archive header ID ('MPK\x1A')
pub const ID_MPK: u32 = 0x1A4B504D;

/// MPK version ("2000")
pub const ID_MPK_VERSION_2000: u32 = 0x30303032;

// =============================================================================
// Hash table constants
// =============================================================================

/// Minimum hash table size (verified: if there is 1 file, hash table size is 4)
pub const HASH_TABLE_SIZE_MIN: u32 = 0x00000004;

/// Default hash table size for empty MPQs
pub const HASH_TABLE_SIZE_DEFAULT: u32 = 0x00001000;

/// Maximum acceptable hash table size
pub const HASH_TABLE_SIZE_MAX: u32 = 0x00080000;

/// Block index for deleted entry in the hash table
pub const HASH_ENTRY_DELETED: u32 = 0xFFFFFFFE;

/// Block index for free entry in the hash table
pub const HASH_ENTRY_FREE: u32 = 0xFFFFFFFF;

/// NameHash1 value for a deleted entry (HET table)
pub const HET_ENTRY_DELETED: u8 = 0x80;

/// NameHash1 value for free entry (HET table)
pub const HET_ENTRY_FREE: u8 = 0x00;

// =============================================================================
// Values for SFileOpenFile
// =============================================================================

/// Open the file from the MPQ archive
pub const SFILE_OPEN_FROM_MPQ: u32 = 0x00000000;

/// Only check whether the file exists
pub const SFILE_OPEN_CHECK_EXISTS: u32 = 0xFFFFFFFC;

/// Reserved for StormLib internal use
pub const SFILE_OPEN_BASE_FILE: u32 = 0xFFFFFFFD;

/// Reserved for StormLib internal use
pub const SFILE_OPEN_ANY_LOCALE: u32 = 0xFFFFFFFE;

/// Open a local file
pub const SFILE_OPEN_LOCAL_FILE: u32 = 0xFFFFFFFF;

// =============================================================================
// Return values
// =============================================================================

pub const SFILE_INVALID_SIZE: u32 = 0xFFFFFFFF;
pub const SFILE_INVALID_POS: u32 = 0xFFFFFFFF;
pub const SFILE_INVALID_ATTRIBUTES: u32 = 0xFFFFFFFF;

// =============================================================================
// Flags for TMPQArchive::dwFlags (internal)
// =============================================================================

/// If set, the MPQ has been open for read-only access
pub const MPQ_FLAG_READ_ONLY: u32 = 0x00000001;

/// If set, the MPQ tables have been changed
pub const MPQ_FLAG_CHANGED: u32 = 0x00000002;

/// Malformed data structure detected (W3M map protectors)
pub const MPQ_FLAG_MALFORMED: u32 = 0x00000004;

/// The hash table goes beyond EOF
pub const MPQ_FLAG_HASH_TABLE_CUT: u32 = 0x00000008;

/// The block table goes beyond EOF
pub const MPQ_FLAG_BLOCK_TABLE_CUT: u32 = 0x00000010;

/// Checking sector CRC when reading files
pub const MPQ_FLAG_CHECK_SECTOR_CRC: u32 = 0x00000020;

/// If set, we are saving MPQ internal files and MPQ tables
pub const MPQ_FLAG_SAVING_TABLES: u32 = 0x00000040;

/// If set, this MPQ is a patch archive
pub const MPQ_FLAG_PATCH: u32 = 0x00000080;

/// If set, this MPQ is from Starcraft I BETA
pub const MPQ_FLAG_STARCRAFT_BETA: u32 = 0x00000100;

/// If set, this MPQ is from Starcraft I
pub const MPQ_FLAG_STARCRAFT: u32 = 0x00000200;

/// If set, this MPQ is a Warcraft III map
pub const MPQ_FLAG_WAR3_MAP: u32 = 0x00000400;

/// Set when no (listfile) was found
pub const MPQ_FLAG_LISTFILE_NONE: u32 = 0x00000800;

/// Set when (listfile) invalidated
pub const MPQ_FLAG_LISTFILE_NEW: u32 = 0x00001000;

/// Save updated listfile on exit
pub const MPQ_FLAG_LISTFILE_FORCE: u32 = 0x00002000;

/// Set when no (attributes) was found
pub const MPQ_FLAG_ATTRIBUTES_NONE: u32 = 0x00004000;

/// Set when (attributes) invalidated
pub const MPQ_FLAG_ATTRIBUTES_NEW: u32 = 0x00008000;

/// Set when no (signature) was found
pub const MPQ_FLAG_SIGNATURE_NONE: u32 = 0x00010000;

/// Set when (signature) invalidated
pub const MPQ_FLAG_SIGNATURE_NEW: u32 = 0x00020000;

// =============================================================================
// Values for TMPQArchive::dwSubType
// =============================================================================

/// The file is a MPQ file (Blizzard games)
pub const MPQ_SUBTYPE_MPQ: u32 = 0x00000000;

/// The file is a SQP file (War of the Immortals)
pub const MPQ_SUBTYPE_SQP: u32 = 0x00000001;

/// The file is a MPK file (Longwu Online)
pub const MPQ_SUBTYPE_MPK: u32 = 0x00000002;

// =============================================================================
// Flags for TMPQBlock::dwFlags (file flags)
// =============================================================================

/// Implode method (By PKWARE Data Compression Library)
pub const MPQ_FILE_IMPLODE: u32 = 0x00000100;

/// Compress methods (By multiple methods)
pub const MPQ_FILE_COMPRESS: u32 = 0x00000200;

/// Indicates an encrypted file
pub const MPQ_FILE_ENCRYPTED: u32 = 0x00010000;

/// Indicates an encrypted file with key v2
pub const MPQ_FILE_KEY_V2: u32 = 0x00020000;

/// The file is a patch file. Raw file data begin with TPatchInfo structure
pub const MPQ_FILE_PATCH_FILE: u32 = 0x00100000;

/// File is stored as a single unit, rather than split into sectors
pub const MPQ_FILE_SINGLE_UNIT: u32 = 0x01000000;

/// File is a deletion marker
pub const MPQ_FILE_DELETE_MARKER: u32 = 0x02000000;

/// File has checksums for each sector
pub const MPQ_FILE_SECTOR_CRC: u32 = 0x04000000;

/// Present on STANDARD.SNP\(signature)
pub const MPQ_FILE_SIGNATURE: u32 = 0x10000000;

/// Set if file exists, reset when the file was deleted
pub const MPQ_FILE_EXISTS: u32 = 0x80000000;

/// Mask for a file being compressed
pub const MPQ_FILE_COMPRESS_MASK: u32 = 0x0000FF00;

// =============================================================================
// Block index mask
// =============================================================================

/// We need to mask out the upper 4 bits of the block table index.
pub const BLOCK_INDEX_MASK: u32 = 0x0FFFFFFF;

// =============================================================================
// Compression types
// =============================================================================

/// Huffmann compression (used on WAVE files only)
pub const MPQ_COMPRESSION_HUFFMANN: u8 = 0x01;

/// ZLIB compression
pub const MPQ_COMPRESSION_ZLIB: u8 = 0x02;

/// PKWARE DCL compression
pub const MPQ_COMPRESSION_PKWARE: u8 = 0x08;

/// BZIP2 compression (added in Warcraft III)
pub const MPQ_COMPRESSION_BZIP2: u8 = 0x10;

/// Run-length (sparse) compression (added in Starcraft 2)
pub const MPQ_COMPRESSION_SPARSE: u8 = 0x20;

/// IMA ADPCM compression (mono)
pub const MPQ_COMPRESSION_ADPCM_MONO: u8 = 0x40;

/// IMA ADPCM compression (stereo)
pub const MPQ_COMPRESSION_ADPCM_STEREO: u8 = 0x80;

/// LZMA compression (added in Starcraft 2)
pub const MPQ_COMPRESSION_LZMA: u8 = 0x12;

// =============================================================================
// HET and BET table signatures
// =============================================================================

/// 'HET\x1a'
pub const HET_TABLE_SIGNATURE: u32 = 0x1A544548;

/// 'BET\x1a'
pub const BET_TABLE_SIGNATURE: u32 = 0x1A544542;

/// Maximum acceptable size of HET&BET tables
pub const BET_TABLE_MAX_SIZE: u32 = 0x00100000;

// =============================================================================
// Decryption keys for MPQ tables
// =============================================================================

/// Key for hash table - HashString("(hash table)", MPQ_HASH_FILE_KEY)
pub const MPQ_KEY_HASH_TABLE: u32 = 0xC3AF3770;

/// Key for block table - HashString("(block table)", MPQ_HASH_FILE_KEY)
pub const MPQ_KEY_BLOCK_TABLE: u32 = 0xEC83B3A3;

// =============================================================================
// Internal file names
// =============================================================================

pub const LISTFILE_NAME: &str = "(listfile)";
pub const SIGNATURE_NAME: &str = "(signature)";
pub const ATTRIBUTES_NAME: &str = "(attributes)";
pub const PATCH_METADATA_NAME: &str = "(patch_metadata)";

// =============================================================================
// MPQ format versions
// =============================================================================

/// Up to The Burning Crusade
pub const MPQ_FORMAT_VERSION_1: u16 = 0;

/// The Burning Crusade and newer
pub const MPQ_FORMAT_VERSION_2: u16 = 1;

/// WoW Cataclysm Beta
pub const MPQ_FORMAT_VERSION_3: u16 = 2;

/// WoW Cataclysm and newer
pub const MPQ_FORMAT_VERSION_4: u16 = 3;

// =============================================================================
// MPQ header sizes
// =============================================================================

pub const MPQ_HEADER_SIZE_V1: u32 = 0x20;
pub const MPQ_HEADER_SIZE_V2: u32 = 0x2C;
pub const MPQ_HEADER_SIZE_V3: u32 = 0x44;
pub const MPQ_HEADER_SIZE_V4: u32 = 0xD0;
pub const MPQ_HEADER_DWORDS: u32 = MPQ_HEADER_SIZE_V4 / 0x04;

// =============================================================================
// Flags for MPQ attributes
// =============================================================================

/// The "(attributes)" contains CRC32 for each file
pub const MPQ_ATTRIBUTE_CRC32: u32 = 0x00000001;

/// The "(attributes)" contains file time for each file
pub const MPQ_ATTRIBUTE_FILETIME: u32 = 0x00000002;

/// The "(attributes)" contains MD5 for each file
pub const MPQ_ATTRIBUTE_MD5: u32 = 0x00000004;

/// The "(attributes)" contains a patch bit for each file
pub const MPQ_ATTRIBUTE_PATCH_BIT: u32 = 0x00000008;

/// Summary mask
pub const MPQ_ATTRIBUTE_ALL: u32 = 0x0000000F;

pub const MPQ_ATTRIBUTES_V1: u32 = 100;

// =============================================================================
// Hash type constants
// =============================================================================

pub const MPQ_HASH_TABLE_INDEX: u32 = 0x000;
pub const MPQ_HASH_NAME_A: u32 = 0x100;
pub const MPQ_HASH_NAME_B: u32 = 0x200;
pub const MPQ_HASH_FILE_KEY: u32 = 0x300;
pub const MPQ_HASH_KEY2_MIX: u32 = 0x400;

// =============================================================================
// Flags for SFileOpenArchive
// =============================================================================

/// Base data source is a file
pub const BASE_PROVIDER_FILE: u32 = 0x00000000;

/// Stream is linear with no offset mapping
pub const STREAM_PROVIDER_FLAT: u32 = 0x00000000;

/// Stream is read only
pub const STREAM_FLAG_READ_ONLY: u32 = 0x00000100;

/// Don't load the internal listfile
pub const MPQ_OPEN_NO_LISTFILE: u32 = 0x00010000;

/// Don't open the attributes
pub const MPQ_OPEN_NO_ATTRIBUTES: u32 = 0x00020000;

/// Don't search for the MPQ header past the begin of the file
pub const MPQ_OPEN_NO_HEADER_SEARCH: u32 = 0x00040000;

/// Always open the archive as MPQ v 1.00
pub const MPQ_OPEN_FORCE_MPQ_V1: u32 = 0x00080000;

/// On files with MPQ_FILE_SECTOR_CRC, the CRC will be checked when reading file
pub const MPQ_OPEN_CHECK_SECTOR_CRC: u32 = 0x00100000;

/// This archive is a patch MPQ
pub const MPQ_OPEN_PATCH: u32 = 0x00200000;

/// Force add listfile even if there is none
pub const MPQ_OPEN_FORCE_LISTFILE: u32 = 0x00400000;

/// Open archive as read-only
pub const MPQ_OPEN_READ_ONLY: u32 = STREAM_FLAG_READ_ONLY;

// =============================================================================
// MD5 digest size
// =============================================================================

pub const MD5_DIGEST_SIZE: usize = 0x10;

// =============================================================================
// Patch file constants
// =============================================================================

/// 'PTCH' signature for patch header
pub const MPQ_PATCH_SIGNATURE: u32 = 0x48435450;

/// 'MD5_' signature for MD5 patch
pub const MPQ_PATCH_MD5_SIGNATURE: u32 = 0x5F35444D;

/// 'XFRM' signature for XFRM patch
pub const MPQ_PATCH_XFRM_SIGNATURE: u32 = 0x4D524658;

/// 'BSD0' signature for BSDIFF40 patch (BSDIFF40)
/// Actually, BSDIFF40 starts with "BSDIFF40" string (8 bytes)
pub const BSDIFF40_SIGNATURE: &[u8; 8] = b"BSDIFF40";
