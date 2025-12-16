//! Error types for MPQ operations.
//! Ported from StormLib.h error codes.

use std::io;

/// Result type for MPQ operations.
pub type MpqResult<T> = Result<T, MpqError>;

/// MPQ-specific error codes.
/// Ported from StormLib.h lines 156-166.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MpqErrorKind {
    /// Not a MPQ file, but an AVI file.
    AviFile = 10000,
    /// Returned by SFileReadFile when can't find file key.
    UnknownFileKey = 10001,
    /// Returned by SFileReadFile when sector CRC doesn't match.
    ChecksumError = 10002,
    /// The given operation is not allowed on internal file.
    InternalFile = 10003,
    /// The file is present as incremental patch file, but base file is missing.
    BaseFileMissing = 10004,
    /// The file was marked as "deleted" in the MPQ.
    MarkedForDelete = 10005,
    /// The required file part is missing.
    FileIncomplete = 10006,
    /// A name of at least one file is unknown.
    UnknownFileNames = 10007,
    /// StormLib was unable to find patch prefix for the patches.
    CantFindPatchPrefix = 10008,
    /// The header at this position is fake header.
    FakeMpqHeader = 10009,
    /// The file is present but contains delete marker.
    FileDeleted = 10010,
}

/// Main error type for MPQ operations.
#[derive(Debug)]
pub enum MpqError {
    /// MPQ-specific error.
    Mpq(MpqErrorKind),
    /// Standard I/O error.
    Io(io::Error),
    /// File not found.
    FileNotFound,
    /// Invalid archive format.
    InvalidArchive,
    /// Invalid MPQ header.
    InvalidHeader,
    /// Decompression failed.
    DecompressionFailed,
    /// Compression failed.
    CompressionFailed,
    /// Unsupported compression type.
    UnsupportedCompression(u8),
    /// Buffer too small.
    BufferTooSmall,
    /// Invalid parameter.
    InvalidParameter,
    /// Disk full or hash table full.
    DiskFull,
    /// File already exists.
    AlreadyExists,
    /// Data missing (partial MPQ).
    DataMissing,
    /// Generic error.
    Generic(String),
}

impl std::fmt::Display for MpqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MpqError::Mpq(kind) => write!(f, "MPQ error: {:?}", kind),
            MpqError::Io(e) => write!(f, "I/O error: {}", e),
            MpqError::FileNotFound => write!(f, "File not found"),
            MpqError::InvalidArchive => write!(f, "Invalid archive format"),
            MpqError::InvalidHeader => write!(f, "Invalid MPQ header"),
            MpqError::DecompressionFailed => write!(f, "Decompression failed"),
            MpqError::CompressionFailed => write!(f, "Compression failed"),
            MpqError::UnsupportedCompression(t) => {
                write!(f, "Unsupported compression type: 0x{:02X}", t)
            }
            MpqError::BufferTooSmall => write!(f, "Buffer too small"),
            MpqError::InvalidParameter => write!(f, "Invalid parameter"),
            MpqError::DiskFull => write!(f, "Disk full or hash table full"),
            MpqError::AlreadyExists => write!(f, "File already exists"),
            MpqError::DataMissing => write!(f, "Data missing (partial MPQ)"),
            MpqError::Generic(msg) => write!(f, "Generic error: {}", msg),
        }
    }
}

impl std::error::Error for MpqError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MpqError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for MpqError {
    fn from(e: io::Error) -> Self {
        MpqError::Io(e)
    }
}
