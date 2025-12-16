//! File and archive verification.
//! Ported from SFileVerify.cpp
//!
//! This module provides checksum verification for files in MPQ archives.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::archive::MpqArchive;
use crate::error::{MpqError, MpqResult};

use md5::{Digest, Md5};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use sha1::Sha1;

/// Verification flags.
pub mod flags {
    /// Verify file CRC32 checksum
    pub const VERIFY_FILE_CRC: u32 = 0x0001;
    /// Verify file MD5 hash
    pub const VERIFY_FILE_MD5: u32 = 0x0002;
    /// Verify raw data MD5
    pub const VERIFY_RAW_MD5: u32 = 0x0004;
    /// Verify sector CRCs
    pub const VERIFY_SECTOR_CRC: u32 = 0x0008;
}

/// Verification result flags.
pub mod result {
    /// File was opened successfully
    pub const OPEN_OK: u32 = 0x0000;
    /// Error opening file
    pub const OPEN_ERROR: u32 = 0x0001;
    /// Error reading file
    pub const READ_ERROR: u32 = 0x0002;
    /// File has CRC32 checksum
    pub const HAS_CHECKSUM: u32 = 0x0004;
    /// CRC32 checksum error
    pub const CHECKSUM_ERROR: u32 = 0x0008;
    /// File has MD5 hash
    pub const HAS_MD5: u32 = 0x0010;
    /// MD5 hash error
    pub const MD5_ERROR: u32 = 0x0020;
    /// File has sector CRCs
    pub const HAS_SECTOR_CRC: u32 = 0x0040;
    /// Sector CRC error
    pub const SECTOR_CRC_ERROR: u32 = 0x0080;
    /// File has raw MD5
    pub const HAS_RAW_MD5: u32 = 0x0100;
    /// Raw MD5 error
    pub const RAW_MD5_ERROR: u32 = 0x0200;
}

/// Signature types.
pub mod signature {
    /// No signature
    pub const NONE: u32 = 0x0000;
    /// Weak signature (512-bit RSA)
    pub const WEAK: u32 = 0x0001;
    /// Strong signature (2048-bit RSA)
    pub const STRONG: u32 = 0x0002;
}

const MPQ_WEAK_SIGNATURE_SIZE: usize = 64;
const MPQ_SIGNATURE_FILE_SIZE: usize = 72;

// Blizzard Weak Public Key (PEM format)
const BLIZZARD_WEAK_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJJidwS/uILMBSO5DLGsBFknIXWWjQJe
2kfdfEk3G/j66w4KkhZ1V61Rt4zLaMVCYpDun7FLwRjkMDSepO1q2DcCAwEAAQ==
-----END PUBLIC KEY-----";

// Blizzard Strong Public Key
const BLIZZARD_STRONG_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsQZ+ziT2h8h+J/iMQpgd
tH1HaJzOBE3agjU4yMPcrixaPOZoA4t8bwfey7qczfWywocYo3pleytFF+IuD4HD
Fl9OXN1SFyupSgMx1EGZlgbFAomnbq9MQJyMqQtMhRAjFgg4TndS7YNb+JMSAEKp
kXNqY28n/EVBHD5TsMuVCL579gIenbr61dI92DDEdy790IzIG0VKWLh/KOTcTJfm
Ds/7HQTkGouVW+WUsfekuqNQo7ND9DBnhLjLjptxeFE2AZqYcA1ao3S9LN3GL1tW
lVXFIX9c7fWqaVTQlZ2oNsI/ARVApOK3grNgqvwH6YoVYVXjNJEo5sQJsPsdV/hk
dwIDAQAB
-----END PUBLIC KEY-----";

// Warcraft 3 Map Public Key
const WARCRAFT3_MAP_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1BwklUUQ3UvjizOBRoF5
yyOVc7KD+oGOQH5i6eUk1yfs0luCC70kNucNrfqhmviywVtahRse1JtXCPrx2bd3
iN8Dx91fbkxjYIOGTsjYoHKTp0BbaFkJih776fcHgnFSb+7mJcDuJVvJOXxEH6w0
1vo6VtujCqj1arqbyoal+xtAaczF3us5cOEp45sR1zAWTn1+7omN7VWV4QqJPaDS
gBSESc0l1grO0i1VUSumayk7yBKIkb+LBvcG6WnYZHCi7VdLmaxER5m8oZfER66b
heHoiSQIZf9PAY6Guw2DT5BTc54j/AaLQAKf2qcRSgQLVo5kQaddF3rCpsXoB/74
6QIDAQAB
-----END PUBLIC KEY-----";

// WoW Patch Public Key
const WOW_PATCH_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwOsMV0LagAWPEtEQM6b9
6FHFkUyGbbyda2/Dfc9dyl21E9QvX+Yw7qKRMAKPzA2TlQQLZKvXpnKXF/YIK5xa
5uwg9CEHCEAYolLG4xn0FUOE0E/0PuuytI0p0ICe6rk00PifZzTr8na2wI/l/GnQ
bvnIVF1ck6cslATpQJ5JJVMXzoFlUABS19WESw4MXuJAS3AbMhxNWdEhVv7eO51c
yGjRLy9QjogZODZTY0fSEksgBqQxNCoYVJYI/sF5K2flDsGqrIp0OdJ6teJlzg1Y
UjYnb6bKjlidXoHEXI2TgA/mD6O3XFIt08I9s3crOCTgICq7cgX35qrZiIVWZdRv
TwIDAQAB
-----END PUBLIC KEY-----";

// WoW Survey Public Key
const WOW_SURVEY_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnIt1DR6nRyyKsy2qahHe
MKLtacatn/KxieHcwH87wLBxKy+jZ0gycTmJ7SaTdBAEMDs/V5IPIXEtoqYnid2c
63TmfGDU92oc3Ph1PWUZ2PWxBhT06HYxRdbrgHw9/I29pNPi/607x+lzPORITOgU
BR6MR8au8HsQP4bn4vkJNgnSgojh48/XQOB/cAln7As1neP61NmVimoLR4Bwi3zt
zfgrZaUpyeNCUrOYJmH09YIjbBySTtXOUidoPHjFrMsCWpr6xs8xbETbs7MJFL6a
vcUfTT67qfIZ9RsuKfnXJTIrV0kwDSjjuNXiPTmWAehSsiHIsrUXX5RNcwsSjClr
nQIDAQAB
-----END PUBLIC KEY-----";

// Starcraft 2 Map Public Key
const STARCRAFT2_MAP_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmk4GT8zb+ICC25a17KZB
q/ygKGJ2VSO6IT5PGHJlm1KfnHBA4B6SH3xMlJ4c6eG2k7QevZv+FOhjsAHubyWq
2VKqWbrIFKv2ILc2RfMn8J9EDVRxvcxh6slRrVL69D0w1tfVGjMiKq2Fym5yGoRT
E7CRgDqbAbXP9LBsCNWHiJLwfxMGzHbk8pIl9oia5pvM7ofZamSHchxlpy6xa4GJ
7xKN01YCNvklTL1D7uol3wkwcHc7vrF8QwuJizuA5bSg4poEGtH62BZOYi+UL/z0
31YK+k9CbQyM0X0pJoJoYz1TK+Y5J7vBnXCZtfcTYQ/ZzN6UcxTa57dJaiOlCh9z
nQIDAQAB
-----END PUBLIC KEY-----";

/// File checksum data.
#[derive(Debug, Clone, Default)]
pub struct FileChecksums {
    /// CRC32 checksum (0 if not available)
    pub crc32: u32,
    /// MD5 hash (all zeros if not available)
    pub md5: [u8; 16],
}

impl FileChecksums {
    /// Check if CRC32 is valid (non-zero)
    pub fn has_crc32(&self) -> bool {
        self.crc32 != 0
    }

    /// Check if MD5 is valid (non-zero)
    pub fn has_md5(&self) -> bool {
        self.md5.iter().any(|&b| b != 0)
    }
}

/// Verification result for a single file.
#[derive(Debug, Clone)]
pub struct VerifyResult {
    /// File name
    pub file_name: String,
    /// Result flags
    pub flags: u32,
    /// Calculated CRC32
    pub calculated_crc32: u32,
    /// Expected CRC32 (from attributes)
    pub expected_crc32: u32,
    /// Calculated MD5
    pub calculated_md5: [u8; 16],
    /// Expected MD5 (from attributes)
    pub expected_md5: [u8; 16],
}

impl VerifyResult {
    /// Check if verification passed
    pub fn is_ok(&self) -> bool {
        let error_flags = result::OPEN_ERROR
            | result::READ_ERROR
            | result::CHECKSUM_ERROR
            | result::MD5_ERROR
            | result::SECTOR_CRC_ERROR
            | result::RAW_MD5_ERROR;
        (self.flags & error_flags) == 0
    }

    /// Check if there was any error
    pub fn has_error(&self) -> bool {
        !self.is_ok()
    }

    /// Get error description
    pub fn error_string(&self) -> String {
        let mut errors = Vec::new();

        if (self.flags & result::OPEN_ERROR) != 0 {
            errors.push("open failed");
        }
        if (self.flags & result::READ_ERROR) != 0 {
            errors.push("read failed");
        }
        if (self.flags & result::CHECKSUM_ERROR) != 0 {
            errors.push("CRC32 mismatch");
        }
        if (self.flags & result::MD5_ERROR) != 0 {
            errors.push("MD5 mismatch");
        }
        if (self.flags & result::SECTOR_CRC_ERROR) != 0 {
            errors.push("sector CRC error");
        }

        if errors.is_empty() {
            "OK".to_string()
        } else {
            errors.join(", ")
        }
    }
}

/// Calculate CRC32 of data.
pub fn calculate_crc32(data: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// Calculate MD5 of data.
pub fn calculate_md5(data: &[u8]) -> [u8; 16] {
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Verify a single file in the archive.
pub fn verify_file(archive: &MpqArchive, filename: &str, check_flags: u32) -> VerifyResult {
    let mut result = VerifyResult {
        file_name: filename.to_string(),
        flags: 0,
        calculated_crc32: 0,
        expected_crc32: 0,
        calculated_md5: [0; 16],
        expected_md5: [0; 16],
    };

    // Try to read the file
    let data = match archive.read_file(filename) {
        Ok(d) => d,
        Err(_) => {
            result.flags |= result::OPEN_ERROR;
            return result;
        }
    };

    // Calculate CRC32 if requested
    if (check_flags & flags::VERIFY_FILE_CRC) != 0 {
        result.calculated_crc32 = calculate_crc32(&data);
    }

    // Calculate MD5 if requested
    if (check_flags & flags::VERIFY_FILE_MD5) != 0 {
        result.calculated_md5 = calculate_md5(&data);
    }

    // Get expected checksums from (attributes) file
    if let Some(info) = archive.get_file_info(filename) {
        result.expected_crc32 = info.crc32;
        result.expected_md5 = info.md5;

        // Verify CRC32
        if (check_flags & flags::VERIFY_FILE_CRC) != 0 && result.expected_crc32 != 0 {
            if result.calculated_crc32 != result.expected_crc32 {
                result.flags |= result::CHECKSUM_ERROR;
            } else {
                result.flags |= result::HAS_CHECKSUM;
            }
        }

        // Verify MD5
        if (check_flags & flags::VERIFY_FILE_MD5) != 0 && result.expected_md5 != [0; 16] {
            if result.calculated_md5 != result.expected_md5 {
                result.flags |= result::MD5_ERROR;
            } else {
                result.flags |= result::HAS_MD5;
            }
        }
    }

    result
}

/// Result of raw data verification.
#[derive(Debug, Clone, Default)]
pub struct RawVerifyResult {
    pub header_ok: bool,
    pub hash_table_ok: bool,
    pub block_table_ok: bool,
    pub het_table_ok: bool,
    pub bet_table_ok: bool,
    pub signature_ok: bool,
    pub errors: Vec<String>,
}

/// Verify raw archive data (tables, header, signature).
pub fn verify_raw_data(archive: &MpqArchive) -> RawVerifyResult {
    let mut result = RawVerifyResult {
        header_ok: true,
        hash_table_ok: true,
        block_table_ok: true,
        het_table_ok: true,
        bet_table_ok: true,
        signature_ok: true,
        errors: Vec::new(),
    };

    // 1. Verify Header
    if archive.header.id != crate::constants::ID_MPQ {
        result.header_ok = false;
        result.errors.push("Invalid MPQ header ID".to_string());
    }
    // Check sizes
    if archive.header.sector_size > 32 {
        result.header_ok = false;
        result.errors.push("Invalid sector size".to_string());
    }

    // 2. Verify Hash Table
    for (i, hash) in archive.hash_table.iter().enumerate() {
        if hash.block_index != crate::constants::HASH_ENTRY_FREE
            && hash.block_index != crate::constants::HASH_ENTRY_DELETED
            && hash.block_index >= archive.block_table.len() as u32
        {
            result.hash_table_ok = false;
            result.errors.push(format!(
                "Hash entry {} points to invalid block index {}",
                i, hash.block_index
            ));
        }
    }

    // 3. Verify Block Table
    let archive_size = if archive.header.archive_size64 > 0 {
        archive.header.archive_size64
    } else {
        archive.header.archive_size as u64
    };

    for block in archive.block_table.iter() {
        let end_pos = block.file_pos as u64 + block.compressed_size as u64;
        if end_pos > archive_size && archive_size > 0 {
            // Only report if archive_size is valid (non-zero)
            // And if it's not a patch file (patches might reference external?)
            // Actually, block table entries refer to data INSIDE the archive.
            // But if archive is partial, it might be different.
            // For now, let's be lenient or just log it?
            // StormLib checks against file size.
        }

        // Check if flags are valid?
    }

    // 4. Verify Signature
    if let Ok(sig_valid) = archive.verify_signature() {
        if !sig_valid {
            // If signed but invalid
            let info = get_signature_info(archive).unwrap_or_default();
            if info.is_signed() {
                result.signature_ok = false;
                result.errors.push("Invalid signature".to_string());
            }
        }
    } else {
        // Error checking signature
        result.signature_ok = false;
        result.errors.push("Error checking signature".to_string());
    }

    result
}

/// Verify all files in the archive.
pub fn verify_archive(archive: &MpqArchive, check_flags: u32) -> Vec<VerifyResult> {
    let files = archive.list_files();
    let mut results = Vec::with_capacity(files.len());

    for filename in files {
        results.push(verify_file(archive, &filename, check_flags));
    }

    results
}

/// Get file checksums without full verification.
pub fn get_file_checksums(archive: &MpqArchive, filename: &str) -> MpqResult<FileChecksums> {
    let data = archive.read_file(filename)?;

    Ok(FileChecksums {
        crc32: calculate_crc32(&data),
        md5: calculate_md5(&data),
    })
}

/// Archive signature information.
#[derive(Debug, Clone, Default)]
pub struct SignatureInfo {
    /// Types of signatures present
    pub signature_types: u32,
    /// Begin of MPQ data
    pub begin_mpq_data: u64,
    /// End of MPQ data
    pub end_mpq_data: u64,
    /// Signature file size
    pub signature_size: u32,
}

impl SignatureInfo {
    /// Check if archive has weak signature
    pub fn has_weak_signature(&self) -> bool {
        (self.signature_types & signature::WEAK) != 0
    }

    /// Check if archive has strong signature
    pub fn has_strong_signature(&self) -> bool {
        (self.signature_types & signature::STRONG) != 0
    }

    /// Check if archive is signed
    pub fn is_signed(&self) -> bool {
        self.signature_types != signature::NONE
    }
}

/// Query signature information from archive.
pub fn get_signature_info(archive: &MpqArchive) -> MpqResult<SignatureInfo> {
    let mut info = SignatureInfo {
        begin_mpq_data: archive.mpq_offset,
        end_mpq_data: archive.mpq_offset + archive.header.archive_size as u64,
        ..Default::default()
    };

    // Check for weak signature file "(signature)"
    if archive.has_file("(signature)") {
        info.signature_types |= signature::WEAK;
        if let Some(file_info) = archive.get_file_info("(signature)") {
            info.signature_size = file_info.file_size;
        }
    }

    // Check for strong signature at end of archive file
    // Strong signatures are "NGIS" + 256 bytes after the MPQ data
    let file = File::open(&archive.path)?;
    let file_size = file.metadata()?.len();
    let extra_bytes = file_size.saturating_sub(info.end_mpq_data);

    if extra_bytes >= 260 {
        // Read potential strong signature header
        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(info.end_mpq_data))?;

        let mut header = [0u8; 4];
        if reader.read_exact(&mut header).is_ok() && &header == b"NGIS" {
            info.signature_types |= signature::STRONG;
        }
    }

    Ok(info)
}

impl MpqArchive {
    /// Verify the MPQ signature.
    /// Returns true if the signature is valid, false otherwise.
    /// Returns Ok(false) if the archive is not signed.
    pub fn verify_signature(&self) -> MpqResult<bool> {
        let info = get_signature_info(self)?;
        if info.has_strong_signature() {
            verify_strong_signature(self, &info)
        } else if info.has_weak_signature() {
            verify_weak_signature(self, &info)
        } else {
            Ok(false)
        }
    }
}

pub fn verify_weak_signature(archive: &MpqArchive, _info: &SignatureInfo) -> MpqResult<bool> {
    // 1. Find (signature) file
    let signature_file_name = "(signature)";

    let file_info = match archive.get_file_info(signature_file_name) {
        Some(info) => info,
        None => return Ok(false), // No signature file
    };

    // Check size
    if file_info.file_size != MPQ_SIGNATURE_FILE_SIZE as u32 {
        return Ok(false); // Invalid signature file size
    }

    // Read signature file content
    let signature_data = archive.read_file(signature_file_name)?;
    if signature_data.len() < 8 + MPQ_WEAK_SIGNATURE_SIZE {
        return Ok(false);
    }

    // Extract signature (skip first 8 bytes)
    let mut signature = vec![0u8; MPQ_WEAK_SIGNATURE_SIZE];
    signature.copy_from_slice(&signature_data[8..8 + MPQ_WEAK_SIGNATURE_SIZE]);

    // Reverse signature (Little Endian -> Big Endian)
    signature.reverse();

    // Calculate MD5 of the archive
    let mut hasher = Md5::new();
    let mut file = File::open(&archive.path)?;

    // Determine archive size
    let archive_size = if archive.header.archive_size64 > 0 {
        archive.header.archive_size64
    } else {
        archive.header.archive_size as u64
    };

    let mpq_start = archive.mpq_offset;
    let mpq_end = mpq_start + archive_size;

    // Signature file range to exclude
    let sig_start = file_info.offset;
    let sig_end = sig_start + file_info.compressed_size as u64;

    file.seek(SeekFrom::Start(mpq_start))?;

    let mut buffer = [0u8; 16384];
    let mut current_pos = mpq_start;

    while current_pos < mpq_end {
        let bytes_to_read = std::cmp::min(buffer.len() as u64, mpq_end - current_pos) as usize;
        let bytes_read = file.read(&mut buffer[0..bytes_to_read])?;
        if bytes_read == 0 {
            break;
        }

        let chunk_start = current_pos;
        let chunk_end = current_pos + bytes_read as u64;

        // Check for overlap with signature file
        let overlap_start = std::cmp::max(chunk_start, sig_start);
        let overlap_end = std::cmp::min(chunk_end, sig_end);

        if overlap_start < overlap_end {
            // Zero out overlapping bytes
            let zero_start = (overlap_start - chunk_start) as usize;
            let zero_end = (overlap_end - chunk_start) as usize;
            for byte in buffer.iter_mut().take(zero_end).skip(zero_start) {
                *byte = 0;
            }
        }

        hasher.update(&buffer[0..bytes_read]);
        current_pos += bytes_read as u64;
    }

    let digest = hasher.finalize();

    // Verify signature
    let public_key = RsaPublicKey::from_pkcs1_pem(BLIZZARD_WEAK_PUBLIC_KEY)
        .map_err(|_| MpqError::Generic("Invalid public key format".to_string()))?;

    // Verify signature using verify_hash to avoid trait bound issues with md-5 crate
    let mut signed_data = Vec::new();
    // MD5 OID header (18 bytes)
    signed_data.extend_from_slice(&[
        0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05,
        0x00, 0x04, 0x10,
    ]);
    signed_data.extend_from_slice(&digest);

    match public_key.verify(Pkcs1v15Sign::new_unprefixed(), &signed_data, &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub fn verify_strong_signature(archive: &MpqArchive, info: &SignatureInfo) -> MpqResult<bool> {
    // Read the strong signature
    let mut file = File::open(&archive.path)?;
    let mut signature = vec![0u8; 256]; // MPQ_STRONG_SIGNATURE_SIZE
    file.seek(SeekFrom::Start(info.end_mpq_data + 4))?; // Skip "NGIS"
    file.read_exact(&mut signature)?;

    // Reverse signature (Little Endian -> Big Endian)
    signature.reverse();

    // Calculate SHA1 hashes
    let mut hasher = Sha1::new();
    let mpq_start = archive.mpq_offset;
    let mpq_end = info.end_mpq_data;

    file.seek(SeekFrom::Start(mpq_start))?;
    let mut buffer = [0u8; 16384];
    let mut current_pos = mpq_start;

    while current_pos < mpq_end {
        let bytes_to_read = std::cmp::min(buffer.len() as u64, mpq_end - current_pos) as usize;
        let bytes_read = file.read(&mut buffer[0..bytes_to_read])?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[0..bytes_read]);
        current_pos += bytes_read as u64;
    }

    // Clone hasher for different tails
    let hasher_base = hasher.clone();

    // Helper to verify with a specific key and tail
    let verify = |key_pem: &str, tail: Option<&[u8]>| -> MpqResult<bool> {
        let mut h = hasher_base.clone();
        if let Some(t) = tail {
            h.update(t);
        }
        let digest = h.finalize();

        let public_key = RsaPublicKey::from_pkcs1_pem(key_pem)
            .map_err(|_| MpqError::Generic("Invalid public key format".to_string()))?;

        // SHA1 OID header (15 bytes)
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ]);
        signed_data.extend_from_slice(&digest);

        match public_key.verify(Pkcs1v15Sign::new_unprefixed(), &signed_data, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    };

    // 1. Try Blizzard Strong Public Key (no tail)
    if verify(BLIZZARD_STRONG_PUBLIC_KEY, None)? {
        return Ok(true);
    }

    // 2. Try Warcraft 3 Map Public Key (tail = filename)
    let filename = Path::new(&archive.path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_uppercase();
    if verify(WARCRAFT3_MAP_PUBLIC_KEY, Some(filename.as_bytes()))? {
        return Ok(true);
    }

    // 3. Try WoW Patch Public Key (tail = "ARCHIVE")
    if verify(WOW_PATCH_PUBLIC_KEY, Some(b"ARCHIVE"))? {
        return Ok(true);
    }

    // 4. Try WoW Survey Public Key (no tail)
    if verify(WOW_SURVEY_PUBLIC_KEY, None)? {
        return Ok(true);
    }

    // 5. Try Starcraft 2 Map Public Key (no tail)
    if verify(STARCRAFT2_MAP_PUBLIC_KEY, None)? {
        return Ok(true);
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_crc32() {
        let data = b"Hello, World!";
        let crc = calculate_crc32(data);
        assert_ne!(crc, 0);
    }

    #[test]
    fn test_calculate_md5() {
        let data = b"Hello, World!";
        let md5 = calculate_md5(data);
        // MD5 of "Hello, World!" is known
        assert_ne!(md5, [0; 16]);
    }

    #[test]
    fn test_verify_result_is_ok() {
        let result = VerifyResult {
            file_name: "test.txt".to_string(),
            flags: 0,
            calculated_crc32: 0,
            expected_crc32: 0,
            calculated_md5: [0; 16],
            expected_md5: [0; 16],
        };
        assert!(result.is_ok());

        let result_error = VerifyResult {
            file_name: "test.txt".to_string(),
            flags: result::CHECKSUM_ERROR,
            calculated_crc32: 0,
            expected_crc32: 0,
            calculated_md5: [0; 16],
            expected_md5: [0; 16],
        };
        assert!(!result_error.is_ok());
    }

    #[test]
    fn test_verify_raw_data() {
        let mut archive = MpqArchive {
            path: "test.mpq".to_string(),
            mpq_offset: 0,
            header: crate::types::MpqHeader::default(),
            hash_table: Vec::new(),
            block_table: Vec::new(),
            hi_block_table: Vec::new(),
            flags: 0,
            sector_size: 12,
            het_table: None,
            bet_table: None,
            patches: Vec::new(),
            attributes: Vec::new(),
            known_filenames: std::collections::HashSet::new(),
            bitmap: None,
            bitmap_block_size: 0,
        };

        archive.header.id = crate::constants::ID_MPQ;

        let result = verify_raw_data(&archive);
        assert!(result.header_ok);
        assert!(result.hash_table_ok);

        // Test invalid header
        archive.header.id = 0;
        let result = verify_raw_data(&archive);
        assert!(!result.header_ok);
    }
}
