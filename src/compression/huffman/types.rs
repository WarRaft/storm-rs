//! Huffman tree structures.
//! Ported from StormLib/src/huffman/huff.h

/// Insertion point for new items in the linked list.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InsertPoint {
    After = 1,
    Before = 2,
}

/// Huffman tree item.
/// Corresponds to THTreeItem in StormLib.
#[derive(Clone, Copy, Debug, Default)]
pub struct TreeNode {
    /// Pointer to lower-weight tree item (next in list)
    pub next: Option<u16>,
    /// Pointer to higher-weight item (prev in list)
    pub prev: Option<u16>,
    /// Decompressed byte value (also index in the array)
    pub decompressed_value: u32,
    /// Weight
    pub weight: u32,
    /// Pointer to parent item (None if none)
    pub parent: Option<u16>,
    /// Pointer to the child with lower-weight child ("left child")
    pub child_lo: Option<u16>,
}

/// Structure used for quick navigating in the huffman tree.
/// Allows skipping up to 7 bits in the compressed stream.
/// Corresponds to TQuickLink in StormLib.
#[derive(Clone, Copy, Debug, Default)]
pub struct QuickLink {
    /// If greater than MinValidValue, the entry is valid
    pub valid_value: u32,
    /// Number of bits that are valid for this item link
    pub valid_bits: u32,
    /// Pointer to the item within the Huffman tree (index)
    pub item: Option<u16>,
    /// Value for direct decompression (used if valid_bits <= 7)
    pub decompressed_value: u32,
}
