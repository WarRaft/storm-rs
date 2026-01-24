//! Huffman tree logic.
//! Ported from StormLib/src/huffman/huff.cpp

use super::bitstream::BitStream;
use super::constants::*;
use super::types::*;

pub struct HuffmanTree {
    pub nodes: Vec<TreeNode>,
    pub items_used: usize,
    pub first: Option<u16>, // Head of linked list (highest weight)
    pub last: Option<u16>,  // Tail of linked list (lowest weight)
    pub items_by_byte: [Option<u16>; 0x102],
    pub quick_links: [QuickLink; LINK_ITEM_COUNT],
    pub min_valid_value: u32,
    pub is_cmp0: bool,
}

impl HuffmanTree {
    pub fn new(compression: bool) -> Self {
        let mut tree = Self {
            nodes: vec![TreeNode::default(); HUFF_ITEM_COUNT],
            items_used: 0,
            first: None,
            last: None,
            items_by_byte: [None; 0x102],
            quick_links: [QuickLink::default(); LINK_ITEM_COUNT],
            min_valid_value: 1,
            is_cmp0: false,
        };

        if !compression {
            // Invalidate all item links
            for link in tree.quick_links.iter_mut() {
                link.valid_value = 0;
            }
        }

        tree
    }

    // Linked list operations
    fn remove_item(&mut self, item_idx: u16) {
        let prev = self.nodes[item_idx as usize].prev;
        let next = self.nodes[item_idx as usize].next;

        if let Some(p) = prev {
            self.nodes[p as usize].next = next;
        } else if self.first == Some(item_idx) {
            self.first = next;
        }

        if let Some(n) = next {
            self.nodes[n as usize].prev = prev;
        } else if self.last == Some(item_idx) {
            self.last = prev;
        }

        self.nodes[item_idx as usize].prev = None;
        self.nodes[item_idx as usize].next = None;
    }

    fn link_two_items(&mut self, item1_idx: u16, item2_idx: u16) {
        // Insert item2 AFTER item1
        let next = self.nodes[item1_idx as usize].next;
        self.nodes[item2_idx as usize].next = next;

        self.nodes[item2_idx as usize].prev = Some(item1_idx);

        if let Some(n) = next {
            self.nodes[n as usize].prev = Some(item2_idx);
        } else {
            self.last = Some(item2_idx);
        }

        self.nodes[item1_idx as usize].next = Some(item2_idx);
    }

    fn insert_item(&mut self, item_idx: u16, point: InsertPoint, ref_idx: Option<u16>) {
        self.remove_item(item_idx);

        if ref_idx.is_none() {
            // ref_idx is None means LIST_HEAD
            match point {
                InsertPoint::After => {
                    // Insert After LIST_HEAD -> Insert as First (Prepend)
                    let old_first = self.first;
                    self.first = Some(item_idx);
                    self.nodes[item_idx as usize].next = old_first;
                    self.nodes[item_idx as usize].prev = None;

                    if let Some(of) = old_first {
                        self.nodes[of as usize].prev = Some(item_idx);
                    } else {
                        self.last = Some(item_idx);
                    }
                }
                InsertPoint::Before => {
                    // Insert Before LIST_HEAD -> Insert as Last (Append)
                    let old_last = self.last;
                    self.last = Some(item_idx);
                    self.nodes[item_idx as usize].prev = old_last;
                    self.nodes[item_idx as usize].next = None;

                    if let Some(ol) = old_last {
                        self.nodes[ol as usize].next = Some(item_idx);
                    } else {
                        self.first = Some(item_idx);
                    }
                }
            }
            return;
        }

        let r = ref_idx.unwrap();
        match point {
            InsertPoint::After => {
                self.link_two_items(r, item_idx);
            }
            InsertPoint::Before => {
                // Insert Before r
                // Same as Insert After r->prev
                if let Some(prev) = self.nodes[r as usize].prev {
                    self.link_two_items(prev, item_idx);
                } else {
                    // r is first, so insert as first
                    self.insert_item(item_idx, InsertPoint::After, None);
                }
            }
        }
    }

    fn find_higher_or_equal_item(&self, start_item: Option<u16>, weight: u32) -> Option<u16> {
        let mut current = start_item;
        while let Some(idx) = current {
            if self.nodes[idx as usize].weight >= weight {
                return Some(idx);
            }
            current = self.nodes[idx as usize].prev;
        }
        None // Not found, equivalent to LIST_HEAD
    }

    fn create_new_item(&mut self, value: u32, weight: u32, point: InsertPoint) -> Option<u16> {
        if self.items_used >= HUFF_ITEM_COUNT {
            return None;
        }
        let idx = self.items_used as u16;
        self.items_used += 1;

        // Insert relative to LIST_HEAD (None)
        self.insert_item(idx, point, None);

        self.nodes[idx as usize].decompressed_value = value;
        self.nodes[idx as usize].weight = weight;
        self.nodes[idx as usize].parent = None;
        self.nodes[idx as usize].child_lo = None;

        Some(idx)
    }

    fn fixup_item_pos_by_weight(&mut self, item_idx: u16, max_weight: u32) -> u32 {
        let weight = self.nodes[item_idx as usize].weight;
        if weight < max_weight {
            let higher_item = self.find_higher_or_equal_item(self.last, weight);
            self.remove_item(item_idx);

            if let Some(h) = higher_item {
                // Insert after higher item
                self.link_two_items(h, item_idx);
            } else {
                // No higher item found, insert at head (heaviest)
                self.insert_item(item_idx, InsertPoint::After, None);
            }
            max_weight
        } else {
            weight
        }
    }

    pub fn build_tree(&mut self, compression_type: u8) -> bool {
        let table_idx = (compression_type & 0x0F) as usize;
        if table_idx >= WEIGHT_TABLES.len() {
            return false;
        }
        let weight_table = WEIGHT_TABLES[table_idx];

        self.items_used = 0;
        self.first = None;
        self.last = None;
        self.items_by_byte = [None; 0x102];
        let mut max_weight = 0;

        for (i, weight) in weight_table.iter().enumerate().take(0x100) {
            if *weight != 0
                && let Some(idx) =
                    self.create_new_item(i as u32, *weight as u32, InsertPoint::After)
            {
                self.items_by_byte[i] = Some(idx);
                max_weight = self.fixup_item_pos_by_weight(idx, max_weight);
            }
        }

        if let Some(idx) = self.create_new_item(0x100, 1, InsertPoint::Before) {
            self.items_by_byte[0x100] = Some(idx);
        }
        if let Some(idx) = self.create_new_item(0x101, 1, InsertPoint::Before) {
            self.items_by_byte[0x101] = Some(idx);
        }

        let mut child_lo = self.last;
        while let Some(lo) = child_lo {
            if self.first == Some(lo) {
                break;
            }

            let child_hi = self.nodes[lo as usize].prev;
            if child_hi.is_none() {
                break;
            }
            let hi = child_hi.unwrap();

            let weight = self.nodes[lo as usize].weight + self.nodes[hi as usize].weight;
            if let Some(parent) = self.create_new_item(0, weight, InsertPoint::After) {
                self.nodes[lo as usize].parent = Some(parent);
                self.nodes[hi as usize].parent = Some(parent);
                self.nodes[parent as usize].child_lo = Some(lo);

                max_weight = self.fixup_item_pos_by_weight(parent, max_weight);

                child_lo = self.nodes[hi as usize].prev;
            } else {
                return false;
            }
        }

        self.min_valid_value = 1;
        true
    }

    pub fn inc_weights_and_rebalance(&mut self, item_idx: u16) {
        let mut current = Some(item_idx);

        while let Some(idx) = current {
            self.nodes[idx as usize].weight += 1;

            if self.nodes[idx as usize].parent.is_some() {
                // Find higher item
                let prev = self.nodes[idx as usize].prev;
                let higher_item =
                    self.find_higher_or_equal_item(prev, self.nodes[idx as usize].weight);

                // pChildHi = pHigherItem->pNext
                let child_hi = if let Some(h) = higher_item {
                    self.nodes[h as usize].next
                } else {
                    self.first
                };

                if child_hi != Some(idx) {
                    let child_hi_idx = child_hi.unwrap(); // Must be Some if != idx and idx is in list

                    // Move pChildHi to the RIGHT from pItem (idx)
                    // pChildHi->RemoveItem(); LinkTwoItems(pItem, pChildHi);
                    self.remove_item(child_hi_idx);
                    self.link_two_items(idx, child_hi_idx);

                    // Move pItem AFTER pHigherItem
                    // pItem->RemoveItem(); LinkTwoItems(pHigherItem, pItem);
                    self.remove_item(idx);
                    if let Some(h) = higher_item {
                        self.link_two_items(h, idx);
                    } else {
                        // Insert after LIST_HEAD -> Prepend
                        let old_first = self.first;
                        self.first = Some(idx);
                        self.nodes[idx as usize].next = old_first;
                        self.nodes[idx as usize].prev = None;
                        if let Some(of) = old_first {
                            self.nodes[of as usize].prev = Some(idx);
                        } else {
                            self.last = Some(idx);
                        }
                    }

                    // Rebalance tree structure
                    // pChildLo = pChildHi->pParent->pChildLo;
                    let child_hi_parent = self.nodes[child_hi_idx as usize].parent.unwrap();
                    let child_lo = self.nodes[child_hi_parent as usize].child_lo;

                    // pParent = pItem->pParent;
                    let parent = self.nodes[idx as usize].parent.unwrap();

                    // if(pParent->pChildLo == pItem) pParent->pChildLo = pChildHi;
                    if self.nodes[parent as usize].child_lo == Some(idx) {
                        self.nodes[parent as usize].child_lo = Some(child_hi_idx);
                    }

                    // if(pChildLo == pChildHi) pChildHi->pParent->pChildLo = pItem;
                    if child_lo == Some(child_hi_idx) {
                        self.nodes[child_hi_parent as usize].child_lo = Some(idx);
                    }

                    // pParent = pItem->pParent; (Already have it)
                    // pItem->pParent = pChildHi->pParent;
                    self.nodes[idx as usize].parent = Some(child_hi_parent);

                    // pChildHi->pParent = pParent;
                    self.nodes[child_hi_idx as usize].parent = Some(parent);
                }
            }

            // Increment the global valid value. This invalidates all quick-link items.
            // MinValidValue++; (Not implemented yet, but maybe needed?)

            current = self.nodes[idx as usize].parent;
        }
    }

    pub fn insert_new_branch_and_rebalance(&mut self, value1: u32, value2: u32) -> bool {
        let last_item = match self.last {
            Some(l) => l,
            None => return false,
        };

        let weight = self.nodes[last_item as usize].weight;

        if let Some(child_hi) = self.create_new_item(value1, weight, InsertPoint::Before) {
            self.nodes[child_hi as usize].parent = Some(last_item);
            self.items_by_byte[value1 as usize] = Some(child_hi);

            if let Some(child_lo) = self.create_new_item(value2, 0, InsertPoint::Before) {
                self.nodes[child_lo as usize].parent = Some(last_item);
                self.nodes[last_item as usize].child_lo = Some(child_lo);
                self.items_by_byte[value2 as usize] = Some(child_lo);

                self.inc_weights_and_rebalance(child_lo);
                return true;
            }
        }

        false
    }

    pub fn decode_one_byte(&mut self, stream: &mut BitStream) -> Option<u32> {
        let mut item_link_index = 0;
        let mut bit_count = 0;
        let has_item_link_index = stream
            .peek_7_bits()
            .inspect(|&v| {
                item_link_index = v;
            })
            .is_some();

        let mut current_item: Option<u16>;

        if has_item_link_index
            && self.quick_links[item_link_index as usize].valid_value > self.min_valid_value
        {
            let link = &self.quick_links[item_link_index as usize];
            if link.valid_bits <= 7 {
                stream.skip_bits(link.valid_bits);
                return Some(link.decompressed_value);
            }

            current_item = link.item;
            stream.skip_bits(7);
        } else {
            self.first?;
            current_item = self.first;
        }

        let mut item_link_ptr = None;

        // Step down until terminal
        while let Some(curr) = current_item {
            if self.nodes[curr as usize].child_lo.is_none() {
                break;
            }

            let bit = match stream.get_1_bit() {
                Some(b) => b,
                None => {
                    return None;
                }
            };

            let child_lo = self.nodes[curr as usize].child_lo.unwrap();

            if bit != 0 {
                // Higher weight child is prev of lower weight child
                current_item = self.nodes[child_lo as usize].prev;
            } else {
                current_item = Some(child_lo);
            }

            bit_count += 1;
            if bit_count == 7 {
                item_link_ptr = current_item;
            }
        }

        if let Some(curr) = current_item {
            let value = self.nodes[curr as usize].decompressed_value;

            // Update quick links
            if has_item_link_index
                && self.quick_links[item_link_index as usize].valid_value < self.min_valid_value
            {
                if bit_count > 7 {
                    self.quick_links[item_link_index as usize].valid_value = self.min_valid_value;
                    self.quick_links[item_link_index as usize].valid_bits = bit_count;
                    self.quick_links[item_link_index as usize].item = item_link_ptr;
                } else {
                    let mut idx = if bit_count != 0 {
                        item_link_index & (0xFFFFFFFF >> (32 - bit_count))
                    } else {
                        0
                    };
                    while idx < LINK_ITEM_COUNT as u32 {
                        self.quick_links[idx as usize].valid_value = self.min_valid_value;
                        self.quick_links[idx as usize].valid_bits = bit_count;
                        self.quick_links[idx as usize].decompressed_value = value;
                        idx += 1 << bit_count;
                    }
                }
            }

            Some(value)
        } else {
            None
        }
    }

    /// Get the Huffman code and length for a given item.
    /// Returns (code, length).
    pub fn get_code(&self, item_idx: u16) -> (u32, u32) {
        let mut code = 0;
        let mut length = 0;
        let mut current = item_idx;

        while let Some(parent_idx) = self.nodes[current as usize].parent {
            let bit = if self.nodes[parent_idx as usize].child_lo == Some(current) {
                0
            } else {
                1
            };
            
            // Match StormLib logic: build bits from leaf to root, shifting previous bits left.
            // This places the root-most bit at the LSB.
            // Since write_bits writes LSB first, this ensures the root bit is written first.
            code = (code << 1) | bit;
            length += 1;
            
            current = parent_idx;
        }

        (code, length)
    }
}
