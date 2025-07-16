// SPDX-License-Identifier: GPL-2.0
/*
 * ouiche_fs - Block sharing implementation for small files
 *
 * Copyright (C) 2018 Redha Gouicem <redha.gouicem@lip6.fr>
 */

#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>

#include "ouichefs.h"
#include "ouichefs_sliced.h"
#include "bitmap.h"

/**
 * Initialize a new sliced block
 * Sets up the metadata in the first slice and marks all data slices as free
 */
int ouichefs_init_sliced_block(struct super_block *sb, uint32_t block_num)
{
	struct buffer_head *bh;
	struct ouichefs_sliced_block_meta *meta;
	
	bh = sb_bread(sb, block_num);
	if (!bh) {
		pr_err("Failed to read block %u for sliced block initialization\n", block_num);
		return -EIO;
	}
	
	/* Clear the entire block */
	memset(bh->b_data, 0, OUICHEFS_BLOCK_SIZE);
	
	/* Set up metadata in first slice */
	meta = (struct ouichefs_sliced_block_meta *)bh->b_data;
	meta->magic = cpu_to_le32(OUICHEFS_SLICED_MAGIC);
	meta->next_block = cpu_to_le32(0);  /* No next block initially */
	
	/* Mark all data slices as free (bits 1-31 set to 1, bit 0 set to 0 for metadata) */
	meta->slice_bitmap = cpu_to_le32(0xFFFFFFFE);  /* 11111111111111111111111111111110 */
	
	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);
	
	pr_debug("Initialized sliced block %u\n", block_num);
	return 0;
}

/**
 * Allocate a slice from existing partially filled blocks or create a new one
 * Returns the block number, slice number is returned via slice_num parameter
 */
uint32_t ouichefs_alloc_slice(struct super_block *sb, uint32_t *slice_num)
{
	struct ouichefs_sb_info *sbi = OUICHEFS_SB(sb);
	struct buffer_head *bh;
	struct ouichefs_sliced_block_meta *meta;
	uint32_t block_num;
	uint32_t bitmap;
	int bit_pos;
	int ret;
	
	/* Check if we have any partially filled sliced blocks */
	if (sbi->s_free_sliced_blocks == 0) {
		/* No partially filled blocks, allocate a new one */
		block_num = get_free_block(sbi);
		if (!block_num) {
			pr_err("No free blocks available for sliced allocation\n");
			return 0;
		}
		
		/* Initialize the new sliced block */
		ret = ouichefs_init_sliced_block(sb, block_num);
		if (ret) {
			put_block(sbi, block_num);
			return 0;
		}
		
		/* Add this block to the partially filled list */
		sbi->s_free_sliced_blocks = block_num;
	} else {
		block_num = sbi->s_free_sliced_blocks;
	}
	
	/* Read the sliced block metadata */
	bh = sb_bread(sb, block_num);
	if (!bh) {
		pr_err("Failed to read sliced block %u\n", block_num);
		return 0;
	}
	
	meta = (struct ouichefs_sliced_block_meta *)bh->b_data;
	
	/* Verify this is actually a sliced block */
	if (le32_to_cpu(meta->magic) != OUICHEFS_SLICED_MAGIC) {
		pr_err("Block %u is not a valid sliced block (magic=%x)\n", 
		       block_num, le32_to_cpu(meta->magic));
		brelse(bh);
		return 0;
	}
	
	bitmap = le32_to_cpu(meta->slice_bitmap);
	
	/* Find the first free slice (bit set to 1) */
	bit_pos = find_first_bit((unsigned long *)&bitmap, OUICHEFS_SLICES_PER_BLOCK);
	if (bit_pos >= OUICHEFS_SLICES_PER_BLOCK) {
		pr_err("No free slices in block %u (bitmap=%x)\n", block_num, bitmap);
		brelse(bh);
		return 0;
	}
	
	/* Allocate the slice by clearing the bit */
	bitmap &= ~(1U << bit_pos);
	meta->slice_bitmap = cpu_to_le32(bitmap);
	
	/* If this block is now full, remove it from the partially filled list */
	if (bitmap == 0) {
		sbi->s_free_sliced_blocks = le32_to_cpu(meta->next_block);
		meta->next_block = cpu_to_le32(0);
	}
	
	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);
	
	*slice_num = bit_pos;
	
	pr_debug("Allocated slice %u in block %u\n", bit_pos, block_num);
	return block_num;
}

/**
 * Free a slice and potentially add the block back to the partially filled list
 */
void ouichefs_free_slice(struct super_block *sb, uint32_t block_num, uint32_t slice_num)
{
	struct ouichefs_sb_info *sbi = OUICHEFS_SB(sb);
	struct buffer_head *bh;
	struct ouichefs_sliced_block_meta *meta;
	uint32_t bitmap;
	bool was_full;
	
	if (slice_num == 0 || slice_num >= OUICHEFS_SLICES_PER_BLOCK) {
		pr_err("Invalid slice number %u\n", slice_num);
		return;
	}
	
	bh = sb_bread(sb, block_num);
	if (!bh) {
		pr_err("Failed to read sliced block %u for freeing\n", block_num);
		return;
	}
	
	meta = (struct ouichefs_sliced_block_meta *)bh->b_data;
	
	/* Verify this is a sliced block */
	if (le32_to_cpu(meta->magic) != OUICHEFS_SLICED_MAGIC) {
		pr_err("Block %u is not a valid sliced block\n", block_num);
		brelse(bh);
		return;
	}
	
	bitmap = le32_to_cpu(meta->slice_bitmap);
	was_full = (bitmap == 0);
	
	/* Free the slice by setting the bit */
	bitmap |= (1U << slice_num);
	meta->slice_bitmap = cpu_to_le32(bitmap);
	
	/* If block was full and now has free space, add it to partially filled list */
	if (was_full) {
		meta->next_block = cpu_to_le32(sbi->s_free_sliced_blocks);
		sbi->s_free_sliced_blocks = block_num;
	}
	
	/* If all data slices are now free (only metadata slice occupied), 
	   remove from partially filled list and return block to general pool */
	if (bitmap == 0xFFFFFFFE) {
		/* Remove from partially filled list */
		if (sbi->s_free_sliced_blocks == block_num) {
			sbi->s_free_sliced_blocks = le32_to_cpu(meta->next_block);
		} else {
			/* Need to find and update the previous block in the list */
			uint32_t prev_block = sbi->s_free_sliced_blocks;
			struct buffer_head *prev_bh;
			struct ouichefs_sliced_block_meta *prev_meta;
			
			while (prev_block != 0) {
				prev_bh = sb_bread(sb, prev_block);
				if (!prev_bh)
					break;
				
				prev_meta = (struct ouichefs_sliced_block_meta *)prev_bh->b_data;
				if (le32_to_cpu(prev_meta->next_block) == block_num) {
					prev_meta->next_block = meta->next_block;
					mark_buffer_dirty(prev_bh);
					sync_dirty_buffer(prev_bh);
					brelse(prev_bh);
					break;
				}
				
				prev_block = le32_to_cpu(prev_meta->next_block);
				brelse(prev_bh);
			}
		}
		
		/* Clear the block and return it to the general pool */
		memset(bh->b_data, 0, OUICHEFS_BLOCK_SIZE);
		mark_buffer_dirty(bh);
		sync_dirty_buffer(bh);
		brelse(bh);
		
		put_block(sbi, block_num);
		pr_debug("Returned empty sliced block %u to general pool\n", block_num);
		return;
	}
	
	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);
	
	pr_debug("Freed slice %u in block %u\n", slice_num, block_num);
}

/**
 * Read data from a specific slice
 */
int ouichefs_read_slice(struct super_block *sb, uint32_t block_num, uint32_t slice_num,
                       char *buffer, size_t size)
{
	struct buffer_head *bh;
	size_t slice_offset;
	size_t copy_size;
	
	if (slice_num == 0 || slice_num >= OUICHEFS_SLICES_PER_BLOCK) {
		pr_err("Invalid slice number %u\n", slice_num);
		return -EINVAL;
	}
	
	if (size > OUICHEFS_SLICE_SIZE) {
		pr_err("Read size %zu exceeds slice size %d\n", size, OUICHEFS_SLICE_SIZE);
		return -EINVAL;
	}
	
	bh = sb_bread(sb, block_num);
	if (!bh) {
		pr_err("Failed to read block %u\n", block_num);
		return -EIO;
	}
	
	slice_offset = slice_num * OUICHEFS_SLICE_SIZE;
	copy_size = min(size, (size_t)OUICHEFS_SLICE_SIZE);
	
	memcpy(buffer, bh->b_data + slice_offset, copy_size);
	
	brelse(bh);
	
	pr_debug("Read %zu bytes from slice %u in block %u\n", copy_size, slice_num, block_num);
	return copy_size;
}

/**
 * Write data to a specific slice
 */
int ouichefs_write_slice(struct super_block *sb, uint32_t block_num, uint32_t slice_num,
                        const char *buffer, size_t size)
{
	struct buffer_head *bh;
	size_t slice_offset;
	size_t copy_size;
	
	if (slice_num == 0 || slice_num >= OUICHEFS_SLICES_PER_BLOCK) {
		pr_err("Invalid slice number %u\n", slice_num);
		return -EINVAL;
	}
	
	if (size > OUICHEFS_SLICE_SIZE) {
		pr_err("Write size %zu exceeds slice size %d\n", size, OUICHEFS_SLICE_SIZE);
		return -EINVAL;
	}
	
	bh = sb_bread(sb, block_num);
	if (!bh) {
		pr_err("Failed to read block %u for writing\n", block_num);
		return -EIO;
	}
	
	slice_offset = slice_num * OUICHEFS_SLICE_SIZE;
	copy_size = min(size, (size_t)OUICHEFS_SLICE_SIZE);
	
	memcpy(bh->b_data + slice_offset, buffer, copy_size);
	
	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);
	
	pr_debug("Wrote %zu bytes to slice %u in block %u\n", copy_size, slice_num, block_num);
	return copy_size;
}