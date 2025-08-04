// SPDX-License-Identifier: GPL-2.0
/*
 * ouiche_fs - Enhanced Block sharing implementation for small files
 * Now supports files spanning multiple contiguous slices
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

/*
 * Helper function: Update the previous block's next pointer to skip the current block
 */
static void update_previous_block_link(struct super_block *sb,
				       uint32_t current_block,
				       __le32 next_block)
{
	struct ouichefs_sb_info *sbi = OUICHEFS_SB(sb);
	struct buffer_head *prev_bh;
	struct ouichefs_sliced_block_meta *prev_meta;
	uint32_t prev_block = sbi->s_free_sliced_blocks;

	/* Walk the list to find the previous block */
	while (prev_block != 0) {
		prev_bh = sb_bread(sb, prev_block);
		if (!prev_bh) {
			pr_err("Failed to read block %u while updating list\n",
			       prev_block);
			return;
		}

		prev_meta =
			(struct ouichefs_sliced_block_meta *)prev_bh->b_data;

		if (le32_to_cpu(prev_meta->next_block) == current_block) {
			/* Found the previous block, update its next pointer */
			prev_meta->next_block = next_block;
			mark_buffer_dirty(prev_bh);
			sync_dirty_buffer(prev_bh);
			brelse(prev_bh);
			return;
		}

		prev_block = le32_to_cpu(prev_meta->next_block);
		brelse(prev_bh);
	}

	pr_warn("Could not find previous block for %u in list\n",
		current_block);
}

/*
 * Helper function: Remove a full block from the partially filled list
 */
static void handle_full_block_removal(struct super_block *sb,
				      uint32_t current_block,
				      struct ouichefs_sliced_block_meta *meta)
{
	struct ouichefs_sb_info *sbi = OUICHEFS_SB(sb);

	if (current_block == sbi->s_free_sliced_blocks) {
		/* Block is head of the list */
		sbi->s_free_sliced_blocks = le32_to_cpu(meta->next_block);
	} else {
		/* Find and update the previous block in the list */
		update_previous_block_link(sb, current_block, meta->next_block);
	}
	meta->next_block = cpu_to_le32(0);
}

/*
 * Helper function: Try to allocate contiguous slices in a specific block
 * Returns the starting slice number on success, 0 on failure
 */
static uint32_t try_allocate_in_block(struct super_block *sb,
				      uint32_t block_num, uint32_t count,
				      uint32_t upper_bound)
{
	struct buffer_head *bh;
	struct ouichefs_sliced_block_meta *meta;
	uint32_t bitmap, start_slice;

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

	/* Find contiguous free slices */
	for (start_slice = 1; start_slice <= upper_bound; start_slice++) {
		if (!ouichefs_has_contiguous_slices(bitmap, start_slice, count))
			continue;

		/* Found contiguous slices! Allocate them */
		for (uint32_t i = 0; i < count; i++)
			bitmap &= ~(1U << (start_slice + i));

		meta->slice_bitmap = cpu_to_le32(bitmap);

		/* Handle block removal from partially filled list if now full */
		if (bitmap == 0)
			handle_full_block_removal(sb, block_num, meta);

		mark_buffer_dirty(bh);
		sync_dirty_buffer(bh);
		brelse(bh);

		pr_debug(
			"Allocated %u slices starting at slice %u in block %u\n",
			count, start_slice, block_num);
		return start_slice;
	}

	brelse(bh);
	return 0; /* No contiguous space found */
}

/*
 * Helper function: Get the next block in the partially filled list
 */
static uint32_t get_next_block_in_list(struct super_block *sb,
				       uint32_t current_block)
{
	struct buffer_head *bh;
	struct ouichefs_sliced_block_meta *meta;
	uint32_t next_block;

	bh = sb_bread(sb, current_block);
	if (!bh) {
		pr_err("Failed to read block %u for list traversal\n",
		       current_block);
		return 0;
	}

	meta = (struct ouichefs_sliced_block_meta *)bh->b_data;
	next_block = le32_to_cpu(meta->next_block);
	brelse(bh);

	return next_block;
}

/*
 * Initialize a new sliced block
 * Sets up the metadata in the first slice and marks all data slices as free
 */
int ouichefs_init_sliced_block(struct super_block *sb, uint32_t block_num)
{
	struct buffer_head *bh;
	struct ouichefs_sliced_block_meta *meta;

	bh = sb_bread(sb, block_num);
	if (!bh) {
		pr_err("Failed to read block %u for sliced block initialization\n",
		       block_num);
		return -EIO;
	}

	/* Clear the entire block */
	memset(bh->b_data, 0, OUICHEFS_BLOCK_SIZE);

	/* Set up metadata in first slice */
	meta = (struct ouichefs_sliced_block_meta *)bh->b_data;
	meta->magic = cpu_to_le32(OUICHEFS_SLICED_MAGIC);
	meta->next_block = cpu_to_le32(0); /* No next block initially */

	/* Mark all data slices as free (bits 1-31 set to 1, bit 0 set to 0 for metadata) */
	meta->slice_bitmap =
		cpu_to_le32(0xFFFFFFFE); /* 11111111111111111111111111111110 */

	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);

	pr_debug("Initialized sliced block %u\n", block_num);
	return 0;
}

/*
 * Allocate contiguous slices from existing partially filled blocks or create a new one
 * Returns the block number, slice number is returned via slice_num parameter
 */
uint32_t ouichefs_alloc_slices(struct super_block *sb, uint32_t *slice_num,
			       uint32_t count)
{
	struct ouichefs_sb_info *sbi = OUICHEFS_SB(sb);
	struct buffer_head *bh;
	struct ouichefs_sliced_block_meta *meta;
	uint32_t block_num;
	uint32_t bitmap;
	int ret;

	if (count == 0 || count > OUICHEFS_DATA_SLICES) {
		pr_err("Invalid slice count %u (max: %d)\n", count,
		       OUICHEFS_DATA_SLICES);
		return 0;
	}

	pr_debug("Allocating %u contiguous slices\n", count);

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

	/* Search for contiguous slices in existing blocks */
	uint32_t current_block = block_num;
	uint32_t upper_bound = OUICHEFS_SLICES_PER_BLOCK - count;
	uint32_t allocated_slice;

	while (current_block != 0) {
		allocated_slice = try_allocate_in_block(sb, current_block,
							count, upper_bound);
		if (allocated_slice != 0) {
			*slice_num = allocated_slice;
			return current_block;
		}

		/* Move to next block */
		current_block = get_next_block_in_list(sb, current_block);
	}

	/* No existing block had enough contiguous space, allocate a new block */
	block_num = get_free_block(sbi);
	if (!block_num) {
		pr_err("No free blocks available for new sliced block\n");
		return 0;
	}

	ret = ouichefs_init_sliced_block(sb, block_num);
	if (ret) {
		put_block(sbi, block_num);
		return 0;
	}

	/* Allocate slices in the new block */
	bh = sb_bread(sb, block_num);
	if (!bh) {
		put_block(sbi, block_num);
		return 0;
	}

	meta = (struct ouichefs_sliced_block_meta *)bh->b_data;
	bitmap = le32_to_cpu(meta->slice_bitmap);

	/* Allocate first 'count' slices */
	for (uint32_t i = 0; i < count; i++)
		bitmap &= ~(1U << (1 + i));

	meta->slice_bitmap = cpu_to_le32(bitmap);

	/* Add to partially filled list if not full */
	if (bitmap != 0) {
		meta->next_block = cpu_to_le32(sbi->s_free_sliced_blocks);
		sbi->s_free_sliced_blocks = block_num;
	}

	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);

	*slice_num = 1;
	pr_debug("Allocated %u slices starting at slice 1 in new block %u\n",
		 count, block_num);
	return block_num;
}

/*
 * Free multiple contiguous slices starting from slice_num
 */
void ouichefs_free_slices(struct super_block *sb, uint32_t block_num,
			  uint32_t slice_num, uint32_t count)
{
	struct ouichefs_sb_info *sbi = OUICHEFS_SB(sb);
	struct buffer_head *bh;
	struct ouichefs_sliced_block_meta *meta;
	uint32_t bitmap;
	bool was_full;
	int free_data_slices;

	if (slice_num == 0 || slice_num + count > OUICHEFS_SLICES_PER_BLOCK ||
	    count == 0) {
		pr_err("Invalid slice range: start=%u, count=%u (valid range: 1-%d)\n",
		       slice_num, count, OUICHEFS_SLICES_PER_BLOCK - 1);
		return;
	}

	pr_debug("Freeing %u slices starting at slice %u in block %u\n", count,
		 slice_num, block_num);

	bh = sb_bread(sb, block_num);
	if (!bh) {
		pr_err("Failed to read sliced block %u for freeing\n",
		       block_num);
		return;
	}

	meta = (struct ouichefs_sliced_block_meta *)bh->b_data;

	/* Verify this is a sliced block */
	if (le32_to_cpu(meta->magic) != OUICHEFS_SLICED_MAGIC) {
		pr_err("Block %u is not a valid sliced block (magic=0x%x, expected=0x%x)\n",
		       block_num, le32_to_cpu(meta->magic),
		       OUICHEFS_SLICED_MAGIC);
		brelse(bh);
		return;
	}

	bitmap = le32_to_cpu(meta->slice_bitmap);
	was_full = (bitmap == 0); /* All data slices were occupied */

	/* Check if slices are already free */
	for (uint32_t i = 0; i < count; i++) {
		if (bitmap & (1U << (slice_num + i))) {
			pr_warn("Slice %u in block %u is already free\n",
				slice_num + i, block_num);
		}
	}

	/* Free the slices by setting the bits */
	for (uint32_t i = 0; i < count; i++)
		bitmap |= (1U << (slice_num + i));

	meta->slice_bitmap = cpu_to_le32(bitmap);

	/* Count free data slices (excluding metadata slice 0) */
	free_data_slices = 0;
	for (int i = 1; i < OUICHEFS_SLICES_PER_BLOCK; i++) {
		if (bitmap & (1U << i))
			free_data_slices++;
	}

	pr_debug("Block %u now has %d free data slices (bitmap=0x%08x)\n",
		 block_num, free_data_slices, bitmap);

	/* If block was full and now has free space, add it to partially filled list */
	if (was_full && free_data_slices > 0 &&
	    free_data_slices < (OUICHEFS_SLICES_PER_BLOCK - 1)) {
		pr_debug("Block %u was full, adding to partially filled list\n",
			 block_num);
		meta->next_block = cpu_to_le32(sbi->s_free_sliced_blocks);
		sbi->s_free_sliced_blocks = block_num;
	}

	/* If all data slices are now free, */
	/* remove from partially filled list and return to general pool */
	if (!was_full && free_data_slices == (OUICHEFS_SLICES_PER_BLOCK - 1)) {
		pr_debug(
			"All data slices free, returning block %u to general pool\n",
			block_num);

		/* Remove from partially filled list */
		if (sbi->s_free_sliced_blocks == block_num) {
			/* Block is head of the list */
			sbi->s_free_sliced_blocks =
				le32_to_cpu(meta->next_block);
			pr_debug(
				"Removed block %u from head of partially filled list\n",
				block_num);
		} else {
			/* Find and update the previous block in the list */
			uint32_t prev_block = sbi->s_free_sliced_blocks;
			struct buffer_head *prev_bh;
			struct ouichefs_sliced_block_meta *prev_meta;
			bool found = false;

			while (prev_block != 0) {
				prev_bh = sb_bread(sb, prev_block);
				if (!prev_bh) {
					pr_err("Failed to read block %u while searching partially filled list\n",
					       prev_block);
					break;
				}

				prev_meta =
					(struct ouichefs_sliced_block_meta *)
						prev_bh->b_data;
				if (le32_to_cpu(prev_meta->next_block) ==
				    block_num) {
					prev_meta->next_block =
						meta->next_block;
					mark_buffer_dirty(prev_bh);
					sync_dirty_buffer(prev_bh);
					brelse(prev_bh);
					found = true;
					pr_debug(
						"Updated previous block %u to skip block %u\n",
						prev_block, block_num);
					break;
				}

				prev_block = le32_to_cpu(prev_meta->next_block);
				brelse(prev_bh);
			}

			if (!found) {
				pr_warn("Block %u not found in partially filled list during removal\n",
					block_num);
			}
		}

		/* Clear the block and return it to the general pool */
		memset(bh->b_data, 0, OUICHEFS_BLOCK_SIZE);
		mark_buffer_dirty(bh);
		sync_dirty_buffer(bh);
		brelse(bh);

		put_block(sbi, block_num);
		pr_info("Returned empty sliced block %u to general pool\n",
			block_num);
		return;
	}

	/* Save the updated metadata */
	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);

	pr_debug(
		"Freed %u slices starting at slice %u in block %u (now %d/%d data slices free)\n",
		count, slice_num, block_num, free_data_slices,
		OUICHEFS_SLICES_PER_BLOCK - 1);
}

/*
 * Read data from multiple contiguous slices
 */
int ouichefs_read_slices(struct super_block *sb, uint32_t block_num,
			 uint32_t slice_start, uint32_t slice_count,
			 char *buffer, size_t size)
{
	struct buffer_head *bh;
	size_t slice_offset;
	size_t copy_size;
	size_t total_copied = 0;

	if (slice_start == 0 ||
	    slice_start + slice_count > OUICHEFS_SLICES_PER_BLOCK) {
		pr_err("Invalid slice range: start=%u, count=%u\n", slice_start,
		       slice_count);
		return -EINVAL;
	}

	if (size > slice_count * OUICHEFS_SLICE_SIZE) {
		pr_err("Read size %zu exceeds slice range capacity %u\n", size,
		       slice_count * OUICHEFS_SLICE_SIZE);
		return -EINVAL;
	}

	bh = sb_bread(sb, block_num);
	if (!bh) {
		pr_err("Failed to read block %u\n", block_num);
		return -EIO;
	}

	slice_offset = slice_start * OUICHEFS_SLICE_SIZE;
	copy_size = min(size, (size_t)(slice_count * OUICHEFS_SLICE_SIZE));

	memcpy(buffer, bh->b_data + slice_offset, copy_size);
	total_copied = copy_size;

	brelse(bh);

	pr_debug(
		"Read %zu bytes from %u slices starting at slice %u in block %u\n",
		total_copied, slice_count, slice_start, block_num);
	return total_copied;
}

/*
 * Write data to multiple contiguous slices
 */
int ouichefs_write_slices(struct super_block *sb, uint32_t block_num,
			  uint32_t slice_start, uint32_t slice_count,
			  const char *buffer, size_t size)
{
	struct buffer_head *bh;
	size_t slice_offset;
	size_t copy_size;

	if (slice_start == 0 ||
	    slice_start + slice_count > OUICHEFS_SLICES_PER_BLOCK) {
		pr_err("Invalid slice range: start=%u, count=%u\n", slice_start,
		       slice_count);
		return -EINVAL;
	}

	if (size > slice_count * OUICHEFS_SLICE_SIZE) {
		pr_err("Write size %zu exceeds slice range capacity %u\n", size,
		       slice_count * OUICHEFS_SLICE_SIZE);
		return -EINVAL;
	}

	bh = sb_bread(sb, block_num);
	if (!bh) {
		pr_err("Failed to read block %u for writing\n", block_num);
		return -EIO;
	}

	slice_offset = slice_start * OUICHEFS_SLICE_SIZE;
	copy_size = min(size, (size_t)(slice_count * OUICHEFS_SLICE_SIZE));

	/* Clear the slice range first, then write new data */
	memset(bh->b_data + slice_offset, 0, slice_count * OUICHEFS_SLICE_SIZE);
	memcpy(bh->b_data + slice_offset, buffer, copy_size);

	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);

	pr_debug(
		"Wrote %zu bytes to %u slices starting at slice %u in block %u\n",
		copy_size, slice_count, slice_start, block_num);
	return copy_size;
}

/*
 * Calculate how many slices are needed for a given file size
 */
uint32_t ouichefs_slices_needed(size_t file_size)
{
	if (file_size == 0)
		return 0;
	return (file_size + OUICHEFS_SLICE_SIZE - 1) / OUICHEFS_SLICE_SIZE;
}

/*
 * Check if bitmap has 'count' contiguous free slices starting from 'start_slice'
 */
bool ouichefs_has_contiguous_slices(uint32_t bitmap, uint32_t start_slice,
				    uint32_t count)
{
	if (start_slice == 0 ||
	    start_slice + count > OUICHEFS_SLICES_PER_BLOCK) {
		return false;
	}

	/* Check if we have count contiguous free slices with the bitmap */
	for (uint32_t i = 0; i < count; i++) {
		if (!(bitmap & (1U << (start_slice + i))))
			return false; /* Slice is occupied */
	}

	return true;
}

/*
 * Try to relocate existing file data to make room for expansion
 * This function attempts to find a better location with more contiguous space
 */
uint32_t ouichefs_try_relocate_slices(struct super_block *sb,
				      uint32_t old_block, uint32_t old_slice,
				      uint32_t old_count, uint32_t new_count,
				      uint32_t *new_slice)
{
	struct buffer_head *old_bh = NULL, *new_bh = NULL;
	uint32_t new_block;
	char *temp_buffer = NULL;

	/* Don't relocate if the new count is smaller */
	if (new_count <= old_count)
		return 0;

	pr_debug(
		"Attempting to relocate %u slices from block %u slice %u to accommodate %u slices\n",
		old_count, old_block, old_slice, new_count);

	/* Allocate temporary buffer to hold existing data */
	temp_buffer = kmalloc(old_count * OUICHEFS_SLICE_SIZE, GFP_KERNEL);
	if (!temp_buffer)
		return 0;

	/* Read existing data */
	old_bh = sb_bread(sb, old_block);
	if (!old_bh) {
		pr_err("Failed to read old block %u for relocation\n",
		       old_block);
		kfree(temp_buffer);
		return 0;
	}

	memcpy(temp_buffer, old_bh->b_data + (old_slice * OUICHEFS_SLICE_SIZE),
	       old_count * OUICHEFS_SLICE_SIZE);
	brelse(old_bh);

	/* Try to allocate new contiguous slices */
	new_block = ouichefs_alloc_slices(sb, new_slice, new_count);
	if (!new_block) {
		pr_debug("Failed to find contiguous space for %u slices\n",
			 new_count);
		kfree(temp_buffer);
		return 0;
	}

	/* Write data to new location */
	new_bh = sb_bread(sb, new_block);
	if (!new_bh) {
		pr_err("Failed to read new block %u for relocation\n",
		       new_block);
		ouichefs_free_slices(sb, new_block, *new_slice, new_count);
		kfree(temp_buffer);
		return 0;
	}

	/* Clear the new slice range and copy data */
	memset(new_bh->b_data + (*new_slice * OUICHEFS_SLICE_SIZE), 0,
	       new_count * OUICHEFS_SLICE_SIZE);
	memcpy(new_bh->b_data + (*new_slice * OUICHEFS_SLICE_SIZE), temp_buffer,
	       old_count * OUICHEFS_SLICE_SIZE);

	mark_buffer_dirty(new_bh);
	sync_dirty_buffer(new_bh);
	brelse(new_bh);

	/* Free old slices */
	ouichefs_free_slices(sb, old_block, old_slice, old_count);

	kfree(temp_buffer);

	pr_info("Successfully relocated %u slices to block %u slice %u (capacity for %u slices)\n",
		old_count, new_block, *new_slice, new_count);

	return new_block;
}
