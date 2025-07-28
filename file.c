// Enhanced file.c with multi-slice support
// SPDX-License-Identifier: GPL-2.0
/*
 * ouiche_fs - Enhanced file operations with multi-slice support
 *
 * Copyright (C) 2018 Redha Gouicem <redha.gouicem@lip6.fr>
 */

#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/mpage.h>

#include "ouichefs.h"
#include "bitmap.h"
#include "ouichefs_sliced.h"
#include <linux/uio.h>

MODULE_LICENSE("GPL");

/* Forward declarations */
static ssize_t ouichefs_convert_to_traditional(struct inode *inode,
					       const char *new_data,
					       size_t new_data_len,
					       loff_t *pos);
static ssize_t ouichefs_write_small_file(struct inode *inode, const char *kbuf,
					 size_t bytes_to_write, loff_t *pos);
static ssize_t ouichefs_write_large_file(struct inode *inode, const char *kbuf,
					 size_t bytes_to_write, loff_t *pos);
static ssize_t ouichefs_read_traditional_file(struct inode *inode, char *buffer,
					      size_t size);
static void ouichefs_free_traditional_blocks(struct inode *inode);

/* Slice relocation function from sliced.c */
extern uint32_t
ouichefs_try_relocate_slices(struct super_block *sb, uint32_t old_block,
			     uint32_t old_slice, uint32_t old_count,
			     uint32_t new_count, uint32_t *new_slice);

/*
 * Map the buffer_head passed in argument with the iblock-th block of the file
 * represented by inode. If the requested block is not allocated and create is
 * true, allocate a new block on disk and map it.
 */
static int ouichefs_file_get_block(struct inode *inode, sector_t iblock,
				   struct buffer_head *bh_result, int create)
{
	struct super_block *sb = inode->i_sb;
	struct ouichefs_sb_info *sbi = OUICHEFS_SB(sb);
	struct ouichefs_inode_info *ci = OUICHEFS_INODE(inode);
	struct ouichefs_file_index_block *index;
	struct buffer_head *bh_index;
	int ret = 0, bno;

	/* For small files, we don't use this function - they use sliced blocks */
	if (ouichefs_is_small_file(inode->i_size)) {
		pr_err("get_block called for small file - this should not happen\n");
		return -EINVAL;
	}

	if (iblock >= OUICHEFS_BLOCK_SIZE >> 2)
		return -EFBIG;

	bh_index = sb_bread(sb, ci->index_block);
	if (!bh_index)
		return -EIO;
	index = (struct ouichefs_file_index_block *)bh_index->b_data;

	if (index->blocks[iblock] == 0) {
		if (!create) {
			ret = 0;
			goto brelse_index;
		}
		bno = get_free_block(sbi);
		if (!bno) {
			ret = -ENOSPC;
			goto brelse_index;
		}
		index->blocks[iblock] = cpu_to_le32(bno);
		mark_buffer_dirty(bh_index);
	} else {
		bno = le32_to_cpu(index->blocks[iblock]);
	}

	map_bh(bh_result, sb, bno);

brelse_index:
	brelse(bh_index);
	return ret;
}

static void ouichefs_readahead(struct readahead_control *rac)
{
	mpage_readahead(rac, ouichefs_file_get_block);
}

static int ouichefs_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, ouichefs_file_get_block, wbc);
}

static int ouichefs_write_begin(struct file *file,
				struct address_space *mapping, loff_t pos,
				unsigned int len, struct page **pagep,
				void **fsdata)
{
	struct ouichefs_sb_info *sbi = OUICHEFS_SB(file->f_inode->i_sb);
	int err;
	uint32_t nr_allocs = 0;

	/* Small files use sliced blocks, handled separately */
	if (ouichefs_is_small_file(file->f_inode->i_size) ||
	    ouichefs_is_small_file(pos + len)) {
		return -EINVAL;
	}

	if (pos + len > OUICHEFS_MAX_FILESIZE)
		return -ENOSPC;
	nr_allocs = max(pos + len, file->f_inode->i_size) / OUICHEFS_BLOCK_SIZE;
	if (nr_allocs > file->f_inode->i_blocks - 1)
		nr_allocs -= file->f_inode->i_blocks - 1;
	else
		nr_allocs = 0;
	if (nr_allocs > sbi->nr_free_blocks)
		return -ENOSPC;

	err = block_write_begin(mapping, pos, len, pagep,
				ouichefs_file_get_block);
	if (err < 0) {
		pr_err("%s:%d: newly allocated blocks reclaim not implemented yet\n",
		       __func__, __LINE__);
	}
	return err;
}

static int ouichefs_write_end(struct file *file, struct address_space *mapping,
			      loff_t pos, unsigned int len, unsigned int copied,
			      struct page *page, void *fsdata)
{
	int ret;
	struct inode *inode = file->f_inode;
	struct ouichefs_inode_info *ci = OUICHEFS_INODE(inode);
	struct super_block *sb = inode->i_sb;

	/* Small files should not use this function */
	if (ouichefs_is_small_file(inode->i_size)) {
		return -EINVAL;
	}

	ret = generic_write_end(file, mapping, pos, len, copied, page, fsdata);
	if (ret < len) {
		pr_err("%s:%d: wrote less than asked... what do I do? nothing for now...\n",
		       __func__, __LINE__);
	} else {
		uint32_t nr_blocks_old = inode->i_blocks;

		inode->i_blocks = (roundup(inode->i_size, OUICHEFS_BLOCK_SIZE) /
				   OUICHEFS_BLOCK_SIZE) +
				  1;
		inode->i_mtime = inode->i_ctime = current_time(inode);
		mark_inode_dirty(inode);

		if (nr_blocks_old > inode->i_blocks) {
			int i;
			struct buffer_head *bh_index;
			struct ouichefs_file_index_block *index;

			truncate_pagecache(inode, inode->i_size);

			bh_index = sb_bread(sb, ci->index_block);
			if (!bh_index) {
				pr_err("failed truncating '%s'. we just lost %llu blocks\n",
				       file->f_path.dentry->d_name.name,
				       nr_blocks_old - inode->i_blocks);
				goto end;
			}
			index = (struct ouichefs_file_index_block *)
					bh_index->b_data;

			for (i = inode->i_blocks - 1; i < nr_blocks_old - 1;
			     i++) {
				put_block(OUICHEFS_SB(sb),
					  le32_to_cpu(index->blocks[i]));
				index->blocks[i] = 0;
			}
			mark_buffer_dirty(bh_index);
			brelse(bh_index);
		}
	}
end:
	return ret;
}

const struct address_space_operations ouichefs_aops = {
	.readahead = ouichefs_readahead,
	.writepage = ouichefs_writepage,
	.write_begin = ouichefs_write_begin,
	.write_end = ouichefs_write_end
};

/*
 * Helper function to determine if a file currently uses slice storage
 */
static bool ouichefs_uses_slice_storage(struct inode *inode)
{
	struct ouichefs_inode_info *ci = OUICHEFS_INODE(inode);

	if (inode->i_size == 0 || ci->index_block == 0) {
		return false;
	}

	if (inode->i_size > OUICHEFS_SMALL_FILE_THRESHOLD) {
		return false;
	}

	uint32_t block_num = ouichefs_get_slice_block(ci->index_block);
	uint32_t slice_num = ouichefs_get_slice_number(ci->index_block);

	return (block_num != 0 && slice_num != 0 &&
		slice_num < OUICHEFS_SLICES_PER_BLOCK);
}

static int ouichefs_open(struct inode *inode, struct file *file)
{
	bool wronly = (file->f_flags & O_WRONLY) != 0;
	bool rdwr = (file->f_flags & O_RDWR) != 0;
	bool trunc = (file->f_flags & O_TRUNC) != 0;
	bool append = (file->f_flags & O_APPEND) != 0;

	pr_debug("File open: size=%lld, trunc=%d, append=%d\n", inode->i_size,
		 trunc, append);

	/* Handle truncation */
	if ((wronly || rdwr) && trunc && (inode->i_size != 0)) {
		struct super_block *sb = inode->i_sb;
		struct ouichefs_sb_info *sbi = OUICHEFS_SB(sb);
		struct ouichefs_inode_info *ci = OUICHEFS_INODE(inode);

		pr_debug("Truncating file: current_size=%lld, uses_slices=%d\n",
			 inode->i_size, ouichefs_uses_slice_storage(inode));

		if (ouichefs_uses_slice_storage(inode)) {
			/* File uses slice storage - free the slices */
			uint32_t block_num =
				ouichefs_get_slice_block(ci->index_block);
			uint32_t slice_num =
				ouichefs_get_slice_number(ci->index_block);
			uint32_t slices_used =
				ouichefs_slices_needed(inode->i_size);

			pr_debug(
				"Freeing %u slices starting at slice %u in block %u\n",
				slices_used, slice_num, block_num);
			ouichefs_free_slices(sb, block_num, slice_num,
					     slices_used);

			/* Reset inode */
			inode->i_size = 0;
			inode->i_blocks = 0;
			ci->index_block = 0;
		} else if (ci->index_block != 0) {
			/* File uses traditional storage - free all blocks */
			struct ouichefs_file_index_block *index;
			struct buffer_head *bh_index;
			uint32_t blocks_to_free = inode->i_blocks - 1;

			pr_debug(
				"Freeing traditional storage: index_block=%u, data_blocks=%u\n",
				ci->index_block, blocks_to_free);

			bh_index = sb_bread(sb, ci->index_block);
			if (!bh_index) {
				pr_err("Failed to read index block %u for truncation\n",
				       ci->index_block);
				return -EIO;
			}

			index = (struct ouichefs_file_index_block *)
					bh_index->b_data;

			for (uint32_t i = 0; i < blocks_to_free; i++) {
				uint32_t data_block =
					le32_to_cpu(index->blocks[i]);
				if (data_block != 0) {
					put_block(sbi, data_block);
					index->blocks[i] = 0;
					pr_debug("Freed data block %u\n",
						 data_block);
				}
			}

			memset(index, 0, OUICHEFS_BLOCK_SIZE);
			mark_buffer_dirty(bh_index);
			sync_dirty_buffer(bh_index);
			brelse(bh_index);

			inode->i_size = 0;
			inode->i_blocks = 1;
		} else {
			inode->i_size = 0;
			inode->i_blocks = 0;
			ci->index_block = 0;
		}

		mark_inode_dirty(inode);
		pr_debug("Truncation completed: new_size=%lld, blocks=%llu\n",
			 inode->i_size, inode->i_blocks);
	}

	if ((wronly || rdwr) && append && (inode->i_size != 0)) {
		file->f_pos = inode->i_size;
		pr_debug("Append mode: set position to %lld\n", file->f_pos);
	}

	return 0;
}

/*
 * Enhanced read function supporting multi-slice files
 */
static ssize_t ouichefs_read(struct file *file, char __user *buf, size_t len,
			     loff_t *pos)
{
	struct inode *inode = file->f_inode;
	struct super_block *sb = inode->i_sb;
	struct ouichefs_inode_info *ci = OUICHEFS_INODE(inode);

	if (*pos >= inode->i_size)
		return 0; // EOF

	/* Check if this is a small file using slice storage */
	if (ouichefs_uses_slice_storage(inode)) {
		uint32_t block_num = ouichefs_get_slice_block(ci->index_block);
		uint32_t slice_start =
			ouichefs_get_slice_number(ci->index_block);
		uint32_t slices_used = ouichefs_slices_needed(inode->i_size);

		char *kbuf = kmalloc(len, GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;

		size_t bytes_to_read = min(len, (size_t)(inode->i_size - *pos));
		ssize_t ret = ouichefs_read_slices(sb, block_num, slice_start,
						   slices_used, kbuf,
						   bytes_to_read);

		if (ret > 0) {
			if (copy_to_user(buf, kbuf + *pos, ret)) {
				kfree(kbuf);
				return -EFAULT;
			}
			*pos += ret;
		}

		kfree(kbuf);
		pr_debug("Read %zd bytes from multi-slice file at pos %lld\n",
			 ret, *pos - ret);
		return ret;
	}

	/* Traditional file handling (existing code for large files) */
	struct buffer_head *bh, *bh_index;
	struct ouichefs_file_index_block *index;
	unsigned long block_num;
	unsigned long block_offset;
	unsigned long bytes_in_block;
	unsigned long bytes_left;
	unsigned long bytes_avail;
	unsigned long to_copy;
	size_t total_copied = 0;

	char *kbuf = kmalloc(len, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	bh_index = sb_bread(sb, ci->index_block);
	if (!bh_index) {
		kfree(kbuf);
		return -EIO;
	}
	index = (struct ouichefs_file_index_block *)bh_index->b_data;

	while (total_copied < len) {
		block_num = *pos / OUICHEFS_BLOCK_SIZE;
		block_offset = *pos % OUICHEFS_BLOCK_SIZE;

		if (block_num >= OUICHEFS_MAX_SUBFILES) {
			break;
		}

		uint32_t bno = le32_to_cpu(index->blocks[block_num]);
		if (bno == 0) {
			break;
		}

		bh = sb_bread(sb, bno);
		if (!bh) {
			brelse(bh_index);
			kfree(kbuf);
			return -EIO;
		}

		bytes_in_block = OUICHEFS_BLOCK_SIZE - block_offset;
		bytes_left = len - total_copied;
		bytes_avail = inode->i_size - *pos;

		to_copy = min3(bytes_in_block, bytes_left, bytes_avail);

		memcpy(kbuf + total_copied, bh->b_data + block_offset, to_copy);

		brelse(bh);

		*pos += to_copy;
		total_copied += to_copy;

		if (*pos >= inode->i_size)
			break;
	}

	if (copy_to_user(buf, kbuf, total_copied)) {
		kfree(kbuf);
		brelse(bh_index);
		return -EFAULT;
	}

	kfree(kbuf);
	brelse(bh_index);
	return total_copied;
}

/*
 * Enhanced write function supporting multi-slice files
 */
static ssize_t ouichefs_write(struct file *file, const char __user *buf,
			      size_t len, loff_t *pos)
{
	struct inode *inode = file->f_inode;
	struct ouichefs_inode_info *ci = OUICHEFS_INODE(inode);
	char *kbuf = NULL;
	size_t bytes_to_write;
	ssize_t ret;
	bool will_exceed_threshold =
		(*pos + len > OUICHEFS_SMALL_FILE_THRESHOLD);
	bool is_currently_small = ouichefs_is_small_file(inode->i_size);
	bool is_currently_large = !is_currently_small && inode->i_size > 0;
	bool uses_slices = false;

	if (*pos >= OUICHEFS_MAX_FILESIZE)
		return -ENOSPC;

	bytes_to_write = min(len, (size_t)(OUICHEFS_MAX_FILESIZE - *pos));

	if (bytes_to_write == 0)
		return 0;

	/* Determine if file currently uses slice storage */
	if (is_currently_small && ci->index_block != 0) {
		uint32_t block_num = ouichefs_get_slice_block(ci->index_block);
		uint32_t slice_num = ouichefs_get_slice_number(ci->index_block);
		uses_slices = (block_num != 0 && slice_num != 0 &&
			       slice_num < OUICHEFS_SLICES_PER_BLOCK);
	}

	/* Copy data from user space */
	kbuf = kmalloc(bytes_to_write, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	if (copy_from_user(kbuf, buf, bytes_to_write)) {
		ret = -EFAULT;
		goto cleanup;
	}

	pr_debug(
		"WRITE: len=%zu, pos=%lld, will_exceed_threshold=%d, current_size=%lld, uses_slices=%d\n",
		bytes_to_write, *pos, will_exceed_threshold, inode->i_size,
		uses_slices);

	/* Decision logic for write handling */
	if (is_currently_large) {
		/* File is already large - use traditional storage operations */
		pr_debug("Writing to existing large file\n");
		ret = ouichefs_write_large_file(inode, kbuf, bytes_to_write,
						pos);
	} else if (will_exceed_threshold && uses_slices) {
		/* Small file with slices needs conversion to traditional storage */
		pr_info("Converting slice-based file to traditional storage\n");
		ret = ouichefs_convert_to_traditional(inode, kbuf,
						      bytes_to_write, pos);
	} else if (will_exceed_threshold && !uses_slices &&
		   ci->index_block == 0) {
		/* Empty file that will be large - allocate traditional storage directly */
		pr_info("Creating new large file with traditional storage\n");
		ret = ouichefs_convert_to_traditional(inode, kbuf,
						      bytes_to_write, pos);
	} else if (will_exceed_threshold && !uses_slices &&
		   ci->index_block != 0) {
		/* File already uses traditional storage - just expand it */
		pr_debug("Expanding existing traditional storage file\n");
		ret = ouichefs_write_large_file(inode, kbuf, bytes_to_write,
						pos);
	} else if (!uses_slices && ci->index_block != 0) {
		/* File currently uses traditional storage - keep using it (small content) */
		pr_debug(
			"Writing small content to existing traditional storage file\n");
		ret = ouichefs_write_large_file(inode, kbuf, bytes_to_write,
						pos);
	} else {
		/* File will use slice storage (new small file or existing slice file) */
		pr_debug("Writing to small file using multi-slice storage\n");
		ret = ouichefs_write_small_file(inode, kbuf, bytes_to_write,
						pos);
	}

cleanup:
	kfree(kbuf);
	return ret;
}

/*
 * Enhanced write to small files using multi-slice storage
 */
static ssize_t ouichefs_write_small_file(struct inode *inode, const char *kbuf,
					 size_t bytes_to_write, loff_t *pos)
{
	struct super_block *sb = inode->i_sb;
	struct ouichefs_inode_info *ci = OUICHEFS_INODE(inode);
	uint32_t block_num, slice_start;
	uint32_t current_slices_used = 0;
	uint32_t new_size =
		max((size_t)inode->i_size, (size_t)(*pos + bytes_to_write));
	uint32_t required_slices = ouichefs_slices_needed(new_size);
	bool need_new_allocation = false;
	bool need_expansion = false;
	ssize_t ret;

	pr_debug(
		"Writing %zu bytes to small file, current_size=%lld, new_size=%u, required_slices=%u\n",
		bytes_to_write, inode->i_size, new_size, required_slices);

	/* Determine current allocation status */
	if (inode->i_size == 0 || ci->index_block == 0) {
		need_new_allocation = true;
	} else {
		block_num = ouichefs_get_slice_block(ci->index_block);
		slice_start = ouichefs_get_slice_number(ci->index_block);
		current_slices_used = ouichefs_slices_needed(inode->i_size);

		if (block_num == 0 || slice_start == 0 ||
		    slice_start >= OUICHEFS_SLICES_PER_BLOCK) {
			pr_err("Invalid slice information: block=%u, slice=%u\n",
			       block_num, slice_start);
			need_new_allocation = true;
		} else if (required_slices > current_slices_used) {
			need_expansion = true;
		}
	}

	/* Handle allocation/expansion */
	if (need_new_allocation) {
		/* Allocate new contiguous slices */
		block_num = ouichefs_alloc_slices(sb, &slice_start,
						  required_slices);
		if (!block_num) {
			pr_err("Failed to allocate %u slices for small file\n",
			       required_slices);
			return -ENOSPC;
		}

		ci->index_block =
			ouichefs_make_slice_index(block_num, slice_start);
		pr_debug("Allocated %u new slices: block=%u, slice=%u\n",
			 required_slices, block_num, slice_start);
	} else if (need_expansion) {
		/* Try to expand in place or relocate */
		struct buffer_head *bh;
		struct ouichefs_sliced_block_meta *meta;
		uint32_t bitmap;
		bool can_expand_in_place = true;

		/* Check if we can expand in place */
		bh = sb_bread(sb, block_num);
		if (!bh) {
			pr_err("Failed to read block %u for expansion check\n",
			       block_num);
			return -EIO;
		}

		meta = (struct ouichefs_sliced_block_meta *)bh->b_data;
		bitmap = le32_to_cpu(meta->slice_bitmap);

		/* Check if subsequent slices are free */
		for (uint32_t i = current_slices_used; i < required_slices;
		     i++) {
			if (slice_start + i >= OUICHEFS_SLICES_PER_BLOCK ||
			    !(bitmap & (1U << (slice_start + i)))) {
				can_expand_in_place = false;
				break;
			}
		}

		if (can_expand_in_place) {
			/* Allocate additional slices in place */
			for (uint32_t i = current_slices_used;
			     i < required_slices; i++) {
				bitmap &= ~(1U << (slice_start + i));
			}
			meta->slice_bitmap = cpu_to_le32(bitmap);
			mark_buffer_dirty(bh);
			sync_dirty_buffer(bh);

			pr_debug("Expanded in place from %u to %u slices\n",
				 current_slices_used, required_slices);
		} else {
			/* Need to relocate to get contiguous space */
			brelse(bh);

			/* Use the relocate function to handle the move efficiently */
			uint32_t new_block = ouichefs_try_relocate_slices(
				sb, block_num, slice_start, current_slices_used,
				required_slices, &slice_start);
			if (!new_block) {
				pr_err("Failed to relocate slices for expansion from %u to %u slices\n",
				       current_slices_used, required_slices);
				return -ENOSPC;
			}

			/* Update inode to point to new location */
			block_num = new_block;
			ci->index_block = ouichefs_make_slice_index(
				block_num, slice_start);

			pr_info("Successfully relocated file from %u to %u slices (block %u, slice %u)\n",
				current_slices_used, required_slices, block_num,
				slice_start);
		}

		brelse(bh);
	}

	/* Now perform the actual write operation */
	char *write_buffer =
		kmalloc(required_slices * OUICHEFS_SLICE_SIZE, GFP_KERNEL);
	if (!write_buffer) {
		pr_err("Failed to allocate write buffer\n");
		return -ENOMEM;
	}

	/* Initialize buffer with zeros */
	memset(write_buffer, 0, required_slices * OUICHEFS_SLICE_SIZE);

	/* Read existing data if doing partial overwrite */
	if (*pos > 0 || (*pos + bytes_to_write < new_size)) {
		if (inode->i_size > 0) {
			ssize_t read_ret = ouichefs_read_slices(
				sb, block_num, slice_start, required_slices,
				write_buffer, inode->i_size);
			if (read_ret < 0) {
				pr_err("Failed to read existing data for partial write: %zd\n",
				       read_ret);
				kfree(write_buffer);
				return read_ret;
			}
		}
	}

	/* Copy new data into buffer */
	if (*pos + bytes_to_write > required_slices * OUICHEFS_SLICE_SIZE) {
		pr_err("Write would exceed allocated slice space\n");
		kfree(write_buffer);
		return -EFBIG;
	}

	memcpy(write_buffer + *pos, kbuf, bytes_to_write);

	/* Write the complete buffer */
	ret = ouichefs_write_slices(sb, block_num, slice_start, required_slices,
				    write_buffer, new_size);
	if (ret < 0) {
		pr_err("Failed to write data to slices: %zd\n", ret);
		kfree(write_buffer);
		return ret;
	}

	kfree(write_buffer);

	/* Update file metadata */
	*pos += bytes_to_write;
	if (*pos > inode->i_size) {
		inode->i_size = *pos;
	}
	inode->i_blocks =
		0; /* Small files don't count blocks in traditional sense */
	inode->i_mtime = inode->i_ctime = current_time(inode);
	mark_inode_dirty(inode);

	pr_debug(
		"Multi-slice write completed: wrote %zu bytes, new file size=%lld, using %u slices\n",
		bytes_to_write, (long long)inode->i_size, required_slices);

	return bytes_to_write;
}

/*
 * Convert a small file from slice storage to traditional storage
 * Enhanced to handle multi-slice files
 */
static ssize_t ouichefs_convert_to_traditional(struct inode *inode,
					       const char *new_data,
					       size_t new_data_len, loff_t *pos)
{
	struct super_block *sb = inode->i_sb;
	struct ouichefs_sb_info *sbi = OUICHEFS_SB(sb);
	struct ouichefs_inode_info *ci = OUICHEFS_INODE(inode);
	uint32_t old_block_num = 0, old_slice_start = 0, old_slices_used = 0;
	uint32_t new_index_block, first_data_block;
	struct buffer_head *bh_index, *bh_data;
	struct ouichefs_file_index_block *index;
	char *combined_data = NULL;
	size_t old_data_size = inode->i_size;
	size_t final_size = max((size_t)(*pos + new_data_len), old_data_size);
	bool currently_uses_slices = false;
	ssize_t ret;

	pr_info("Converting multi-slice file to traditional storage: old_size=%zu, new_size=%zu\n",
		old_data_size, final_size);

	/* Check if the file currently uses slice storage */
	if (old_data_size <= OUICHEFS_SMALL_FILE_THRESHOLD &&
	    ci->index_block != 0) {
		old_block_num = ouichefs_get_slice_block(ci->index_block);
		old_slice_start = ouichefs_get_slice_number(ci->index_block);
		old_slices_used = ouichefs_slices_needed(old_data_size);
		currently_uses_slices =
			(old_block_num != 0 && old_slice_start != 0 &&
			 old_slice_start < OUICHEFS_SLICES_PER_BLOCK);
	}

	pr_debug(
		"File currently uses slices: %s (block=%u, slice=%u, count=%u)\n",
		currently_uses_slices ? "yes" : "no", old_block_num,
		old_slice_start, old_slices_used);

	/* Allocate buffer for combined data */
	combined_data = kzalloc(final_size, GFP_KERNEL);
	if (!combined_data)
		return -ENOMEM;

	/* Read existing data */
	if (old_data_size > 0) {
		if (currently_uses_slices) {
			/* Read from multiple slices */
			ret = ouichefs_read_slices(
				sb, old_block_num, old_slice_start,
				old_slices_used, combined_data, old_data_size);
			if (ret < 0) {
				pr_err("Failed to read old slice data: %zd\n",
				       ret);
				kfree(combined_data);
				return ret;
			}
			pr_debug("Read %zd bytes from %u slices\n",
				 old_data_size, old_slices_used);
		} else if (ci->index_block != 0) {
			/* Read from traditional storage */
			ret = ouichefs_read_traditional_file(
				inode, combined_data, old_data_size);
			if (ret < 0) {
				pr_err("Failed to read old traditional data: %zd\n",
				       ret);
				kfree(combined_data);
				return ret;
			}
			pr_debug("Read %zd bytes from traditional storage\n",
				 old_data_size);
		}
	}

	/* Merge new data into combined buffer */
	if (*pos < final_size && new_data_len > 0) {
		size_t copy_len =
			min(new_data_len, (size_t)(final_size - *pos));
		memcpy(combined_data + *pos, new_data, copy_len);
		pr_debug("Merged %zu bytes of new data at position %lld\n",
			 copy_len, *pos);
	}

	/* Free old storage if it uses slices */
	if (currently_uses_slices) {
		ouichefs_free_slices(sb, old_block_num, old_slice_start,
				     old_slices_used);
		pr_debug(
			"Freed %u old slices starting at slice %u in block %u\n",
			old_slices_used, old_slice_start, old_block_num);
	} else if (old_data_size > OUICHEFS_SMALL_FILE_THRESHOLD &&
		   ci->index_block != 0) {
		/* File was already traditional - we need to free old blocks */
		ouichefs_free_traditional_blocks(inode);
		pr_debug("Freed old traditional blocks\n");
	}

	/* Allocate new index block */
	new_index_block = get_free_block(sbi);
	if (!new_index_block) {
		pr_err("Failed to allocate index block\n");
		kfree(combined_data);
		return -ENOSPC;
	}

	/* Initialize the index block */
	bh_index = sb_bread(sb, new_index_block);
	if (!bh_index) {
		put_block(sbi, new_index_block);
		kfree(combined_data);
		return -EIO;
	}

	index = (struct ouichefs_file_index_block *)bh_index->b_data;
	memset(index, 0, OUICHEFS_BLOCK_SIZE);

	/* Calculate how many data blocks we need */
	uint32_t blocks_needed =
		(final_size + OUICHEFS_BLOCK_SIZE - 1) / OUICHEFS_BLOCK_SIZE;
	if (blocks_needed == 0)
		blocks_needed = 1;

	pr_debug("Need %u data blocks for %zu bytes\n", blocks_needed,
		 final_size);

	/* Allocate and write data blocks */
	size_t bytes_written = 0;
	for (uint32_t i = 0; i < blocks_needed; i++) {
		first_data_block = get_free_block(sbi);
		if (!first_data_block) {
			pr_err("Failed to allocate data block %u\n", i);
			/* Clean up already allocated blocks */
			for (uint32_t j = 0; j < i; j++) {
				if (index->blocks[j] != 0) {
					put_block(
						sbi,
						le32_to_cpu(index->blocks[j]));
				}
			}
			brelse(bh_index);
			put_block(sbi, new_index_block);
			kfree(combined_data);
			return -ENOSPC;
		}

		index->blocks[i] = cpu_to_le32(first_data_block);

		/* Write data to this block */
		bh_data = sb_bread(sb, first_data_block);
		if (!bh_data) {
			pr_err("Failed to read data block %u\n",
			       first_data_block);
			put_block(sbi, first_data_block);
			continue;
		}

		memset(bh_data->b_data, 0, OUICHEFS_BLOCK_SIZE);

		size_t bytes_to_copy = min((size_t)OUICHEFS_BLOCK_SIZE,
					   final_size - bytes_written);
		if (bytes_to_copy > 0) {
			memcpy(bh_data->b_data, combined_data + bytes_written,
			       bytes_to_copy);
			bytes_written += bytes_to_copy;
		}

		mark_buffer_dirty(bh_data);
		sync_dirty_buffer(bh_data);
		brelse(bh_data);

		pr_debug("Wrote %zu bytes to data block %u\n", bytes_to_copy,
			 first_data_block);
	}

	/* Save the index block */
	mark_buffer_dirty(bh_index);
	sync_dirty_buffer(bh_index);
	brelse(bh_index);

	/* Update inode to use traditional storage */
	ci->index_block = new_index_block;
	inode->i_size = final_size;
	inode->i_blocks = blocks_needed + 1; /* +1 for index block */
	*pos += (new_data_len <= final_size - *pos) ? new_data_len :
						      (final_size - *pos);
	inode->i_mtime = inode->i_ctime = current_time(inode);
	mark_inode_dirty(inode);

	kfree(combined_data);

	pr_info("Conversion completed: multi-slice file now uses traditional storage, size=%zu, blocks=%llu\n",
		final_size, inode->i_blocks);

	return new_data_len;
}

/*
 * Write to large files using traditional storage
 */
static ssize_t ouichefs_write_large_file(struct inode *inode, const char *kbuf,
					 size_t bytes_to_write, loff_t *pos)
{
	struct super_block *sb = inode->i_sb;
	struct ouichefs_sb_info *sbi = OUICHEFS_SB(sb);
	struct ouichefs_inode_info *ci = OUICHEFS_INODE(inode);
	struct ouichefs_file_index_block *index;
	struct buffer_head *bh_index, *bh_data;
	size_t bytes_written = 0;
	size_t new_file_size;
	uint32_t blocks_needed, blocks_allocated;

	pr_debug("Writing %zu bytes to large file at position %lld\n",
		 bytes_to_write, *pos);

	/* Calculate new file size */
	new_file_size =
		max((size_t)inode->i_size, (size_t)(*pos + bytes_to_write));

	/* Read the index block */
	bh_index = sb_bread(sb, ci->index_block);
	if (!bh_index) {
		pr_err("Failed to read index block %u\n", ci->index_block);
		return -EIO;
	}
	index = (struct ouichefs_file_index_block *)bh_index->b_data;

	/* Calculate how many blocks we need for the new file size */
	blocks_needed =
		(new_file_size + OUICHEFS_BLOCK_SIZE - 1) / OUICHEFS_BLOCK_SIZE;
	blocks_allocated = inode->i_blocks - 1; /* Subtract index block */

	pr_debug("Current blocks: %u, needed blocks: %u\n", blocks_allocated,
		 blocks_needed);

	/* Allocate additional blocks if needed */
	if (blocks_needed > blocks_allocated) {
		uint32_t blocks_to_allocate = blocks_needed - blocks_allocated;

		if (blocks_to_allocate > sbi->nr_free_blocks) {
			pr_err("Not enough free blocks (need %u, have %u)\n",
			       blocks_to_allocate, sbi->nr_free_blocks);
			brelse(bh_index);
			return -ENOSPC;
		}

		/* Allocate new data blocks */
		for (uint32_t i = blocks_allocated; i < blocks_needed; i++) {
			uint32_t new_block = get_free_block(sbi);
			if (!new_block) {
				pr_err("Failed to allocate block %u\n", i);
				brelse(bh_index);
				return -ENOSPC;
			}

			index->blocks[i] = cpu_to_le32(new_block);

			/* Initialize the new block with zeros */
			bh_data = sb_bread(sb, new_block);
			if (bh_data) {
				memset(bh_data->b_data, 0, OUICHEFS_BLOCK_SIZE);
				mark_buffer_dirty(bh_data);
				sync_dirty_buffer(bh_data);
				brelse(bh_data);
			}

			pr_debug("Allocated new data block %u at index %u\n",
				 new_block, i);
		}

		/* Update the index block */
		mark_buffer_dirty(bh_index);
		sync_dirty_buffer(bh_index);
	}

	/* Write the data block by block */
	while (bytes_written < bytes_to_write) {
		uint32_t block_index =
			(*pos + bytes_written) / OUICHEFS_BLOCK_SIZE;
		uint32_t block_offset =
			(*pos + bytes_written) % OUICHEFS_BLOCK_SIZE;
		uint32_t bytes_in_block =
			min((size_t)(OUICHEFS_BLOCK_SIZE - block_offset),
			    bytes_to_write - bytes_written);

		if (block_index >= blocks_needed) {
			pr_err("Block index %u exceeds allocated blocks %u\n",
			       block_index, blocks_needed);
			break;
		}

		uint32_t data_block = le32_to_cpu(index->blocks[block_index]);
		if (data_block == 0) {
			pr_err("Data block %u not allocated\n", block_index);
			break;
		}

		/* Read the data block */
		bh_data = sb_bread(sb, data_block);
		if (!bh_data) {
			pr_err("Failed to read data block %u\n", data_block);
			break;
		}

		/* Write data to the block */
		memcpy(bh_data->b_data + block_offset, kbuf + bytes_written,
		       bytes_in_block);

		mark_buffer_dirty(bh_data);
		sync_dirty_buffer(bh_data);
		brelse(bh_data);

		bytes_written += bytes_in_block;

		pr_debug("Wrote %u bytes to block %u at offset %u\n",
			 bytes_in_block, data_block, block_offset);
	}

	brelse(bh_index);

	if (bytes_written > 0) {
		/* Update file metadata */
		*pos += bytes_written;
		if (*pos > inode->i_size) {
			inode->i_size = *pos;
		}
		inode->i_blocks = blocks_needed + 1; /* +1 for index block */
		inode->i_mtime = inode->i_ctime = current_time(inode);
		mark_inode_dirty(inode);

		pr_debug(
			"Large file write completed: %zu bytes, new size=%lld, blocks=%llu\n",
			bytes_written, (long long)inode->i_size,
			inode->i_blocks);
	}

	return bytes_written;
}

/*
 * Read data from a traditional file (using index blocks)
 */
static ssize_t ouichefs_read_traditional_file(struct inode *inode, char *buffer,
					      size_t size)
{
	struct super_block *sb = inode->i_sb;
	struct ouichefs_inode_info *ci = OUICHEFS_INODE(inode);
	struct ouichefs_file_index_block *index;
	struct buffer_head *bh_index, *bh_data;
	size_t bytes_read = 0;
	size_t bytes_to_read = min(size, (size_t)inode->i_size);

	if (ci->index_block == 0 || bytes_to_read == 0) {
		return 0;
	}

	/* Read the index block */
	bh_index = sb_bread(sb, ci->index_block);
	if (!bh_index) {
		pr_err("Failed to read index block %u\n", ci->index_block);
		return -EIO;
	}
	index = (struct ouichefs_file_index_block *)bh_index->b_data;

	/* Read data block by block */
	while (bytes_read < bytes_to_read) {
		uint32_t block_index = bytes_read / OUICHEFS_BLOCK_SIZE;
		uint32_t block_offset = bytes_read % OUICHEFS_BLOCK_SIZE;
		uint32_t bytes_in_block =
			min((size_t)(OUICHEFS_BLOCK_SIZE - block_offset),
			    bytes_to_read - bytes_read);

		uint32_t data_block = le32_to_cpu(index->blocks[block_index]);
		if (data_block == 0) {
			pr_debug(
				"Unallocated block at index %u, stopping read\n",
				block_index);
			break;
		}

		/* Read the data block */
		bh_data = sb_bread(sb, data_block);
		if (!bh_data) {
			pr_err("Failed to read data block %u\n", data_block);
			break;
		}

		/* Copy data from the block */
		memcpy(buffer + bytes_read, bh_data->b_data + block_offset,
		       bytes_in_block);

		brelse(bh_data);
		bytes_read += bytes_in_block;
	}

	brelse(bh_index);
	return bytes_read;
}

/*
 * Free all data blocks used by a traditional file
 */
static void ouichefs_free_traditional_blocks(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct ouichefs_sb_info *sbi = OUICHEFS_SB(sb);
	struct ouichefs_inode_info *ci = OUICHEFS_INODE(inode);
	struct ouichefs_file_index_block *index;
	struct buffer_head *bh_index;
	uint32_t blocks_to_free =
		inode->i_blocks - 1; /* Subtract index block */

	if (ci->index_block == 0) {
		return;
	}

	/* Read the index block */
	bh_index = sb_bread(sb, ci->index_block);
	if (!bh_index) {
		pr_err("Failed to read index block %u for cleanup\n",
		       ci->index_block);
		return;
	}
	index = (struct ouichefs_file_index_block *)bh_index->b_data;

	/* Free all data blocks */
	for (uint32_t i = 0; i < blocks_to_free; i++) {
		uint32_t data_block = le32_to_cpu(index->blocks[i]);
		if (data_block != 0) {
			put_block(sbi, data_block);
			pr_debug("Freed traditional data block %u\n",
				 data_block);
		}
	}

	brelse(bh_index);

	/* Free the index block */
	put_block(sbi, ci->index_block);
	pr_debug("Freed traditional index block %u\n", ci->index_block);
}

/* IOCTL implementation */
#include "ouichefs_ioctl.h"

/*
 * IOCTL handler for displaying block content
 */
static long ouichefs_display_block_ioctl(struct file *file, unsigned long arg)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct ouichefs_inode_info *ci = OUICHEFS_INODE(inode);
	struct ouichefs_block_display __user *user_data;
	struct ouichefs_block_display *display_data;
	struct buffer_head *bh;
	struct ouichefs_sliced_block_meta *meta;
	uint32_t block_num, slice_num;
	char *block_data;
	int i, ret = 0;

	/* Check if this is a regular file */
	if (!S_ISREG(inode->i_mode)) {
		pr_err("IOCTL: File is not a regular file\n");
		return -EINVAL;
	}

	/* Check if file is small enough to use sliced storage */
	if (inode->i_size > OUICHEFS_SMALL_FILE_THRESHOLD) {
		pr_err("IOCTL: File size (%lld) exceeds slice storage limit (%u bytes)\n",
		       inode->i_size, OUICHEFS_SMALL_FILE_THRESHOLD);
		return -EINVAL;
	}

	/* Check if file is not empty */
	if (ci->index_block == 0) {
		pr_err("IOCTL: File has no storage allocated\n");
		return -ENODATA;
	}

	/* Extract slice information */
	block_num = ouichefs_get_slice_block(ci->index_block);
	slice_num = ouichefs_get_slice_number(ci->index_block);

	/* Validate slice information */
	if (block_num == 0 || slice_num == 0 ||
	    slice_num >= OUICHEFS_SLICES_PER_BLOCK) {
		pr_err("IOCTL: Invalid slice info - block:%u slice:%u\n",
		       block_num, slice_num);
		return -EINVAL;
	}

	/* Allocate memory for display data */
	display_data =
		kmalloc(sizeof(struct ouichefs_block_display), GFP_KERNEL);
	if (!display_data) {
		return -ENOMEM;
	}

	/* Read the block from disk */
	bh = sb_bread(sb, block_num);
	if (!bh) {
		pr_err("IOCTL: Failed to read block %u\n", block_num);
		ret = -EIO;
		goto free_display_data;
	}

	block_data = bh->b_data;
	display_data->block_number = block_num;

	/* Copy all slices from the block */
	for (i = 0; i < OUICHEFS_SLICES_PER_BLOCK; i++) {
		memcpy(display_data->slices[i],
		       block_data + (i * OUICHEFS_SLICE_SIZE),
		       OUICHEFS_SLICE_SIZE);
	}

	brelse(bh);

	/* Copy data to user space */
	user_data = (struct ouichefs_block_display __user *)arg;
	if (copy_to_user(user_data, display_data,
			 sizeof(struct ouichefs_block_display))) {
		ret = -EFAULT;
		goto free_display_data;
	}

	/* Print debug information to kernel log */
	uint32_t slices_used = ouichefs_slices_needed(inode->i_size);
	pr_info("IOCTL: Block %u content displayed for multi-slice file (inode %lu, size %lld, slices %u)\n",
		block_num, inode->i_ino, inode->i_size, slices_used);

	pr_info("IOCTL: File uses %u slices starting at slice %u in block %u\n",
		slices_used, slice_num, block_num);

	/* Verify and display metadata */
	meta = (struct ouichefs_sliced_block_meta *)display_data->slices[0];
	if (le32_to_cpu(meta->magic) == OUICHEFS_SLICED_MAGIC) {
		uint32_t bitmap = le32_to_cpu(meta->slice_bitmap);
		uint32_t next_block = le32_to_cpu(meta->next_block);
		pr_info("IOCTL: Block metadata - Magic:0x%08X Bitmap:0x%08X Next:%u\n",
			le32_to_cpu(meta->magic), bitmap, next_block);
	} else {
		pr_warn("IOCTL: Block metadata has invalid magic number (not sliced): 0x%08X\n",
			le32_to_cpu(meta->magic));
	}

free_display_data:
	kfree(display_data);
	return ret;
}

/*
 * IOCTL dispatcher
 */
static long ouichefs_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	switch (cmd) {
	case OUICHEFS_IOC_DISPLAY_BLOCK:
		return ouichefs_display_block_ioctl(file, arg);
	default:
		return -ENOTTY; /* Not a valid ioctl command */
	}
}

/*
 * Compatibility IOCTL for 32-bit applications on 64-bit systems
 */
/*#ifdef CONFIG_COMPAT
static long ouichefs_compat_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	return ouichefs_ioctl(file, cmd, arg);
}
#endif*/

const struct file_operations ouichefs_file_ops = {
	.owner = THIS_MODULE,
	.open = ouichefs_open,
	.llseek = generic_file_llseek,
	.read = ouichefs_read,
	.write = ouichefs_write,
	.unlocked_ioctl = ouichefs_ioctl,
	/*#ifdef CONFIG_COMPAT
	.compat_ioctl = ouichefs_compat_ioctl,
#endif*/
	.read_iter = generic_file_read_iter,
	.write_iter = generic_file_write_iter,
	.fsync = generic_file_fsync,
};