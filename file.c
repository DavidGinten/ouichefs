// SPDX-License-Identifier: GPL-2.0
/*
 * ouiche_fs - a simple educational filesystem for Linux
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

	// If block number exceeds filesize, fail /
	// Because one file has max. 1024 blocks
	if (iblock >= OUICHEFS_BLOCK_SIZE >> 2)
		return -EFBIG;

	// Read index block from disk /
	bh_index = sb_bread(sb, ci->index_block);
	if (!bh_index)
		return -EIO;
	index = (struct ouichefs_file_index_block *)bh_index->b_data;

	//
	 // Check if iblock is already allocated. If not and create is true,
	 // allocate it. Else, get the physical block number.
	 //
	if (index->blocks[iblock] == 0) {
		if (!create) {
			ret = 0;
			goto brelse_index;
		}
		// get_free_block returns an index and index->blocks[iblock]
		// is now the reference to this newly allocated block
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
	// Map the physical block to the given buffer_head /
	map_bh(bh_result, sb, bno);

brelse_index:
	brelse(bh_index);
	return ret;
}

/*
 * Called by the page cache to read a page from the physical disk and map it in
 * memory.
 */
static void ouichefs_readahead(struct readahead_control *rac)
{
	mpage_readahead(rac, ouichefs_file_get_block);
}

/*
 * Called by the page cache to write a dirty page to the physical disk (when
 * sync is called or when memory is needed).
 */
static int ouichefs_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, ouichefs_file_get_block, wbc);
}

/*
 * Called by the VFS when a write() syscall occurs on file before writing the
 * data in the page cache. This functions checks if the write will be able to
 * complete and allocates the necessary blocks through block_write_begin().
 */
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
		/* Small file operations are handled by custom read/write functions */
		return -EINVAL;
	}

	// Check if the write can be completed (enough space?) /
	if (pos + len > OUICHEFS_MAX_FILESIZE)
		return -ENOSPC;
	nr_allocs = max(pos + len, file->f_inode->i_size) / OUICHEFS_BLOCK_SIZE;
	if (nr_allocs > file->f_inode->i_blocks - 1) // Subtract the index block
		nr_allocs -= file->f_inode->i_blocks - 1;
	else
		nr_allocs = 0;
	if (nr_allocs > sbi->nr_free_blocks)
		return -ENOSPC;

	// prepare the write /
	err = block_write_begin(mapping, pos, len, pagep,
				ouichefs_file_get_block);
	// if this failed, reclaim newly allocated blocks /
	if (err < 0) {
		pr_err("%s:%d: newly allocated blocks reclaim not implemented yet\n",
		       __func__, __LINE__);
	}
	return err;
}

/*
 * Called by the VFS after writing data from a write() syscall to the page
 * cache. This functions updates inode metadata and truncates the file if
 * necessary.
 */
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

	// Complete the write()
	ret = generic_write_end(file, mapping, pos, len, copied, page, fsdata);
	if (ret < len) {
		pr_err("%s:%d: wrote less than asked... what do I do? nothing for now...\n",
		       __func__, __LINE__);
	} else {
		uint32_t nr_blocks_old = inode->i_blocks;

		// Update inode metadata
		inode->i_blocks = (roundup(inode->i_size, OUICHEFS_BLOCK_SIZE) /
				   OUICHEFS_BLOCK_SIZE) +
				  1;
		inode->i_mtime = inode->i_ctime = current_time(inode);
		mark_inode_dirty(inode);

		// If file is smaller than before, free unused blocks
		if (nr_blocks_old > inode->i_blocks) {
			int i;
			struct buffer_head *bh_index;
			struct ouichefs_file_index_block *index;

			// Free unused blocks from page cache
			truncate_pagecache(inode, inode->i_size);

			// Read index block to remove unused blocks
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
				put_block(OUICHEFS_SB(sb), le32_to_cpu(index->blocks[i]));
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

static int ouichefs_open(struct inode *inode, struct file *file)
{
	bool wronly = (file->f_flags & O_WRONLY) != 0;
	bool rdwr = (file->f_flags & O_RDWR) != 0;
	bool trunc = (file->f_flags & O_TRUNC) != 0;
	bool append = (file->f_flags & O_APPEND) != 0;
	pr_info("trunc: %d", trunc);
	pr_info("append: %d", append);
	if ((wronly || rdwr) && trunc && (inode->i_size != 0)) {
		struct super_block *sb = inode->i_sb;
		struct ouichefs_sb_info *sbi = OUICHEFS_SB(sb);
		struct ouichefs_inode_info *ci = OUICHEFS_INODE(inode);

		/* Handle truncation for small files differently */
		if (ouichefs_is_small_file(inode->i_size)) {
			uint32_t block_num = ouichefs_get_slice_block(ci->index_block);
			uint32_t slice_num = ouichefs_get_slice_number(ci->index_block);
			
			/* Free the slice */
			ouichefs_free_slice(sb, block_num, slice_num);
			
			/* Reset inode */
			inode->i_size = 0;
			inode->i_blocks = 0;
			ci->index_block = 0;
		} else {
			/* Handle truncation for regular files */
			struct ouichefs_file_index_block *index;
			struct buffer_head *bh_index;
			sector_t iblock;

			bh_index = sb_bread(sb, ci->index_block);
			if (!bh_index)
				return -EIO;
			index = (struct ouichefs_file_index_block *)bh_index->b_data;

			for (iblock = 0; index->blocks[iblock] != 0; iblock++) {
				put_block(sbi, le32_to_cpu(index->blocks[iblock]));
				index->blocks[iblock] = 0;
			}
			inode->i_size = 0;
			inode->i_blocks = 1;

			mark_buffer_dirty(bh_index);
			brelse(bh_index);
		}
	}
	/* For appending - We append the new content to the file */
	if ((wronly || rdwr) && append && (inode->i_size != 0)) {
		struct super_block *sb = inode->i_sb;
		struct ouichefs_sb_info *sbi = OUICHEFS_SB(sb);
		struct ouichefs_inode_info *ci = OUICHEFS_INODE(inode);

		/* Handle appending for small files differently */
		if (ouichefs_is_small_file(inode->i_size)) {
			file->f_pos = inode->i_size;
		} else {
			/* Handle appending for regular files */
			struct ouichefs_file_index_block *index;
			struct buffer_head *bh_index;
			sector_t iblock;

			bh_index = sb_bread(sb, ci->index_block);
			if (!bh_index)
				return -EIO;
			index = (struct ouichefs_file_index_block *)bh_index->b_data;

			for (iblock = 0; index->blocks[iblock] != 0; iblock++) {
				put_block(sbi, le32_to_cpu(index->blocks[iblock]));
				index->blocks[iblock] = 0;
			}
			inode->i_size = 0;
			inode->i_blocks = 1;

			mark_buffer_dirty(bh_index);
			brelse(bh_index);
		}
	}
	return 0;
}

static ssize_t ouichefs_read(struct file *file, char __user *buf, size_t len, loff_t *pos)
{
	struct inode *inode = file->f_inode;

	if (*pos >= inode->i_size)
		return 0;  // EOF: no more data to read

	struct super_block *sb = inode->i_sb;
	struct buffer_head *bh, *bh_index;
	struct ouichefs_inode_info *ci = OUICHEFS_INODE(inode);
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
			// outside file limits or max blocks
			break;
		}

		uint32_t bno = le32_to_cpu(index->blocks[block_num]);
		if (bno == 0) {
			// block not allocated, treat as zeroes or EOF
			break;
		}

		/* Get current block for reading data from disk */
		// Use sb_bread and brelse to read data directly from the disk.
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
	pr_info("READ: total_copied=%zu, data: %.6s\n", total_copied, kbuf);

	if (copy_to_user(buf, kbuf, total_copied)) {
		kfree(kbuf);
		brelse(bh_index);
		return -EFAULT;
	}

	kfree(kbuf);
	brelse(bh_index);
	// Return the amount of bytes that have been copied to userspace.
	return total_copied;
}

static ssize_t ouichefs_write(struct file *file, const char __user *buf, size_t len, loff_t *pos)
{
	struct inode *inode = file->f_inode;
	struct super_block *sb = inode->i_sb;
	struct ouichefs_inode_info *ci = OUICHEFS_INODE(inode);
	char *kbuf = NULL;
	uint32_t block_num, slice_num;
	size_t bytes_to_write;
	ssize_t ret;
	bool need_new_slice = false;

	if (*pos >= OUICHEFS_MAX_FILESIZE)
		return -ENOSPC;

	/* Check if final file size will exceed 128 bytes - return error if so */
	if (*pos + len > 128) {
		pr_err("File size would exceed 128 bytes (%lld + %zu = %lld bytes)\n", 
		       *pos, len, *pos + len);
		return -EFBIG;
	}

	/* Calculate how many bytes we can actually write within 128 byte limit */
	bytes_to_write = min(len, (size_t)(128 - *pos));
	
	if (bytes_to_write == 0)
		return 0;

	/* Copy data from user space */
	kbuf = kmalloc(bytes_to_write, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	if (copy_from_user(kbuf, buf, bytes_to_write)) {
		ret = -EFAULT;
		goto cleanup;
	}

	pr_debug("WRITE: len=%zu, pos=%lld, data: %.10s\n", bytes_to_write, *pos, kbuf);

	/* Determine if we need a new slice or can use existing one */
	if (inode->i_size == 0) {
		/* Empty file - need to allocate new slice */
		need_new_slice = true;
	} else {
		/* File already has data - check if it has a valid slice allocated */
		if (ci->index_block == 0) {
			need_new_slice = true;
		} else {
			/* Extract existing slice information */
			block_num = ouichefs_get_slice_block(ci->index_block);
			slice_num = ouichefs_get_slice_number(ci->index_block);
			
			/* Validate the slice information */
			if (block_num == 0 || slice_num == 0 || slice_num >= OUICHEFS_SLICES_PER_BLOCK) {
				pr_err("Invalid slice information: block=%u, slice=%u\n", 
				       block_num, slice_num);
				need_new_slice = true;
			}
		}
	}

	/* Allocate new slice if needed */
	if (need_new_slice) {
		block_num = ouichefs_alloc_slice(sb, &slice_num);
		if (!block_num) {
			pr_err("Failed to allocate slice for small file\n");
			ret = -ENOSPC;
			goto cleanup;
		}
		
		/* Update inode with new slice location */
		ci->index_block = ouichefs_make_slice_index(block_num, slice_num);
		
		pr_debug("Allocated new slice: block=%u, slice=%u, index=0x%x\n", 
			 block_num, slice_num, ci->index_block);
	}

	/* Handle the write operation */
	if (*pos == 0 && bytes_to_write <= 128) {
		/* Complete overwrite of file content - need to clear the slice first */
		char *slice_buffer = kmalloc(OUICHEFS_SLICE_SIZE, GFP_KERNEL);
		if (!slice_buffer) {
			ret = -ENOMEM;
			goto cleanup;
		}
		
		/* Clear the entire slice buffer */
		memset(slice_buffer, 0, OUICHEFS_SLICE_SIZE);
		
		/* Copy new data into the cleared buffer */
		memcpy(slice_buffer, kbuf, bytes_to_write);
		
		/* Write the cleared buffer with new content to the slice */
		ret = ouichefs_write_slice(sb, block_num, slice_num, slice_buffer, OUICHEFS_SLICE_SIZE);
		
		kfree(slice_buffer);
		
		if (ret < 0) {
			pr_err("Failed to write slice: %zd\n", ret);
			goto cleanup;
		}
		
		/* Update file size to match written data */
		inode->i_size = bytes_to_write;
		
		/* Return the number of bytes written */
		ret = bytes_to_write;
		
	} else {
		/* Partial write or append - need to read existing data first */
		char *slice_buffer = kmalloc(OUICHEFS_SLICE_SIZE, GFP_KERNEL);
		if (!slice_buffer) {
			ret = -ENOMEM;
			goto cleanup;
		}
		
		/* Initialize buffer with zeros */
		memset(slice_buffer, 0, OUICHEFS_SLICE_SIZE);
		
		/* Read existing data if file is not empty */
		if (inode->i_size > 0) {
			ssize_t read_ret = ouichefs_read_slice(sb, block_num, slice_num, 
							       slice_buffer, inode->i_size);
			if (read_ret < 0) {
				pr_err("Failed to read existing slice data: %zd\n", read_ret);
				kfree(slice_buffer);
				ret = read_ret;
				goto cleanup;
			}
		}
		
		/* Check bounds for the write operation */
		if (*pos + bytes_to_write > OUICHEFS_SLICE_SIZE) {
			pr_err("Write would exceed slice boundaries\n");
			kfree(slice_buffer);
			ret = -EFBIG;
			goto cleanup;
		}
		
		/* Copy new data into the buffer at the specified position */
		memcpy(slice_buffer + *pos, kbuf, bytes_to_write);
		
		/* Write the updated buffer back to the slice */
		size_t new_size = max((size_t)inode->i_size, (size_t)(*pos + bytes_to_write));
		ret = ouichefs_write_slice(sb, block_num, slice_num, slice_buffer, new_size);
		
		kfree(slice_buffer);
		
		if (ret < 0) {
			pr_err("Failed to write updated slice: %zd\n", ret);
			goto cleanup;
		}
		
		/* Update file size if we extended the file */
		if (*pos + bytes_to_write > inode->i_size) {
			inode->i_size = *pos + bytes_to_write;
		}
		
		/* Return the number of bytes actually written by this operation */
		ret = bytes_to_write;
	}

	/* Update file position */
	*pos += bytes_to_write;

	/* Update inode metadata */
	inode->i_blocks = 0; /* Small files don't count blocks in traditional sense */
	inode->i_mtime = inode->i_ctime = current_time(inode);
	mark_inode_dirty(inode);

	pr_debug("Write completed: wrote %zd bytes, new file size=%lld, pos=%lld\n", 
		 ret, (long long)inode->i_size, *pos);

cleanup:
	kfree(kbuf);
	return ret;
}

/*
static ssize_t ouichefs_write(struct file *file, const char __user *buf, size_t len, loff_t *pos)
{
	struct inode *inode = file->f_inode;
	struct super_block *sb = inode->i_sb;
	struct ouichefs_sb_info *sbi = OUICHEFS_SB(sb);
	struct ouichefs_inode_info *ci = OUICHEFS_INODE(inode);
	struct ouichefs_file_index_block *index;
	struct buffer_head *bh_index, *bh_data;
	size_t total_written = 0;

	if (*pos >= OUICHEFS_MAX_FILESIZE)
		return -ENOSPC;

	// Copy data from user
	char *kbuf = kmalloc(len, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	if (copy_from_user(kbuf, buf, len)) {
		kfree(kbuf);
		return -EFAULT;
	}
	pr_info("WRITE: len=%zu, data: %.6s\n", len, kbuf);


	bh_index = sb_bread(sb, ci->index_block);
	if (!bh_index)
		return -EIO;
	index = (struct ouichefs_file_index_block *)bh_index->b_data;

	while (total_written < len) {
		sector_t iblock = *pos / OUICHEFS_BLOCK_SIZE;
		unsigned long block_offset = *pos % OUICHEFS_BLOCK_SIZE;
		unsigned long left_in_block = OUICHEFS_BLOCK_SIZE - block_offset;
		unsigned long bytes_left = len - total_written;
		unsigned long to_copy = min(left_in_block, bytes_left);

		// Wenn der offset größer als das File ist, breche ab
		if (iblock >= OUICHEFS_BLOCK_SIZE >> 2) {
			brelse(bh_index);
			return -EFBIG;
		}

		uint32_t bno = le32_to_cpu(index->blocks[iblock]);
		// Wenn der Block für das File nicht existiert
		// (d.h. wir hinter EOF), dann wollen wir den neuen Block allozieren
		// und die Leertasten die dazwischen entstehen (zwischen EOF und dem neuen Text)
		// einfügen.
		if (bno == 0) {
			bno = get_free_block(sbi);
			if (!bno) {
				brelse(bh_index);
				return -ENOSPC;
			}
			index->blocks[iblock] = cpu_to_le32(bno);
			struct buffer_head *bh_new = sb_bread(sb, bno);
			if (!bh_new) {
				brelse(bh_index);
				return -EIO;
			}
			memset(bh_new->b_data, 0, OUICHEFS_BLOCK_SIZE);
			mark_buffer_dirty(bh_new);
			sync_dirty_buffer(bh_new);
			brelse(bh_new);

			mark_buffer_dirty(bh_index);
		}

		// Wenn die Block Nummer existiert, holen wir uns den Block und
		// schreiben da rein
		bh_data = sb_bread(sb, bno);
		if (!bh_data)
			break;

		memcpy(bh_data->b_data + block_offset, kbuf + total_written, to_copy);

		mark_buffer_dirty(bh_data);
		sync_dirty_buffer(bh_data);
		brelse(bh_data);

		*pos += to_copy;
		total_written += to_copy;

		if (*pos >= OUICHEFS_MAX_FILESIZE)
			break;
	}

	brelse(bh_index);

	// Aktualisiere EOF
	if (*pos > inode->i_size)
		inode->i_size = *pos;



	// AB HIER NOCH SCHAUEN, DER REST SOLLTE EIGENTLICH STIMMEN!!!!!
	uint32_t nr_blocks_old = inode->i_blocks;

	// Update inode metadata
	inode->i_blocks = roundup(inode->i_size, OUICHEFS_BLOCK_SIZE) / OUICHEFS_BLOCK_SIZE;
	inode->i_mtime = inode->i_ctime = current_time(inode);
	mark_inode_dirty(inode);

	// If file is smaller than before, free unused blocks
	if (nr_blocks_old > inode->i_blocks) {
		int i;
		struct buffer_head *bh_index;
		struct ouichefs_file_index_block *index;

		// Free unused blocks from page cache 
		truncate_pagecache(inode, inode->i_size);

		// Read index block to remove unused blocks
		bh_index = sb_bread(sb, ci->index_block);
		if (!bh_index) {
			pr_err("failed truncating '%s'. we just lost %llu blocks\n",
					file->f_path.dentry->d_name.name,
					nr_blocks_old - inode->i_blocks);
			goto end;
		}
		index = (struct ouichefs_file_index_block *)
				bh_index->b_data;

		for (i = inode->i_blocks - 1; i < nr_blocks_old - 1; i++) {
			put_block(OUICHEFS_SB(sb), le32_to_cpu(index->blocks[i]));
			index->blocks[i] = 0;
		}
		mark_buffer_dirty(bh_index);
		brelse(bh_index);
	}

	end:
		kfree(kbuf);
		return total_written;
}
*/

/* IOCTL implementation */

#include "ouichefs_ioctl.h"

/**
 * Format a slice for display - converts non-printable characters to '.'
 */
/*static void format_slice_for_display(const char *slice_data, char *output, size_t size)
{
	size_t i;
	for (i = 0; i < size && i < OUICHEFS_SLICE_SIZE; i++) {
		char c = slice_data[i];
		// Convert non-printable characters to '.' for better readability
		if (c >= 32 && c <= 126) {
			output[i] = c;
		} else if (c == 0) {
			output[i] = '0'; // Show null bytes as '0'
		} else {
			output[i] = '.'; // Show other non-printable as '.'
		}
	}
	// Null terminate
	if (i < OUICHEFS_SLICE_SIZE) {
		output[i] = '\0';
	} else {
		output[OUICHEFS_SLICE_SIZE - 1] = '\0';
	}
}*/

/**
 * Display the metadata slice in a readable format
 */
static void display_metadata_slice(const struct ouichefs_sliced_block_meta *meta, 
				   char *output, size_t output_size)
{
	uint32_t bitmap = le32_to_cpu(meta->slice_bitmap);
	uint32_t next_block = le32_to_cpu(meta->next_block);
	uint32_t magic = le32_to_cpu(meta->magic);
	
	snprintf(output, output_size,
		"[META] Magic:0x%08X Bitmap:0x%08X Next:%u Free_slices:",
		magic, bitmap, next_block);
	
	/* Add free slice numbers to the output */
	char slice_info[64] = "";
	int info_pos = 0;
	int i;
	
	for (i = 1; i < OUICHEFS_SLICES_PER_BLOCK && info_pos < 50; i++) {
		if (bitmap & (1U << i)) {
			info_pos += snprintf(slice_info + info_pos, 
					     sizeof(slice_info) - info_pos, "%d,", i);
		}
	}
	
	/* Remove trailing comma */
	if (info_pos > 0 && slice_info[info_pos - 1] == ',') {
		slice_info[info_pos - 1] = '\0';
	}
	
	strncat(output, slice_info, output_size - strlen(output) - 1);
}

/**
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
	if (inode->i_size > 128) {
		pr_err("IOCTL: File size (%lld) exceeds slice storage limit (128 bytes)\n", 
		       inode->i_size);
		return -EINVAL;
	}

	/* Check if file has slice allocation */
	if (ci->index_block == 0) {
		pr_err("IOCTL: File has no slice allocated\n");
		return -ENODATA;
	}

	/* Extract slice information */
	block_num = ouichefs_get_slice_block(ci->index_block);
	slice_num = ouichefs_get_slice_number(ci->index_block);

	/* Validate slice information */
	if (block_num == 0 || slice_num == 0 || slice_num >= OUICHEFS_SLICES_PER_BLOCK) {
		pr_err("IOCTL: Invalid slice info - block:%u slice:%u\n", block_num, slice_num);
		return -EINVAL;
	}

	/* Allocate memory for display data */
	display_data = kmalloc(sizeof(struct ouichefs_block_display), GFP_KERNEL);
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
	if (copy_to_user(user_data, display_data, sizeof(struct ouichefs_block_display))) {
		ret = -EFAULT;
		goto free_display_data;
	}

	/* Print debug information to kernel log */
	pr_info("IOCTL: Block %u content displayed for file (inode %lu, size %lld)\n", 
		block_num, inode->i_ino, inode->i_size);
	
	pr_info("IOCTL: File uses slice %u in block %u\n", slice_num, block_num);

	/* Verify and display metadata */
	meta = (struct ouichefs_sliced_block_meta *)display_data->slices[0];
	if (le32_to_cpu(meta->magic) == OUICHEFS_SLICED_MAGIC) {
		char meta_display[128];
		display_metadata_slice(meta, meta_display, sizeof(meta_display));
		pr_info("IOCTL: %s\n", meta_display);
	} else {
		pr_warn("IOCTL: Block metadata has invalid magic number: 0x%08X\n", 
			le32_to_cpu(meta->magic));
	}

free_display_data:
	kfree(display_data);
	return ret;
}

/**
 * IOCTL dispatcher
 */
static long ouichefs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case OUICHEFS_IOC_DISPLAY_BLOCK:
		return ouichefs_display_block_ioctl(file, arg);
	default:
		return -ENOTTY; /* Not a valid ioctl command */
	}
}

/**
 * Compatibility IOCTL for 32-bit applications on 64-bit systems
 */
#ifdef CONFIG_COMPAT
static long ouichefs_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return ouichefs_ioctl(file, cmd, arg);
}
#endif

const struct file_operations ouichefs_file_ops = {
	.owner = THIS_MODULE,
	.open = ouichefs_open,
	.llseek = generic_file_llseek,
	.read = ouichefs_read,
	.write = ouichefs_write,
	.unlocked_ioctl = ouichefs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = ouichefs_compat_ioctl,
#endif
	// legacy functions -> remove later
	.read_iter = generic_file_read_iter,
	.write_iter = generic_file_write_iter,
	.fsync = generic_file_fsync,
};
