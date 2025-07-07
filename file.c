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

	if ((wronly || rdwr) && trunc && (inode->i_size != 0)) {
		struct super_block *sb = inode->i_sb;
		struct ouichefs_sb_info *sbi = OUICHEFS_SB(sb);
		struct ouichefs_inode_info *ci = OUICHEFS_INODE(inode);
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

	/* Update inode metadata */
	inode->i_blocks = roundup(inode->i_size, OUICHEFS_BLOCK_SIZE) / OUICHEFS_BLOCK_SIZE;
	inode->i_mtime = inode->i_ctime = current_time(inode);
	mark_inode_dirty(inode);

	/* If file is smaller than before, free unused blocks */
	if (nr_blocks_old > inode->i_blocks) {
		int i;
		struct buffer_head *bh_index;
		struct ouichefs_file_index_block *index;

		/* Free unused blocks from page cache */
		truncate_pagecache(inode, inode->i_size);

		/* Read index block to remove unused blocks */
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

const struct file_operations ouichefs_file_ops = {
	.owner = THIS_MODULE,
	.open = ouichefs_open,
	.llseek = generic_file_llseek,
	.read = ouichefs_read,
	.write = ouichefs_write,
	// legacy functions -> remove later
	.read_iter = generic_file_read_iter,
	.write_iter = generic_file_write_iter,
	.fsync = generic_file_fsync,
};
