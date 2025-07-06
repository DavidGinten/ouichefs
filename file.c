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

	/* If block number exceeds filesize, fail */
	if (iblock >= OUICHEFS_BLOCK_SIZE >> 2)
		return -EFBIG;

	/* Read index block from disk */
	bh_index = sb_bread(sb, ci->index_block);
	if (!bh_index)
		return -EIO;
	index = (struct ouichefs_file_index_block *)bh_index->b_data;

	/*
	 * Check if iblock is already allocated. If not and create is true,
	 * allocate it. Else, get the physical block number.
	 */

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
	/* Map the physical block to the given buffer_head */
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

static ssize_t ouichefs_write(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct ouichefs_sb_info *sbi = OUICHEFS_SB(sb);
	struct ouichefs_inode_info *ci = OUICHEFS_INODE(inode);
	struct ouichefs_file_index_block *index;
	struct buffer_head *bh_index, *bh_data;
	ssize_t copied = 0;
	loff_t offset = iocb->ki_pos;
	size_t count = iov_iter_count(from);
	unsigned int block_size = sb->s_blocksize;
	
	/* Check if the write can be completed (enough space?) */
	if (offset + count > OUICHEFS_MAX_FILESIZE)
		return -ENOSPC;

	bh_index = sb_bread(sb, ci->index_block);
	if (!bh_index)
		return -EIO;
	index = (struct ouichefs_file_index_block *)bh_index->b_data;

	while (count > 0) {
		sector_t iblock = offset / block_size;
		size_t block_off = offset % block_size;
		size_t left_in_block = block_size - block_off;
		size_t to_copy = min_t(size_t, left_in_block, count);

		if (iblock >= OUICHEFS_BLOCK_SIZE >> 2) {
			brelse(bh_index);
			return -EFBIG;
		}

		uint32_t bno = le32_to_cpu(index->blocks[iblock]);
		if (bno == 0) {
			bno = get_free_block(sbi);
			if (!bno) {
				brelse(bh_index);
				return -ENOSPC;
			}
			index->blocks[iblock] = cpu_to_le32(bno);
			mark_buffer_dirty(bh_index);
		}

		bh_data = sb_bread(sb, bno);
		if (!bh_data)
			break;

		if (copy_from_iter(bh_data->b_data + block_off, to_copy, from) != to_copy) {
			brelse(bh_data);
			break;
		}

		mark_buffer_dirty(bh_data);
		sync_dirty_buffer(bh_data);
		brelse(bh_data);

		offset += to_copy;
		count -= to_copy;
		copied += to_copy;
	}

	brelse(bh_index);
	iocb->ki_pos = offset;

	if (offset > inode->i_size)
		inode->i_size = offset;

	inode->i_mtime = inode->i_ctime = current_time(inode);
	inode->i_blocks = (roundup(inode->i_size, block_size) / block_size) + 1;
	mark_inode_dirty(inode);

	return copied;
}

const struct address_space_operations ouichefs_aops = {
	.readahead = ouichefs_readahead,
	.writepage = ouichefs_writepage,
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

const struct file_operations ouichefs_file_ops = {
	.owner = THIS_MODULE,
	.open = ouichefs_open,
	.llseek = generic_file_llseek,
	.read_iter = generic_file_read_iter,
	.write_iter = ouichefs_write,
	.fsync = generic_file_fsync,
};
