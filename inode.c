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
#include <linux/slab.h>

#include "ouichefs.h"
#include "bitmap.h"
#include "ouichefs_sliced.h"

static const struct inode_operations ouichefs_inode_ops;

/*
 * Get inode ino from disk.
 */
struct inode *ouichefs_iget(struct super_block *sb, unsigned long ino)
{
	struct inode *inode = NULL;
	struct ouichefs_inode *cinode = NULL;
	struct ouichefs_inode_info *ci = NULL;
	struct ouichefs_sb_info *sbi = OUICHEFS_SB(sb);
	struct buffer_head *bh = NULL;
	uint32_t inode_block = (ino / OUICHEFS_INODES_PER_BLOCK) + 1;
	uint32_t inode_shift = ino % OUICHEFS_INODES_PER_BLOCK;
	int ret;

	/* Fail if ino is out of range */
	if (ino >= sbi->nr_inodes)
		return ERR_PTR(-EINVAL);

	/* Get a locked inode from Linux */
	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	/* If inode is in cache, return it */
	if (!(inode->i_state & I_NEW))
		return inode;

	ci = OUICHEFS_INODE(inode);
	/* Read inode from disk and initialize */
	bh = sb_bread(sb, inode_block);
	if (!bh) {
		ret = -EIO;
		goto failed;
	}
	cinode = (struct ouichefs_inode *)bh->b_data;
	cinode += inode_shift;

	inode->i_ino = ino;
	inode->i_sb = sb;
	inode->i_op = &ouichefs_inode_ops;

	inode->i_mode = le32_to_cpu(cinode->i_mode);
	i_uid_write(inode, le32_to_cpu(cinode->i_uid));
	i_gid_write(inode, le32_to_cpu(cinode->i_gid));
	inode->i_size = le32_to_cpu(cinode->i_size);
	inode->i_ctime.tv_sec = (time64_t)le32_to_cpu(cinode->i_ctime);
	inode->i_ctime.tv_nsec = (long)le64_to_cpu(cinode->i_nctime);
	inode->i_atime.tv_sec = (time64_t)le32_to_cpu(cinode->i_atime);
	inode->i_atime.tv_nsec = (long)le64_to_cpu(cinode->i_natime);
	inode->i_mtime.tv_sec = (time64_t)le32_to_cpu(cinode->i_mtime);
	inode->i_mtime.tv_nsec = (long)le64_to_cpu(cinode->i_nmtime);
	inode->i_blocks = le32_to_cpu(cinode->i_blocks);
	set_nlink(inode, le32_to_cpu(cinode->i_nlink));

	ci->index_block = le32_to_cpu(cinode->index_block);

	if (S_ISDIR(inode->i_mode)) {
		inode->i_fop = &ouichefs_dir_ops;
	} else if (S_ISREG(inode->i_mode)) {
		inode->i_fop = &ouichefs_file_ops;
		inode->i_mapping->a_ops = &ouichefs_aops;
	}

	brelse(bh);

	/* Unlock the inode to make it usable */
	unlock_new_inode(inode);

	return inode;

failed:
	brelse(bh);
	iget_failed(inode);
	return ERR_PTR(ret);
}

/*
 * Look for dentry in dir.
 * Fill dentry with NULL if not in dir, with the corresponding inode if found.
 * Returns NULL on success.
 */
static struct dentry *ouichefs_lookup(struct inode *dir, struct dentry *dentry,
				      unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	struct ouichefs_inode_info *ci_dir = OUICHEFS_INODE(dir);
	struct inode *inode = NULL;
	struct buffer_head *bh = NULL;
	struct ouichefs_dir_block *dblock = NULL;
	struct ouichefs_file *f = NULL;
	int i;

	/* Check filename length */
	if (dentry->d_name.len > OUICHEFS_FILENAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	/* Read the directory index block on disk */
	bh = sb_bread(sb, ci_dir->index_block);
	if (!bh)
		return ERR_PTR(-EIO);
	dblock = (struct ouichefs_dir_block *)bh->b_data;

	/* Search for the file in directory */
	for (i = 0; i < OUICHEFS_MAX_SUBFILES; i++) {
		f = &dblock->files[i];
		if (!f->inode)
			break;
		if (!strncmp(f->filename, dentry->d_name.name,
			     OUICHEFS_FILENAME_LEN)) {
			inode = ouichefs_iget(sb, le32_to_cpu(f->inode));
			break;
		}
	}
	brelse(bh);

	/* Fill the dentry with the inode */
	d_add(dentry, inode);

	return NULL;
}

/*
 * Create a new inode in dir.
 * FIXED: Don't allocate index blocks for small files initially (Task 1.4)
 */
static struct inode *ouichefs_new_inode(struct inode *dir, mode_t mode)
{
	struct inode *inode;
	struct ouichefs_inode_info *ci;
	struct super_block *sb;
	struct ouichefs_sb_info *sbi;
	uint32_t ino, bno;
	int ret;

	/* Check mode before doing anything to avoid undoing everything */
	if (!S_ISDIR(mode) && !S_ISREG(mode)) {
		pr_err("File type not supported (only directory and regular files supported)\n");
		return ERR_PTR(-EINVAL);
	}

	/* Check if inodes are available */
	sb = dir->i_sb;
	sbi = OUICHEFS_SB(sb);
	if (sbi->nr_free_inodes == 0)
		return ERR_PTR(-ENOSPC);

	/* For directories, we always need an index block */
	/* For regular files, we'll allocate blocks later when we know the file size */
	if (S_ISDIR(mode) && sbi->nr_free_blocks == 0)
		return ERR_PTR(-ENOSPC);

	/* Get a new free inode */
	ino = get_free_inode(sbi);
	if (!ino)
		return ERR_PTR(-ENOSPC);
	inode = ouichefs_iget(sb, ino);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto put_ino;
	}
	ci = OUICHEFS_INODE(inode);

	/* Only allocate index block for directories */
	if (S_ISDIR(mode)) {
		/* Get a free block for this new directory's index */
		bno = get_free_block(sbi);
		if (!bno) {
			ret = -ENOSPC;
			goto put_inode;
		}
		ci->index_block = bno;
		inode->i_blocks = 1;
	} else {
		/* Regular files start with no blocks allocated */
		/* Blocks will be allocated when data is written */
		ci->index_block = 0;
		inode->i_blocks = 0;
	}

	/* Initialize inode */
	inode_init_owner(&nop_mnt_idmap, inode, dir, mode);
	
	if (S_ISDIR(mode)) {
		inode->i_size = OUICHEFS_BLOCK_SIZE;
		inode->i_fop = &ouichefs_dir_ops;
	} else if (S_ISREG(mode)) {
		inode->i_size = 0;  /* Empty file initially */
		inode->i_fop = &ouichefs_file_ops;
		inode->i_mapping->a_ops = &ouichefs_aops;
	}
	set_nlink(inode, 1);

	inode->i_ctime = inode->i_atime = inode->i_mtime = current_time(inode);

	/*pr_debug("Created new inode %u, mode=%o, blocks=%u, index_block=%u\n", 
		 ino, mode, inode->i_blocks, ci->index_block);*/

	return inode;

put_inode:
	iput(inode);
put_ino:
	put_inode(sbi, ino);

	return ERR_PTR(ret);
}

/*
 * Create a file or directory in this way:
 *   - check filename length and if the parent directory is not full
 *   - create the new inode (allocate inode and blocks only for directories)
 *   - cleanup index block of the new inode (only for directories)
 *   - add new file/directory in parent index
 * FIXED: Only initialize index blocks for directories (task 1.4)
 */
static int ouichefs_create(struct mnt_idmap *idmap, struct inode *dir,
			   struct dentry *dentry, umode_t mode, bool excl)
{
	struct super_block *sb;
	struct inode *inode;
	struct ouichefs_inode_info *ci_dir;
	struct ouichefs_dir_block *dblock;
	char *fblock;
	struct buffer_head *bh, *bh2;
	int ret = 0, i;

	/* Check filename length */
	if (strlen(dentry->d_name.name) > OUICHEFS_FILENAME_LEN)
		return -ENAMETOOLONG;

	/* Read parent directory index */
	ci_dir = OUICHEFS_INODE(dir);
	sb = dir->i_sb;
	bh = sb_bread(sb, ci_dir->index_block);
	if (!bh)
		return -EIO;
	dblock = (struct ouichefs_dir_block *)bh->b_data;

	/* Check if parent directory is full */
	if (dblock->files[OUICHEFS_MAX_SUBFILES - 1].inode != 0) {
		ret = -EMLINK;
		goto end;
	}

	/* Get a new free inode */
	inode = ouichefs_new_inode(dir, mode);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto end;
	}

	/*
	 * Only scrub index_block for directories
	 * Regular files will allocate blocks when data is written
	 */
	if (S_ISDIR(mode)) {
		bh2 = sb_bread(sb, OUICHEFS_INODE(inode)->index_block);
		if (!bh2) {
			ret = -EIO;
			goto iput;
		}
		fblock = (char *)bh2->b_data;
		memset(fblock, 0, OUICHEFS_BLOCK_SIZE);
		mark_buffer_dirty(bh2);
		brelse(bh2);
	}

	/* Find first free slot in parent index and register new inode */
	for (i = 0; i < OUICHEFS_MAX_SUBFILES; i++)
		if (dblock->files[i].inode == 0)
			break;
	dblock->files[i].inode = cpu_to_le32(inode->i_ino);
	strscpy(dblock->files[i].filename, dentry->d_name.name,
		OUICHEFS_FILENAME_LEN);
	mark_buffer_dirty(bh);
	brelse(bh);

	/* Update stats and mark dir and new inode dirty */
	mark_inode_dirty(inode);
	dir->i_mtime = dir->i_ctime = current_time(dir);
	if (S_ISDIR(mode))
		inode_inc_link_count(dir);
	mark_inode_dirty(dir);

	/* setup dentry */
	d_instantiate(dentry, inode);

	/*pr_debug("Created %s: inode %lu, blocks=%u\n", 
		 S_ISDIR(mode) ? "directory" : "file", 
		 inode->i_ino, inode->i_blocks);*/

	return 0;

iput:
	/* Only put block if it was allocated (directories only) */
	if (S_ISDIR(mode) && OUICHEFS_INODE(inode)->index_block != 0)
		put_block(OUICHEFS_SB(sb), OUICHEFS_INODE(inode)->index_block);
	put_inode(OUICHEFS_SB(sb), inode->i_ino);
	iput(inode);
end:
	brelse(bh);
	return ret;
}

/*
 * Remove a link for a file. If link count is 0, destroy file in this way:
 *   - remove the file from its parent directory.
 *   - cleanup blocks containing data (different for small vs large files)
 *   - cleanup file index block (only for large files)
 *   - cleanup inode
 * UPDATED: Handle small files using slices and large files using index blocks
 */
static int ouichefs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct super_block *sb = dir->i_sb;
	struct ouichefs_sb_info *sbi = OUICHEFS_SB(sb);
	struct inode *inode = d_inode(dentry);
	struct ouichefs_inode_info *ci = OUICHEFS_INODE(inode);
	struct buffer_head *bh = NULL, *bh2 = NULL;
	struct ouichefs_dir_block *dir_block = NULL;
	struct ouichefs_file_index_block *file_block = NULL;
	uint32_t ino, bno;
	int i, f_id = -1, nr_subs = 0;
	bool is_small_file;

	ino = inode->i_ino;
	is_small_file = (inode->i_size <= 128 && inode->i_size > 0);

	pr_debug("Unlinking %s file: inode %u, size %lld\n", 
		 is_small_file ? "small" : "large", ino, inode->i_size);

	/* Read parent directory index */
	bh = sb_bread(sb, OUICHEFS_INODE(dir)->index_block);
	if (!bh)
		return -EIO;
	dir_block = (struct ouichefs_dir_block *)bh->b_data;

	/* Search for inode in parent index and get number of subfiles */
	for (i = 0; i < OUICHEFS_MAX_SUBFILES; i++) {
		if (le32_to_cpu(dir_block->files[i].inode) == ino)
			f_id = i;
		else if (dir_block->files[i].inode == 0)
			break;
	}
	nr_subs = i;

	/* Remove file from parent directory */
	if (f_id != OUICHEFS_MAX_SUBFILES - 1)
		memmove(dir_block->files + f_id, dir_block->files + f_id + 1,
			(nr_subs - f_id - 1) * sizeof(struct ouichefs_file));
	memset(&dir_block->files[nr_subs - 1], 0, sizeof(struct ouichefs_file));
	mark_buffer_dirty(bh);
	brelse(bh);

	/* Update parent directory stats */
	dir->i_mtime = dir->i_ctime = current_time(dir);
	if (S_ISDIR(inode->i_mode))
		inode_dec_link_count(dir);
	mark_inode_dirty(dir);

	/*
	 * Handle data cleanup based on file type
	 */
	if (is_small_file) {
		/* Small file - release slice */
		if (ci->index_block != 0) {
			uint32_t block_num = ouichefs_get_slice_block(ci->index_block);
			uint32_t slice_num = ouichefs_get_slice_number(ci->index_block);

			pr_debug("Releasing slice %u in block %u for small file\n", 
				 slice_num, block_num);

			/* Validate slice information */
			if (block_num != 0 && slice_num != 0 && slice_num < OUICHEFS_SLICES_PER_BLOCK) {
				ouichefs_free_slice(sb, block_num, slice_num);
			} else {
				pr_warn("Invalid slice info during unlink: block=%u, slice=%u\n", 
					block_num, slice_num);
			}
		}
	} else if (inode->i_size > 128) {
		/* Large file - cleanup pointed blocks */
		bno = ci->index_block;
		if (bno == 0) {
			pr_warn("Large file has no index block\n");
			goto clean_inode;
		}

		bh = sb_bread(sb, bno);
		if (!bh) {
			pr_err("Failed to read index block %u, losing file blocks\n", bno);
			goto clean_inode;
		}
		
		file_block = (struct ouichefs_file_index_block *)bh->b_data;

		/* Free all data blocks */
		for (i = 0; i < inode->i_blocks - 1; i++) {
			if (!file_block->blocks[i])
				continue;

			uint32_t data_block = le32_to_cpu(file_block->blocks[i]);
			
			/* Scrub the data block */
			bh2 = sb_bread(sb, data_block);
			if (bh2) {
				memset(bh2->b_data, 0, OUICHEFS_BLOCK_SIZE);
				mark_buffer_dirty(bh2);
				brelse(bh2);
			}

			/* Release the block */
			put_block(sbi, data_block);
			pr_debug("Released data block %u\n", data_block);
		}

		/* Scrub and release index block */
		memset(file_block, 0, OUICHEFS_BLOCK_SIZE);
		mark_buffer_dirty(bh);
		sync_dirty_buffer(bh);
		brelse(bh);
		
		put_block(sbi, bno);
		pr_debug("Released index block %u\n", bno);
	} else {
		/* Empty file (size == 0) - no data blocks to clean */
		pr_debug("Empty file, no blocks to release\n");
	}

clean_inode:
	/* Cleanup inode and mark dirty */
	inode->i_blocks = 0;
	ci->index_block = 0;
	inode->i_size = 0;
	i_uid_write(inode, 0);
	i_gid_write(inode, 0);
	inode->i_mode = 0;
	inode->i_ctime.tv_sec = inode->i_mtime.tv_sec = inode->i_atime.tv_sec = 0;
	inode->i_ctime.tv_nsec = inode->i_mtime.tv_nsec = inode->i_atime.tv_nsec = 0;
	inode_dec_link_count(inode);  /* This sets nlink to 0 */
	
	pr_debug("After cleanup: inode %u, mode=%u, nlink=%u, size=%lld\n", 
		 ino, inode->i_mode, inode->i_nlink, inode->i_size);
	
	mark_inode_dirty(inode);

	/* CRITICAL: Force immediate write to disk */
	/* We need to manually write the inode to disk because mark_inode_dirty() 
	   only schedules the write for later, but sysfs reads from disk immediately */
	{
		struct ouichefs_inode *disk_inode;
		struct buffer_head *bh_inode;
		uint32_t inode_block_num = (ino / OUICHEFS_INODES_PER_BLOCK) + 1;
		uint32_t inode_offset = ino % OUICHEFS_INODES_PER_BLOCK;

		bh_inode = sb_bread(sb, inode_block_num);
		if (bh_inode) {
			disk_inode = (struct ouichefs_inode *)bh_inode->b_data + inode_offset;
			
			/* Manually update the on-disk inode */
			disk_inode->i_mode = cpu_to_le32(0);
			disk_inode->i_nlink = cpu_to_le32(0);
			disk_inode->i_size = cpu_to_le32(0);
			disk_inode->i_blocks = cpu_to_le32(0);
			disk_inode->index_block = cpu_to_le32(0);
			disk_inode->i_uid = cpu_to_le32(0);
			disk_inode->i_gid = cpu_to_le32(0);
			disk_inode->i_ctime = cpu_to_le32(0);
			disk_inode->i_atime = cpu_to_le32(0);
			disk_inode->i_mtime = cpu_to_le32(0);
			disk_inode->i_nctime = cpu_to_le64(0);
			disk_inode->i_natime = cpu_to_le64(0);
			disk_inode->i_nmtime = cpu_to_le64(0);
			
			mark_buffer_dirty(bh_inode);
			sync_dirty_buffer(bh_inode);  /* Force immediate write */
			brelse(bh_inode);
			
			pr_debug("Forced disk write for inode %u\n", ino);
		} else {
			pr_err("Failed to read inode block for manual cleanup\n");
		}
	}

	/* Free inode from bitmap */
	put_inode(sbi, ino);

	pr_debug("Unlink completed for inode %u\n", ino);
	return 0;
}

static int ouichefs_rename(struct mnt_idmap *idmap, struct inode *old_dir,
			   struct dentry *old_dentry, struct inode *new_dir,
			   struct dentry *new_dentry, unsigned int flags)
{
	struct super_block *sb = old_dir->i_sb;
	struct ouichefs_inode_info *ci_old = OUICHEFS_INODE(old_dir);
	struct ouichefs_inode_info *ci_new = OUICHEFS_INODE(new_dir);
	struct inode *src = d_inode(old_dentry);
	struct buffer_head *bh_old = NULL, *bh_new = NULL;
	struct ouichefs_dir_block *dir_block = NULL;
	int i, f_id = -1, new_pos = -1, ret, nr_subs, f_pos = -1;

	/* fail with these unsupported flags */
	if (flags & (RENAME_EXCHANGE | RENAME_WHITEOUT))
		return -EINVAL;

	/* Check if filename is not too long */
	if (strlen(new_dentry->d_name.name) > OUICHEFS_FILENAME_LEN)
		return -ENAMETOOLONG;

	/* Fail if new_dentry exists or if new_dir is full */
	bh_new = sb_bread(sb, ci_new->index_block);
	if (!bh_new)
		return -EIO;
	dir_block = (struct ouichefs_dir_block *)bh_new->b_data;
	for (i = 0; i < OUICHEFS_MAX_SUBFILES; i++) {
		/* if old_dir == new_dir, save the renamed file position */
		if (new_dir == old_dir) {
			if (strncmp(dir_block->files[i].filename,
				    old_dentry->d_name.name,
				    OUICHEFS_FILENAME_LEN) == 0)
				f_pos = i;
		}
		if (strncmp(dir_block->files[i].filename,
			    new_dentry->d_name.name,
			    OUICHEFS_FILENAME_LEN) == 0) {
			ret = -EEXIST;
			goto relse_new;
		}
		if (new_pos < 0 && dir_block->files[i].inode == 0)
			new_pos = i;
	}
	/* if old_dir == new_dir, just rename entry */
	if (old_dir == new_dir) {
		strscpy(dir_block->files[f_pos].filename,
			new_dentry->d_name.name, OUICHEFS_FILENAME_LEN);
		mark_buffer_dirty(bh_new);
		ret = 0;
		goto relse_new;
	}

	/* If new directory is empty, fail */
	if (new_pos < 0) {
		ret = -EMLINK;
		goto relse_new;
	}

	/* insert in new parent directory */
	dir_block->files[new_pos].inode = cpu_to_le32(src->i_ino);
	strscpy(dir_block->files[new_pos].filename, new_dentry->d_name.name,
		OUICHEFS_FILENAME_LEN);
	mark_buffer_dirty(bh_new);
	brelse(bh_new);

	/* Update new parent inode metadata */
	new_dir->i_atime = new_dir->i_ctime = new_dir->i_mtime =
		current_time(new_dir);
	if (S_ISDIR(src->i_mode))
		inode_inc_link_count(new_dir);
	mark_inode_dirty(new_dir);

	/* remove target from old parent directory */
	bh_old = sb_bread(sb, ci_old->index_block);
	if (!bh_old)
		return -EIO;
	dir_block = (struct ouichefs_dir_block *)bh_old->b_data;
	/* Search for inode in old directory and number of subfiles */
	for (i = 0; OUICHEFS_MAX_SUBFILES; i++) {
		if (le32_to_cpu(dir_block->files[i].inode) == src->i_ino)
			f_id = i;
		else if (dir_block->files[i].inode == 0)
			break;
	}
	nr_subs = i;

	/* Remove file from old parent directory */
	if (f_id != OUICHEFS_MAX_SUBFILES - 1)
		memmove(dir_block->files + f_id, dir_block->files + f_id + 1,
			(nr_subs - f_id - 1) * sizeof(struct ouichefs_file));
	memset(&dir_block->files[nr_subs - 1], 0, sizeof(struct ouichefs_file));
	mark_buffer_dirty(bh_old);
	brelse(bh_old);

	/* Update old parent inode metadata */
	old_dir->i_ctime = old_dir->i_mtime = current_time(old_dir);
	if (S_ISDIR(src->i_mode))
		inode_dec_link_count(old_dir);
	mark_inode_dirty(old_dir);

	return 0;

relse_new:
	brelse(bh_new);
	return ret;
}

static int ouichefs_mkdir(struct mnt_idmap *idmap, struct inode *dir,
			  struct dentry *dentry, umode_t mode)
{
	return ouichefs_create(NULL, dir, dentry, mode | S_IFDIR, 0);
}

static int ouichefs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode = d_inode(dentry);
	struct buffer_head *bh;
	struct ouichefs_dir_block *dblock;

	/* If the directory is not empty, fail */
	if (inode->i_nlink > 2)
		return -ENOTEMPTY;
	bh = sb_bread(sb, OUICHEFS_INODE(inode)->index_block);
	if (!bh)
		return -EIO;
	dblock = (struct ouichefs_dir_block *)bh->b_data;
	if (dblock->files[0].inode != 0) {
		brelse(bh);
		return -ENOTEMPTY;
	}
	brelse(bh);

	/* Remove directory with unlink */
	return ouichefs_unlink(dir, dentry);
}

static const struct inode_operations ouichefs_inode_ops = {
	.lookup = ouichefs_lookup,
	.create = ouichefs_create,
	.unlink = ouichefs_unlink,
	.mkdir = ouichefs_mkdir,
	.rmdir = ouichefs_rmdir,
	.rename = ouichefs_rename,
};
