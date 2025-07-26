// SPDX-License-Identifier: GPL-2.0
/*
 * ouiche_fs - SysFS interface for filesystem monitoring
 *
 * Copyright (C) 2018 Redha Gouicem <redha.gouicem@lip6.fr>
 */

#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/buffer_head.h>
#include <linux/hashtable.h>
#include <linux/writeback.h>

#include "ouichefs.h"
#include "ouichefs_sliced.h"
#include "bitmap.h"

/* Global variables for sysfs */
static struct kobject *ouichefs_kobj;
//static struct kobject *partition_kobj;

/* Statistics structure */
struct ouichefs_stats {
	uint32_t total_blocks;
	uint32_t total_inodes;
 	uint32_t inode_store_blocks;
	uint32_t inode_free_bitmap_blocks;
	uint32_t block_free_bitmap_blocks;
	uint32_t free_inodes;
	uint32_t free_blocks;
	uint32_t used_blocks;
	uint32_t sliced_blocks;
	uint32_t total_free_slices;
	uint32_t files;
	uint32_t small_files;
	uint64_t total_data_size;
	uint64_t total_used_size;
	uint32_t efficiency;
};

/* Forward declarations */
static int ouichefs_collect_stats(struct super_block *sb, struct ouichefs_stats *stats);
static struct super_block *ouichefs_get_sb_from_kobj(struct kobject *kobj);

/* SysFS show functions */
static ssize_t other_stats_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct super_block *sb = ouichefs_get_sb_from_kobj(kobj);
	struct ouichefs_stats stats;
	int ret;

	if (!sb)
		return -ENODEV;

	ret = ouichefs_collect_stats(sb, &stats);
	if (ret)
		return ret;

	return sprintf(buf, "Total Blocks: %u\n"
						"Total Inodes: %u\n"
						"Nr_istore_blocks: %u\n"
						"Nr_ifree_blocks: %u\n"
						"Nr_bfree_blocks: %u\n" 
						"Nr_free_inodes: %u\n",
						stats.total_blocks, stats.total_inodes,
						stats.inode_store_blocks, stats.inode_free_bitmap_blocks,
						stats.block_free_bitmap_blocks, stats.free_inodes);
}

/* SysFS show functions */
static ssize_t free_blocks_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct super_block *sb = ouichefs_get_sb_from_kobj(kobj);
	struct ouichefs_stats stats;
	int ret;

	if (!sb)
		return -ENODEV;

	ret = ouichefs_collect_stats(sb, &stats);
	if (ret)
		return ret;

	return sprintf(buf, "%u\n", stats.free_blocks);
}

static ssize_t used_blocks_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct super_block *sb = ouichefs_get_sb_from_kobj(kobj);
	struct ouichefs_stats stats;
	int ret;

	if (!sb)
		return -ENODEV;

	ret = ouichefs_collect_stats(sb, &stats);
	if (ret)
		return ret;

	return sprintf(buf, "%u\n", stats.used_blocks);
}

static ssize_t sliced_blocks_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct super_block *sb = ouichefs_get_sb_from_kobj(kobj);
	struct ouichefs_stats stats;
	int ret;

	if (!sb)
		return -ENODEV;

	ret = ouichefs_collect_stats(sb, &stats);
	if (ret)
		return ret;

	return sprintf(buf, "%u\n", stats.sliced_blocks);
}

static ssize_t total_free_slices_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct super_block *sb = ouichefs_get_sb_from_kobj(kobj);
	struct ouichefs_stats stats;
	int ret;

	if (!sb)
		return -ENODEV;

	ret = ouichefs_collect_stats(sb, &stats);
	if (ret)
		return ret;

	return sprintf(buf, "%u\n", stats.total_free_slices);
}

static ssize_t files_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct super_block *sb = ouichefs_get_sb_from_kobj(kobj);
	struct ouichefs_stats stats;
	int ret;

	if (!sb)
		return -ENODEV;

	ret = ouichefs_collect_stats(sb, &stats);
	if (ret)
		return ret;

	return sprintf(buf, "%u\n", stats.files);
}

static ssize_t small_files_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct super_block *sb = ouichefs_get_sb_from_kobj(kobj);
	struct ouichefs_stats stats;
	int ret;

	if (!sb)
		return -ENODEV;

	ret = ouichefs_collect_stats(sb, &stats);
	if (ret)
		return ret;

	return sprintf(buf, "%u\n", stats.small_files);
}

static ssize_t total_data_size_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct super_block *sb = ouichefs_get_sb_from_kobj(kobj);
	struct ouichefs_stats stats;
	int ret;

	if (!sb)
		return -ENODEV;

	ret = ouichefs_collect_stats(sb, &stats);
	if (ret)
		return ret;

	return sprintf(buf, "%llu\n", stats.total_data_size);
}

static ssize_t total_used_size_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct super_block *sb = ouichefs_get_sb_from_kobj(kobj);
	struct ouichefs_stats stats;
	int ret;

	if (!sb)
		return -ENODEV;

	ret = ouichefs_collect_stats(sb, &stats);
	if (ret)
		return ret;

	return sprintf(buf, "%llu\n", stats.total_used_size);
}

static ssize_t efficiency_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct super_block *sb = ouichefs_get_sb_from_kobj(kobj);
	struct ouichefs_stats stats;
	int ret;

	if (!sb)
		return -ENODEV;

	ret = ouichefs_collect_stats(sb, &stats);
	if (ret)
		return ret;

	return sprintf(buf, "%u%%\n", stats.efficiency);
}

/* Define sysfs attributes */
static struct kobj_attribute other_stats_attr = __ATTR_RO(other_stats);
static struct kobj_attribute free_blocks_attr = __ATTR_RO(free_blocks);
static struct kobj_attribute used_blocks_attr = __ATTR_RO(used_blocks);
static struct kobj_attribute sliced_blocks_attr = __ATTR_RO(sliced_blocks);
static struct kobj_attribute total_free_slices_attr = __ATTR_RO(total_free_slices);
static struct kobj_attribute files_attr = __ATTR_RO(files);
static struct kobj_attribute small_files_attr = __ATTR_RO(small_files);
static struct kobj_attribute total_data_size_attr = __ATTR_RO(total_data_size);
static struct kobj_attribute total_used_size_attr = __ATTR_RO(total_used_size);
static struct kobj_attribute efficiency_attr = __ATTR_RO(efficiency);

/* Attribute array */
static struct attribute *ouichefs_attrs[] = {
	&other_stats_attr.attr,
	&free_blocks_attr.attr,
	&used_blocks_attr.attr,
	&sliced_blocks_attr.attr,
	&total_free_slices_attr.attr,
	&files_attr.attr,
	&small_files_attr.attr,
	&total_data_size_attr.attr,
	&total_used_size_attr.attr,
	&efficiency_attr.attr,
	NULL,
};

/* Attribute group */
static struct attribute_group ouichefs_attr_group = {
	.attrs = ouichefs_attrs,
};

/* Global superblock pointer for sysfs access */
//static struct super_block *g_sb;

// Instead of a single global sb, maintain a hash table of mounted filesystems
#define OUICHEFS_SYSFS_HASH_BITS 4  /* 16 buckets should be plenty */

struct ouichefs_sysfs_entry {
    struct super_block *sb;
    char device_name[32];
    struct kobject *kobj;        // Pointer, not embedded
    struct hlist_node hash_node;
};

static DEFINE_HASHTABLE(ouichefs_sysfs_hash, OUICHEFS_SYSFS_HASH_BITS);
static DEFINE_MUTEX(ouichefs_sysfs_mutex);

static inline u32 ouichefs_sb_hash(struct super_block *sb)
{
    /* Simple hash based on superblock pointer */
    return hash_ptr(sb, OUICHEFS_SYSFS_HASH_BITS);
}

static struct super_block *ouichefs_get_sb_from_kobj(struct kobject *kobj)
{
    struct ouichefs_sysfs_entry *entry;
    u32 hash;
    
    // Find the entry that owns this kobject
    mutex_lock(&ouichefs_sysfs_mutex);
    hash_for_each(ouichefs_sysfs_hash, hash, entry, hash_node) {
        if (entry->kobj == kobj) {
            mutex_unlock(&ouichefs_sysfs_mutex);
            return entry->sb;
        }
    }
    mutex_unlock(&ouichefs_sysfs_mutex);
    return NULL;
}
/*
void ouichefs_sysfs_set_sb(struct super_block *sb)
{
	g_sb = sb;
}*/
/*
void ouichefs_sysfs_clear_sb(void)
{
	g_sb = NULL;
}*/

/**
 * Count sliced blocks and free slices
 */
static int ouichefs_count_sliced_stats(struct super_block *sb, uint32_t *sliced_blocks, uint32_t *free_slices)
{
	struct ouichefs_sb_info *sbi = OUICHEFS_SB(sb);
	struct buffer_head *bh;
	struct ouichefs_sliced_block_meta *meta;
	uint32_t current_block;
	uint32_t total_sliced = 0;
	uint32_t total_free = 0;

	*sliced_blocks = 0;
	*free_slices = 0;

	/* Walk through the list of partially filled sliced blocks */
	current_block = sbi->s_free_sliced_blocks;

	while (current_block != 0) {
		bh = sb_bread(sb, current_block);
		if (!bh) {
			pr_err("Failed to read sliced block %u\n", current_block);
			break;
		}

		meta = (struct ouichefs_sliced_block_meta *)bh->b_data;

		/* Verify this is a sliced block */
		if (le32_to_cpu(meta->magic) == OUICHEFS_SLICED_MAGIC) {
			uint32_t bitmap = le32_to_cpu(meta->slice_bitmap);
			uint32_t free_in_block = 0;
			int i;

			total_sliced++;

			/* Count free slices in this block (bits set to 1) */
			for (i = 1; i < OUICHEFS_SLICES_PER_BLOCK; i++) {
				if (bitmap & (1U << i))
					free_in_block++;
			}

			total_free += free_in_block;
		}

		current_block = le32_to_cpu(meta->next_block);
		brelse(bh);
	}

	/* Also need to count fully occupied sliced blocks */
	/* This requires scanning all data blocks to find sliced blocks not in the free list */
	/* For now, we'll scan the block bitmap to identify sliced blocks */
	uint32_t data_start = 1 + sbi->nr_istore_blocks + sbi->nr_ifree_blocks + sbi->nr_bfree_blocks;
	uint32_t block_num;

	for (block_num = data_start; block_num < sbi->nr_blocks; block_num++) {
		/* Check if block is allocated */
		if (!test_bit(block_num, sbi->bfree_bitmap)) {
			/* Block is allocated, check if it's a sliced block */
			bh = sb_bread(sb, block_num);
			if (bh) {
				meta = (struct ouichefs_sliced_block_meta *)bh->b_data;
				if (le32_to_cpu(meta->magic) == OUICHEFS_SLICED_MAGIC) {
					uint32_t bitmap = le32_to_cpu(meta->slice_bitmap);

					/* If this block is not in the free list (bitmap == 0), count it */
					if (bitmap == 0) {
						total_sliced++;
					}
				}
				brelse(bh);
			}
		}
	}

	*sliced_blocks = total_sliced;
	*free_slices = total_free;
	return 0;
}

/**
 * Count files and collect size statistics by scanning all inodes
 * FIXED: Use nlink as the primary indicator of file deletion
 */
static int ouichefs_count_file_stats(struct super_block *sb, uint32_t *files, uint32_t *small_files, 
				     uint64_t *total_data_size)
{
	struct ouichefs_sb_info *sbi = OUICHEFS_SB(sb);
	struct buffer_head *bh;
	struct ouichefs_inode *inode;
	uint32_t total_files = 0;
	uint32_t total_small = 0;
	uint64_t total_size = 0;
	uint32_t inode_block, inode_shift;
	uint32_t i;

	/* Scan all inodes */
	for (i = 1; i < sbi->nr_inodes; i++) {  /* Start from 1, skip root */
		inode_block = (i / OUICHEFS_INODES_PER_BLOCK) + 1;
		inode_shift = i % OUICHEFS_INODES_PER_BLOCK;
		
		bh = sb_bread(sb, inode_block);
		if (!bh)
			continue;

		inode = (struct ouichefs_inode *)bh->b_data + inode_shift;
		
		/* 
		 * Check if inode is in use and is a regular file
		 * In Linux filesystems, nlink == 0 means the file is deleted
		 * We use nlink as the primary deletion indicator
		 */
		uint32_t mode = le32_to_cpu(inode->i_mode);
		uint32_t nlink = le32_to_cpu(inode->i_nlink);
		uint32_t size = le32_to_cpu(inode->i_size);
		
		/* Skip deleted/free inodes - nlink == 0 means deleted */
		if (nlink == 0) {
			pr_debug("Skipping deleted inode %u (nlink=0, mode=%u, size=%u)\n", 
				 i, mode, size);
			brelse(bh);
			continue;
		}
		
		/* Also skip if mode is 0 (completely uninitialized) */
		if (mode == 0) {
			pr_debug("Skipping uninitialized inode %u (mode=0, nlink=%u, size=%u)\n", 
				 i, nlink, size);
			brelse(bh);
			continue;
		}
		
		/* Only count regular files */
		if (S_ISREG(mode)) {
			total_files++;
			total_size += size;
			
			/* Check if it's a small file (using sliced blocks) */
			if (size > 0 && size <= 128) {
				total_small++;
				pr_debug("Found small file: inode %u, size %u bytes, nlink=%u\n", i, size, nlink);
			} else if (size > 128) {
				pr_debug("Found large file: inode %u, size %u bytes, nlink=%u\n", i, size, nlink);
			} else if (size == 0) {
				pr_debug("Found empty file: inode %u, nlink=%u\n", i, nlink);
				/* Empty files are counted as regular files but not as small files */
			}
		} else {
			pr_debug("Skipping non-regular file: inode %u, mode=0%o, nlink=%u\n", i, mode, nlink);
		}

		brelse(bh);
	}

	*files = total_files;
	*small_files = total_small;
	*total_data_size = total_size;
	
	pr_debug("File stats scan result: total=%u, small=%u, total_size=%llu\n", 
		 total_files, total_small, total_size);
	
	return 0;
}

/**
 * Collect all filesystem statistics
 */
static int ouichefs_collect_stats(struct super_block *sb, struct ouichefs_stats *stats)
{
	// Force any pending writes to complete
    //sync_inodes_sb(sb);

	struct ouichefs_sb_info *sbi = OUICHEFS_SB(sb);
	int ret;

	if (!sb || !sbi || !stats)
		return -EINVAL;

	memset(stats, 0, sizeof(*stats));

	/* Basic block statistics */
	stats->total_blocks = sbi->nr_blocks;
	stats->total_inodes = sbi->nr_inodes;
	stats->inode_store_blocks = sbi->nr_istore_blocks;
	stats->inode_free_bitmap_blocks = sbi->nr_ifree_blocks;
	stats->block_free_bitmap_blocks = sbi->nr_bfree_blocks;
	stats->free_inodes = sbi->nr_free_inodes;
	stats->free_blocks = sbi->nr_free_blocks;

	/* Calculate actual used blocks correctly */
	/* Used blocks = Total data blocks - Free blocks */
	uint32_t total_data_blocks = sbi->nr_blocks - 1 - sbi->nr_istore_blocks -
	                            sbi->nr_ifree_blocks - sbi->nr_bfree_blocks;
	stats->used_blocks = total_data_blocks - sbi->nr_free_blocks;

	//sync_inodes_sb(sb);

	/* Sliced block statistics */
	ret = ouichefs_count_sliced_stats(sb, &stats->sliced_blocks, &stats->total_free_slices);
	if (ret)
		return ret;

	//sync_inodes_sb(sb);

	/* File statistics */
	ret = ouichefs_count_file_stats(sb, &stats->files, &stats->small_files, &stats->total_data_size);
	if (ret)
		return ret;

	//sync_inodes_sb(sb);

	/* Calculate total used size */
	stats->total_used_size = (uint64_t)stats->used_blocks * OUICHEFS_BLOCK_SIZE;

	/* Calculate efficiency (percentage) */
	if (stats->total_used_size > 0) {
		stats->efficiency = (uint32_t)((stats->total_data_size * 100) / stats->total_used_size);
	} else {
		stats->efficiency = 0;
	}

	pr_debug("Stats: used_blocks=%u, sliced_blocks=%u, files=%u, small_files=%u\n",
		 stats->used_blocks, stats->sliced_blocks, stats->files, stats->small_files);

	return 0;
}

/**
 * Initialize sysfs interface
 */
int ouichefs_sysfs_init(void)
{
	/* Create /sys/fs/ouichefs */
	ouichefs_kobj = kobject_create_and_add("ouichefs", fs_kobj);
	if (!ouichefs_kobj) {
		pr_err("Failed to create ouichefs sysfs directory\n");
		return -ENOMEM;
	}

	pr_info("OuiChefs sysfs interface initialized\n");
	return 0;
}

/**
 * Create partition-specific sysfs directory
 */
int ouichefs_sysfs_create_partition(struct super_block *sb, const char *partition_name)
{
    struct ouichefs_sysfs_entry *entry;
    u32 hash;
    int ret;

    pr_info("Creating sysfs partition for %s\n", partition_name);

    if (!ouichefs_kobj) {
        pr_err("OuiChefs sysfs not initialized\n");
        return -EINVAL;
    }

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        pr_err("Failed to allocate sysfs entry\n");
        return -ENOMEM;
    }

    entry->sb = sb;
    strncpy(entry->device_name, partition_name, sizeof(entry->device_name) - 1);
    entry->device_name[sizeof(entry->device_name) - 1] = '\0';

    /* Create a simple subdirectory first */
    entry->kobj = kobject_create_and_add(partition_name, ouichefs_kobj);
    if (!entry->kobj) {
        pr_err("Failed to create kobject for %s\n", partition_name);
        kfree(entry);
        return -ENOMEM;
    }

    pr_info("Created kobject directory\n");

    /* Create sysfs attribute files */
    ret = sysfs_create_group(entry->kobj, &ouichefs_attr_group);
    if (ret) {
        pr_err("Failed to create sysfs attributes: %d\n", ret);
        kobject_put(entry->kobj);
        kfree(entry);
        return ret;
    }

    pr_info("Created sysfs attributes\n");

    /* Add to hash table */
    hash = ouichefs_sb_hash(sb);
    mutex_lock(&ouichefs_sysfs_mutex);
    hash_add(ouichefs_sysfs_hash, &entry->hash_node, hash);
    mutex_unlock(&ouichefs_sysfs_mutex);

    pr_info("Created sysfs interface for partition %s\n", partition_name);
    return 0;
}

/**
 * Remove partition-specific sysfs directory
 */
void ouichefs_sysfs_remove_partition(struct super_block *sb)
{
    struct ouichefs_sysfs_entry *entry;
    u32 hash = ouichefs_sb_hash(sb);

    mutex_lock(&ouichefs_sysfs_mutex);
    hash_for_each_possible(ouichefs_sysfs_hash, entry, hash_node, hash) {
        if (entry->sb == sb) {
            hash_del(&entry->hash_node);  // Remove from hash table FIRST
            mutex_unlock(&ouichefs_sysfs_mutex);
            
            sysfs_remove_group(entry->kobj, &ouichefs_attr_group);
            kobject_put(entry->kobj);
            pr_info("Removed sysfs interface for partition %s\n", entry->device_name);
            
            // FIX: Explicitly free the entry structure
            kfree(entry);
            return;
        }
    }
    mutex_unlock(&ouichefs_sysfs_mutex);
    
    pr_warn("Superblock not found in sysfs hash table\n");
}

/**
 * Cleanup sysfs interface
 */
void ouichefs_sysfs_exit(void)
{
    struct ouichefs_sysfs_entry *entry;
    struct hlist_node *tmp;
    int bkt;

    /* Clean up all remaining entries */
    mutex_lock(&ouichefs_sysfs_mutex);
    hash_for_each_safe(ouichefs_sysfs_hash, bkt, tmp, entry, hash_node) {
        hash_del(&entry->hash_node);
        sysfs_remove_group(entry->kobj, &ouichefs_attr_group);
        kobject_put(entry->kobj);
        pr_info("Cleaned up sysfs interface for partition %s\n", entry->device_name);
        
        // FIX: Explicitly free the entry structure
        kfree(entry);
    }
    mutex_unlock(&ouichefs_sysfs_mutex);

    if (ouichefs_kobj) {
        kobject_put(ouichefs_kobj);
        ouichefs_kobj = NULL;
    }

    pr_info("OuiChefs sysfs interface removed\n");
}