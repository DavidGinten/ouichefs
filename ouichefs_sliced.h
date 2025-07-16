/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ouiche_fs - Block sharing implementation for small files
 *
 * Copyright (C) 2018 Redha Gouicem <redha.gouicem@lip6.fr>
 */
#ifndef _OUICHEFS_SLICED_H
#define _OUICHEFS_SLICED_H

#include "ouichefs.h"

/* Sliced block constants */
#define OUICHEFS_SLICE_SIZE 128  /* 128 bytes per slice */
#define OUICHEFS_SLICES_PER_BLOCK 32  /* 32 slices per 4KB block */
#define OUICHEFS_DATA_SLICES 31  /* 31 data slices (first slice is metadata) */

/* Small file threshold - files smaller than this use sliced blocks */
#define OUICHEFS_SMALL_FILE_THRESHOLD (OUICHEFS_SLICE_SIZE * 4)  /* 512 bytes */

/* Bit manipulation for index_block field in small files */
#define OUICHEFS_SLICE_BLOCK_MASK 0x07FFFFFF  /* 27 bits for block number */
#define OUICHEFS_SLICE_NUMBER_SHIFT 27        /* 5 bits for slice number */
#define OUICHEFS_SLICE_NUMBER_MASK 0x1F       /* 5 bits mask */

/* Maximum sliceable block number (512GB / 4KB = 128M blocks) */
#define OUICHEFS_MAX_SLICEABLE_BLOCK ((1UL << 27) - 1)

/**
 * Sliced block metadata structure
 * This occupies the first slice (128 bytes) of a sliced block
 */
struct ouichefs_sliced_block_meta {
	__le32 slice_bitmap;    /* Bitmap of free slices (1=free, 0=occupied) */
	__le32 next_block;      /* Next block in partially filled list (0 if none) */
	__le32 magic;           /* Magic number to identify sliced blocks */
	__le32 reserved[29];    /* Reserved space to fill 128 bytes */
};

/* Magic number for sliced blocks */
#define OUICHEFS_SLICED_MAGIC 0x534C4943  /* "SLIC" */

/**
 * Extract block number from small file index_block
 */
static inline uint32_t ouichefs_get_slice_block(uint32_t index_block)
{
	return index_block & OUICHEFS_SLICE_BLOCK_MASK;
}

/**
 * Extract slice number from small file index_block
 */
static inline uint32_t ouichefs_get_slice_number(uint32_t index_block)
{
	return (index_block >> OUICHEFS_SLICE_NUMBER_SHIFT) & OUICHEFS_SLICE_NUMBER_MASK;
}

/**
 * Create index_block value for small file
 */
static inline uint32_t ouichefs_make_slice_index(uint32_t block_num, uint32_t slice_num)
{
	return (block_num & OUICHEFS_SLICE_BLOCK_MASK) | 
	       ((slice_num & OUICHEFS_SLICE_NUMBER_MASK) << OUICHEFS_SLICE_NUMBER_SHIFT);
}

/**
 * Check if a file is small enough to use sliced blocks
 */
static inline bool ouichefs_is_small_file(size_t size)
{
	return size <= OUICHEFS_SMALL_FILE_THRESHOLD;
}

/**
 * Get offset within a slice for a given file position
 */
static inline uint32_t ouichefs_get_slice_offset(loff_t pos, uint32_t slice_size)
{
	return pos % slice_size;
}

/* Function declarations */
uint32_t ouichefs_alloc_slice(struct super_block *sbi, uint32_t *slice_num);
void ouichefs_free_slice(struct super_block *sbi, uint32_t block_num, uint32_t slice_num);
int ouichefs_read_slice(struct super_block *sb, uint32_t block_num, uint32_t slice_num, 
                       char *buffer, size_t size);
int ouichefs_write_slice(struct super_block *sb, uint32_t block_num, uint32_t slice_num,
                        const char *buffer, size_t size);
int ouichefs_init_sliced_block(struct super_block *sb, uint32_t block_num);

#endif /* _OUICHEFS_SLICED_H */