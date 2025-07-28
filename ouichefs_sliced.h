/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ouiche_fs - Enhanced Block sharing implementation for small files
 * Now supports files spanning multiple contiguous slices
 *
 * Copyright (C) 2018 Redha Gouicem <redha.gouicem@lip6.fr>
 */
#ifndef _OUICHEFS_SLICED_H
#define _OUICHEFS_SLICED_H

#include "ouichefs.h"

/* Sliced block constants */
#define OUICHEFS_SLICE_SIZE 128 /* 128 bytes per slice */
#define OUICHEFS_SLICES_PER_BLOCK 32 /* 32 slices per 4KB block */
#define OUICHEFS_DATA_SLICES 31 /* 31 data slices (first slice is metadata) */

/* Enhanced small file threshold - now supports files up to a full page */
#define OUICHEFS_SMALL_FILE_THRESHOLD \
	(OUICHEFS_SLICE_SIZE * OUICHEFS_DATA_SLICES) /* ~4KB */

/* Bit manipulation for index_block field in small files */
#define OUICHEFS_SLICE_BLOCK_MASK 0x07FFFFFF /* 27 bits for block number */
#define OUICHEFS_SLICE_NUMBER_SHIFT 27 /* 5 bits for slice number */
#define OUICHEFS_SLICE_NUMBER_MASK 0x1F /* 5 bits mask */

/* Magic number for sliced blocks */
#define OUICHEFS_SLICED_MAGIC 0x534C4943 /* "SLIC" */

/*
 * Enhanced sliced block metadata structure
 * This occupies the first slice (128 bytes) of a sliced block
 * Additional space can be used for future optimizations
 */
struct ouichefs_sliced_block_meta {
	__le32 slice_bitmap; /* Bitmap of free slices (1=free, 0=occupied) */
	__le32 next_block; /* Next block in partially filled list (0 if none) */
	__le32 magic; /* Magic number to identify sliced blocks */
	__le32 total_free; /* Total free slices in this block for quick lookup */
	__le32 largest_free; /* Size of largest contiguous free region */
	__le32 reserved[27]; /* Reserved space for future enhancements */
};

/*
 * Extract block number from small file index_block
 */
static inline uint32_t ouichefs_get_slice_block(uint32_t index_block)
{
	return index_block & OUICHEFS_SLICE_BLOCK_MASK;
}

/*
 * Extract slice number from small file index_block
 */
static inline uint32_t ouichefs_get_slice_number(uint32_t index_block)
{
	return (index_block >> OUICHEFS_SLICE_NUMBER_SHIFT) &
	       OUICHEFS_SLICE_NUMBER_MASK;
}

/*
 * Create index_block value for small file
 */
static inline uint32_t ouichefs_make_slice_index(uint32_t block_num,
						 uint32_t slice_num)
{
	return (block_num & OUICHEFS_SLICE_BLOCK_MASK) |
	       ((slice_num & OUICHEFS_SLICE_NUMBER_MASK)
		<< OUICHEFS_SLICE_NUMBER_SHIFT);
}

/*
 * Check if a file is small enough to use sliced blocks
 * Enhanced to support larger files up to page size
 */
static inline bool ouichefs_is_small_file(size_t size)
{
	return size <= OUICHEFS_SMALL_FILE_THRESHOLD;
}

/*
 * Calculate how many slices are needed for a given file size
 */
static inline uint32_t ouichefs_slices_needed(size_t file_size)
{
	if (file_size == 0)
		return 0;
	return (file_size + OUICHEFS_SLICE_SIZE - 1) / OUICHEFS_SLICE_SIZE;
}

/*
 * Get offset within a slice for a given file position
 */
/*static inline uint32_t ouichefs_get_slice_offset(loff_t pos,
						 uint32_t slice_size)
{
	return pos % slice_size;
}*/

/*
 * Check if bitmap has 'count' contiguous free slices starting from 'start_slice'
 */
static inline bool ouichefs_has_contiguous_slices(uint32_t bitmap,
						  uint32_t start_slice,
						  uint32_t count)
{
	if (start_slice == 0 ||
	    start_slice + count > OUICHEFS_SLICES_PER_BLOCK) {
		return false;
	}

	/* Check if we have count contiguous free slices with the bitmap */
	for (uint32_t i = 0; i < count; i++) {
		if (!(bitmap & (1U << (start_slice + i)))) {
			return false; /* Slice is occupied */
		}
	}

	return true;
}

/* Enhanced function declarations for multi-slice support */

/* Multi-slice allocation and freeing */
uint32_t ouichefs_alloc_slices(struct super_block *sb, uint32_t *slice_num,
			       uint32_t count);
void ouichefs_free_slices(struct super_block *sb, uint32_t block_num,
			  uint32_t slice_num, uint32_t count);

/* Multi-slice I/O operations */
int ouichefs_read_slices(struct super_block *sb, uint32_t block_num,
			 uint32_t slice_start, uint32_t slice_count,
			 char *buffer, size_t size);
int ouichefs_write_slices(struct super_block *sb, uint32_t block_num,
			  uint32_t slice_start, uint32_t slice_count,
			  const char *buffer, size_t size);

/* Legacy single-slice functions (for backward compatibility) */
uint32_t ouichefs_alloc_slice(struct super_block *sb, uint32_t *slice_num);
void ouichefs_free_slice(struct super_block *sb, uint32_t block_num,
			 uint32_t slice_num);
int ouichefs_read_slice(struct super_block *sb, uint32_t block_num,
			uint32_t slice_num, char *buffer, size_t size);
int ouichefs_write_slice(struct super_block *sb, uint32_t block_num,
			 uint32_t slice_num, const char *buffer, size_t size);

/* Block management */
int ouichefs_init_sliced_block(struct super_block *sb, uint32_t block_num);
bool ouichefs_has_contiguous_slices(uint32_t bitmap, uint32_t start_slice,
				    uint32_t count);
uint32_t ouichefs_slices_needed(size_t file_size);

/* Advanced slice management for relocation and defragmentation */
uint32_t ouichefs_try_relocate_slices(struct super_block *sb,
				      uint32_t old_block, uint32_t old_slice,
				      uint32_t old_count, uint32_t new_count,
				      uint32_t *new_slice);

#endif /* _OUICHEFS_SLICED_H */