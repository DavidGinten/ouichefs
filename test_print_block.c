#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdint.h>

/* Constants matching kernel definitions */
#define OUICHEFS_SLICE_SIZE 128
#define OUICHEFS_SLICES_PER_BLOCK 32
#define OUICHEFS_SLICED_MAGIC 0x534C4943  /* "SLIC" */

/* IOCTL definitions */
#define OUICHEFS_IOC_MAGIC 'O'
#define OUICHEFS_IOC_DISPLAY_BLOCK _IOR(OUICHEFS_IOC_MAGIC, 1, struct ouichefs_block_display)

/* Structure for block display data */
struct ouichefs_block_display {
	uint32_t block_number;
	char slices[OUICHEFS_SLICES_PER_BLOCK][OUICHEFS_SLICE_SIZE];
};

/* Metadata structure */
struct ouichefs_sliced_block_meta {
	uint32_t slice_bitmap;
	uint32_t next_block;
	uint32_t magic; // Maybe just remove this ...
	uint32_t reserved[29];
};


/**
 * Convert a character to a printable representation
 */
char to_printable(char c)
{
	if (c >= 32 && c <= 126) {
		return c;
	} else if (c == 0) {
		return '!';  /* Unicode null symbol */
	} else {
		return '?';  /* Middle dot for non-printable */
	}
}

/**
 * Display slice content with formatting
 */
void display_slice(int slice_num, const char *slice_data, int highlight_slice)
{
	int i;
	char formatted[OUICHEFS_SLICE_SIZE + 1];
	
	/* Convert to printable characters */
	for (i = 0; i < OUICHEFS_SLICE_SIZE; i++) {
		formatted[i] = to_printable(slice_data[i]);
	}
	formatted[OUICHEFS_SLICE_SIZE] = '\0';
	
	printf("[%02d] %s\n", slice_num, formatted);
}

/**
 * Display metadata information
 */
void display_metadata(const struct ouichefs_sliced_block_meta *meta)
{
	uint32_t bitmap = meta->slice_bitmap;
	uint32_t next_block = meta->next_block;
	uint32_t magic = meta->magic;
	
	printf("\n=== METADATA SLICE (Slice 0) ===\n");
	printf("Magic Number:   0x%08X %s\n", magic, 
	       (magic == OUICHEFS_SLICED_MAGIC) ? "[VALID]" : "[INVALID]");
	printf("Slice Bitmap:   0x%08X (binary: ", bitmap);
	
	/* Display bitmap in binary with colors */
	for (int i = 31; i >= 0; i--) {
		if (i == 0) {
			printf("%d", (bitmap >> i) & 1);  /* Metadata bit */
		} else if ((bitmap >> i) & 1) {
			printf("%d", 1);  /* Free slice */
		} else {
			printf("%d", 0);    /* Occupied slice */
		}
	}
	printf(")\n");
	
	printf("Next Block:     %u %s\n", next_block,
	       (next_block == 0) ? "[NONE]" : "");
	
	/* Count and display free/occupied slices */
	int free_count = 0, occupied_count = 0;
	printf("Slice Status:   ");
	for (int i = 1; i < OUICHEFS_SLICES_PER_BLOCK; i++) {
		if ((bitmap >> i) & 1) {
			free_count++;
		} else {
			occupied_count++;
		}
	}
	printf("Free: %d , Occupied: %d\n", 
	       free_count, occupied_count);
	
	/* List occupied slices */
	if (occupied_count > 0) {
		printf("Occupied slices: ");
		for (int i = 1; i < OUICHEFS_SLICES_PER_BLOCK; i++) {
			if (!((bitmap >> i) & 1)) {
				printf("%d\n", i);
			}
		}
		printf("\n");
	}
	
	printf("\n");
}

/**
 * Display block summary statistics
 */
void display_block_summary(const struct ouichefs_block_display *display_data, int file_slice)
{
	int total_data_bytes = 0;
	int slices_with_data = 0;
	int empty_slices = 0;
	
	/* Analyze all slices except metadata */
	for (int i = 1; i < OUICHEFS_SLICES_PER_BLOCK; i++) {
		int slice_bytes = 0;
		int has_data = 0;
		
		for (int j = 0; j < OUICHEFS_SLICE_SIZE; j++) {
			if (display_data->slices[i][j] != 0) {
				has_data = 1;
				slice_bytes++;
			}
		}
		
		if (has_data) {
			slices_with_data++;
			total_data_bytes += slice_bytes;
		} else {
			empty_slices++;
		}
	}
	printf("\n");
}

int main(int argc, char *argv[])
{
	struct ouichefs_block_display display_data;
	int fd, ret;
	const char *filename;
	
	/* Check arguments */
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
		fprintf(stderr, "Display the block content for a small file in OuiChefs\n");
		return 1;
	}
	
	filename = argv[1];
	
	/* Open the file */
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("Error opening file");
		return 1;
	}
	
	printf("OuiChefs Block Content Display Tool\n");
	printf("File: %s\n\n", filename);
	
	/* Call the ioctl */
	ret = ioctl(fd, OUICHEFS_IOC_DISPLAY_BLOCK, &display_data);
	if (ret < 0) {
		perror("IOCTL failed");
		switch (errno) {
		case EINVAL:
			fprintf(stderr, "Error: File is not a regular file or exceeds 128 bytes or doesn't use slices\n");
			break;
		case ENODATA:
			fprintf(stderr, "Error: File has no slice allocated\n");
			break;
		case EIO:
			fprintf(stderr, "Error: Failed to read block from disk\n");
			break;
		case ENOTTY:
			fprintf(stderr, "Error: IOCTL not supported (wrong filesystem?)\n");
			break;
		default:
			fprintf(stderr, "Error: Unknown error occurred\n");
			break;
		}
		close(fd);
		return 1;
	}
	
	/* Display metadata */
	struct ouichefs_sliced_block_meta *meta = 
		(struct ouichefs_sliced_block_meta *)display_data.slices[0];
	display_metadata(meta);
	
	/* Find which slice belongs to this file by checking bitmap */
	int file_slice = -1;
	uint32_t bitmap = meta->slice_bitmap;
	
	/* The file's slice should be marked as occupied (bit = 0) */
	/* We'll guess it's the first occupied slice for now */
	for (int i = 1; i < OUICHEFS_SLICES_PER_BLOCK; i++) {
		if (!((bitmap >> i) & 1)) {
			file_slice = i;
			break;
		}
	}
	
	/* Display block summary */
	display_block_summary(&display_data, file_slice);
	
	/* Display all slices */
	printf("=== BLOCK CONTENT (32 slices x 128 bytes) ===\n");
	printf("Legend: First row (slice) is Metadata | Then 31 data slices | "
					"! is Unicode null symbol or an actual ! | "
					"? is non-printable char or an actual ?\n\n");
	
	for (int i = 0; i < OUICHEFS_SLICES_PER_BLOCK; i++) {
		display_slice(i, display_data.slices[i], file_slice);
	}
	
	printf("\n=== END OF BLOCK ===\n");
	
	close(fd);
	return 0;
}