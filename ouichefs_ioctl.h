#ifndef _OUICHEFS_IOCTL_H
#define _OUICHEFS_IOCTL_H

#include <linux/ioctl.h>

/* IOCTL command definitions */
#define OUICHEFS_IOC_MAGIC 'O'
#define OUICHEFS_IOC_DISPLAY_BLOCK \
	_IOR(OUICHEFS_IOC_MAGIC, 1, struct ouichefs_block_display)

/* Structure for block display data */
struct ouichefs_block_display {
	uint32_t block_number;
	char slices[OUICHEFS_SLICES_PER_BLOCK][OUICHEFS_SLICE_SIZE];
};

#endif /* _OUICHEFS_IOCTL_H */