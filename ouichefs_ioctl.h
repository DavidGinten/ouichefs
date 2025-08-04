/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ouiche_fs - a simple educational filesystem for Linux
 *
 * Copyright (C) 2018 Redha Gouicem <redha.gouicem@lip6.fr>
 */
#ifndef _OUICHEFS_IOCTL_H
#define _OUICHEFS_IOCTL_H

#include <linux/ioctl.h>

/* IOCTL command definitions */
#define OUICHEFS_IOC_DISPLAY_BLOCK \
	_IOR('O', 1, struct ouichefs_block_display)

/* Structure for block display data */
struct ouichefs_block_display {
	uint32_t block_number;
	char slices[OUICHEFS_SLICES_PER_BLOCK][OUICHEFS_SLICE_SIZE];
};

#endif /* _OUICHEFS_IOCTL_H */
