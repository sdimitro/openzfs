/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2011 Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2011, 2014 by Delphix. All rights reserved.
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

/*
 * The efilabel tool writes out a new partition table on a given disk
 * using the libefi API.  The partition table is identical to the one
 * 'zpool create' creates when presented with a whole disk.  The
 * routine label_disk() is based on zpool_label_disk() which ZFS calls
 * to label disks.
 */

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <unistd.h>
#include <sys/param.h>
#include <libintl.h>
#include <locale.h>
#include <sys/vtoc.h>
#include <sys/efi_partition.h>

#define	RDISK_ROOT	"/dev/rdsk"
#define	BACKUP_SLICE	"s2"
#define	START_BLOCK	256

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

void
usage()
{
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);
	(void) fputs(gettext("Usage: efilabel <devicename>\n"), stderr);
}

int
label_disk(char *disk)
{
	char path[MAXPATHLEN];
	struct dk_gpt *vtoc;
	int fd;
	size_t resv = EFI_MIN_RESV_SIZE;
	uint64_t slice_size;
	int err;

	if (strncmp(disk, RDISK_ROOT, strlen(RDISK_ROOT)) == 0) {
		(void) snprintf(path, sizeof (path), "%s%s", disk,
		    BACKUP_SLICE);
	} else {
		(void) snprintf(path, sizeof (path), "%s/%s%s", RDISK_ROOT,
		    disk, BACKUP_SLICE);
	}

	if ((fd = open(path, O_RDWR | O_NDELAY)) < 0) {
		perror("Error opening device.");
		return (1);
	}

	if (efi_alloc_and_init(fd, EFI_NUMPAR, &vtoc) != 0) {
		/*
		 * The only way this can fail is if we run out of memory, or we
		 * were unable to read the disk's capacity
		 */
		if (errno == ENOMEM)
			perror("Failed to allocate EFI vtoc.");

		(void) close(fd);
		(void) fprintf(stderr, "Unable to read disk capacity.");

		return (1);
	}

	slice_size = vtoc->efi_last_u_lba + 1;
	slice_size -= EFI_MIN_RESV_SIZE;
	slice_size -= START_BLOCK;

	vtoc->efi_parts[0].p_start = START_BLOCK;
	vtoc->efi_parts[0].p_size = slice_size;

	/*
	 * Why we use V_USR: V_BACKUP confuses users, and is considered
	 * disposable by some EFI utilities (since EFI doesn't have a backup
	 * slice).  V_UNASSIGNED is supposed to be used only for zero size
	 * partitions, and efi_write() will fail if we use it.  V_ROOT, V_BOOT,
	 * etc. were all pretty specific.  V_USR is as close to reality as we
	 * can get, in the absence of V_OTHER.
	 */
	vtoc->efi_parts[0].p_tag = V_USR;
	(void) strcpy(vtoc->efi_parts[0].p_name, "efilabel");

	vtoc->efi_parts[8].p_start = slice_size + START_BLOCK;
	vtoc->efi_parts[8].p_size = resv;
	vtoc->efi_parts[8].p_tag = V_RESERVED;

	err = efi_write(fd, vtoc);
	(void) close(fd);
	efi_free(vtoc);
	/*
	 * Some block drivers (like pcata) may not support EFI GPT labels.
	 */
	if (err != 0)
		(void) fprintf(stderr,
		    "Unable to format. Please try using fdisk(1M).");
	return (err == 0 ? 0 : 1);
}

int
main(int argc, char *argv[])
{
	if (argc != 2) {
		usage();
		return (1);
	}

	return (label_disk(argv[1]));
}
