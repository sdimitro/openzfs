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
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

#ifndef	_LIBZFS2_H
#define	_LIBZFS2_H

#include <libnvpair.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/fs/zfs.h>

#ifdef	__cplusplus
extern "C" {
#endif

int libzfs2_init(void);
void libzfs2_fini(void);

int zfs2_snapshot(nvlist_t *snaps, nvlist_t *props, nvlist_t **resultp);

int zfs2_snaprange_space(const char *firstsnap, const char *lastsnap,
    uint64_t *usedp);

int zfs2_send(const char *snapname, const char *fromsnap, int fd);
int zfs2_receive(const char *snapname, nvlist_t *props, const char *origin,
    boolean_t force, int fd);
int zfs2_send_space(const char *snapname, const char *fromsnap, uint64_t *);

boolean_t zfs2_exists(const char *dataset);


#ifdef	__cplusplus
}
#endif

#endif	/* _LIBZFS2_H */
