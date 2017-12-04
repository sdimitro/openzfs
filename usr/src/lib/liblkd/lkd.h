/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

#ifndef	_LKD_H
#define	_LKD_H

#include <sys/types.h>
#include <nlist.h>
#include <sys/user.h>
#include <sys/proc.h>


#ifdef __cplusplus
extern "C" {
#endif

/* define a 'cookie' to pass around between user code and the library */
typedef struct lkd lkd_t;

/* liblkd routine definitions */

#ifdef __STDC__

extern lkd_t	*lkd_open(const char *, const char *, const char *,
		int, const char *);
extern int	lkd_close(lkd_t *);
extern ssize_t	lkd_pread(lkd_t *, uint64_t, void *, size_t);
extern ssize_t	lkd_kread(lkd_t *, uint64_t, void *, size_t);
extern char	*lkd_vmcoreinfo_lookup(lkd_t *, const char *);

#else

extern lkd_t	*lkd_open();
extern int	lkd_close();
extern ssize_t	lkd_pread();
extern ssize_t	lkd_kread();
extern char	*lkd_vmcoreinfo_lookup();

#endif	/* __STDC__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _LKD_H */
