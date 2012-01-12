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

/*
 * LibZFS2 is intended to replace most functionality in libzfs (1).
 * It has the following characteristics:
 *
 *  - Thread Safe.  libzfs2 is accessible concurrently from multiple
 *  threads.  This is accomplished primarily by avoiding global data
 *  (e.g. caching).  Since it's thread-safe, there is no reason for a
 *  process to have multiple libzfs "instances".  Therefore, we store our
 *  few pieces of data (e.g. the file descriptor) in global variables.
 *  The fd is reference-counted so that the libzfs2 library can be "initialized"
 *  multiple times (e.g. by different consumers within the same process).
 *
 *  - Committed Interface.  The libzfs2 interface will be committed, therefore
 *  consumers can compile against it and be confident that their code will
 *  continue to work on future releases of this code.  Currently, the interface
 *  is Evolving (not Committed), but we intend to commit to it once it is more
 *  complete and we determine that it meets the needs of all consumers.
 *
 *  - Programatic Error Handling.  libzfs2 communicates errors with
 *  defined error numbers, and doesn't print anything to stdout/stderr.
 *
 *  - Thin Layer.  libzfs2 is a thin layer, marshaling arguments
 *  to/from the kernel ioctls.  There is generally a 1:1 correspondence
 *  between libzfs2 functions and ioctls to /dev/zfs.
 *
 *  - Clear Atomicity.
 *  Because libzfs2 functions are generally 1:1 with kernel ioctls, and kernel
 *  ioctls are general atomic, each libzfs2 function is atomic.
 *  For example, creating multiple snapshots with a single call to
 *  zfs2_snapshot() is atomic -- it can't fail with only some of the requested
 *  snapshots created, even in the event of power loss or system crash.
 *
 *  - Continued libzfs1 Support.  Some higher-level operations (e.g.
 *  support for "zfs send -R") are too complicated to fit the scope of
 *  libzfs2.  This functionality will continue to live in libzfs1.  Where
 *  appropriate, libzfs1 will use the underlying atomic operations of libzfs2.
 *  For example, libzfs1 may implement "zfs send -R | zfs receive" by
 *  using individual "send one snapshot", rename, destroy, and "receive one
 *  snapshot" operations in libzfs2.  /sbin/zfs and /zbin/zpool will link with
 *  both libzfs1 and libzfs2.  Other consumers should aim to use only libzfs2,
 *  since that will be the supported, stable interface going forwards.
 */

#include <libzfs2.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/nvpair.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/zfs_ioctl.h>

static int g_fd;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_refcount;

int
libzfs2_init(void)
{
	(void) pthread_mutex_lock(&g_lock);
	if (g_refcount == 0) {
		g_fd = open("/dev/zfs", O_RDWR);
		if (g_fd < 0) {
			(void) pthread_mutex_unlock(&g_lock);
			return (errno);
		}
	}
	g_refcount++;
	(void) pthread_mutex_unlock(&g_lock);
	return (0);
}

void
libzfs2_fini(void)
{
	(void) pthread_mutex_lock(&g_lock);
	ASSERT3S(g_refcount, >, 0);
	g_refcount--;
	if (g_refcount == 0)
		(void) close(g_fd);
	(void) pthread_mutex_unlock(&g_lock);
}

static int
libzfs2_ioctl(zfs_ioc_t ioc, const char *name,
    nvlist_t *source, nvlist_t **resultp)
{
	zfs_cmd_t zc = { 0 };
	int error = 0;
	char *packed;
	size_t size;

	ASSERT3S(g_refcount, >, 0);

	packed = fnvlist_pack(source, &size);

	(void) strlcpy(zc.zc_name, name, sizeof (zc.zc_name));
	zc.zc_nvlist_src = (uint64_t)(uintptr_t)packed;
	zc.zc_nvlist_src_size = size;

	if (resultp != NULL) {
		zc.zc_nvlist_dst_size = 128 * 1024;
		zc.zc_nvlist_dst = (uint64_t)(uintptr_t)
		    malloc(zc.zc_nvlist_dst_size);
		if (zc.zc_nvlist_dst == NULL) {
			error = ENOMEM;
			goto out;
		}
	}

	while (ioctl(g_fd, ioc, &zc) != 0) {
		if (errno == ENOMEM && resultp != NULL) {
			free((void *)(uintptr_t)zc.zc_nvlist_dst);
			zc.zc_nvlist_dst_size *= 2;
			zc.zc_nvlist_dst = (uint64_t)(uintptr_t)
			    malloc(zc.zc_nvlist_dst_size);
			if (zc.zc_nvlist_dst == NULL) {
				error = ENOMEM;
				goto out;
			}
		} else {
			error = errno;
			break;
		}
	}
	if (zc.zc_nvlist_dst_filled) {
		*resultp = fnvlist_unpack((void *)(uintptr_t)zc.zc_nvlist_dst,
		    zc.zc_nvlist_dst_size);
	} else if (resultp != NULL) {
		*resultp = NULL;
	}

out:
	free(packed);
	free((void *)(uintptr_t)zc.zc_nvlist_dst);
	return (error);
}

/*
 * Creates snapshots.
 *
 * The keys in the snaps nvlist are the snapshots to be created.
 * They must all be in the same pool.
 *
 * The props nvlist is properties to set.  Currently only user properties
 * are supported.  { user:prop_name -> string value }
 *
 * The returned results nvlist will have an entry for each snapshot that failed.
 * The value will be the error code.
 *
 * The return value will be 0 if all snapshots were created, otherwise it will
 * be the errno of a (undetermined) snapshot that failed.
 */
int
zfs2_snapshot(nvlist_t *snaps, nvlist_t *props, nvlist_t **resultp)
{
	nvpair_t *elem;
	nvlist_t *args;
	int error;
	char pool[MAXNAMELEN];

	/* determine the pool name */
	elem = nvlist_next_nvpair(snaps, NULL);
	if (elem == NULL)
		return (0);
	(void) strlcpy(pool, nvpair_name(elem), sizeof (pool));
	pool[strcspn(pool, "/@")] = '\0';

	args = fnvlist_alloc();
	fnvlist_add_nvlist(args, "snaps", snaps);
	if (props != NULL)
		fnvlist_add_nvlist(args, "props", props);

	error = libzfs2_ioctl(ZFS_IOC_SNAPSHOT, pool, args, resultp);
	nvlist_free(args);

	return (error);
}

int
zfs2_snaprange_space(const char *firstsnap, const char *lastsnap,
    uint64_t *usedp)
{
	nvlist_t *args;
	nvlist_t *result;
	int err;
	char fs[MAXNAMELEN];
	char *atp;

	/* determine the fs name */
	(void) strlcpy(fs, firstsnap, sizeof (fs));
	atp = strchr(fs, '@');
	if (atp == NULL)
		return (EINVAL);
	*atp = '\0';

	args = fnvlist_alloc();
	fnvlist_add_string(args, "firstsnap", firstsnap);

	err = libzfs2_ioctl(ZFS_IOC_SPACE_SNAPS, lastsnap, args, &result);
	nvlist_free(args);
	if (err == 0)
		*usedp = fnvlist_lookup_uint64(result, "used");
	fnvlist_free(result);

	return (err);
}
