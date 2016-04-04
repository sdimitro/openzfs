/*
 * CDDL HEADER START
 *
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include "lua.h"
#include "lauxlib.h"

#include <sys/zcp.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_prop.h>
#include <sys/dsl_synctask.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_bookmark.h>
#include <sys/dsl_destroy.h>
#include <sys/dmu_objset.h>
#include <sys/zfs_znode.h>
#include <sys/zfeature.h>
#include <sys/metaslab.h>

#define	DST_AVG_BLKSHIFT 14

typedef int (zcp_synctask_func_t)(lua_State *, boolean_t);
typedef struct zcp_synctask_info {
	const char *name;
	zcp_synctask_func_t *func;
	zfs_space_check_t space_check;
	int blocks_modified;
	const zcp_arg_t pargs[4];
	const zcp_arg_t kwargs[2];
} zcp_synctask_info_t;

static int zcp_synctask_destroy(lua_State *, boolean_t);
static zcp_synctask_info_t zcp_synctask_destroy_info = {
	.name = "destroy",
	.func = zcp_synctask_destroy,
	.space_check = ZFS_SPACE_CHECK_NONE,
	.blocks_modified = 0,
	.pargs = {
	    {.za_name = "filesystem | snapshot", .za_lua_type = LUA_TSTRING},
	    {NULL, NULL}
	},
	.kwargs = {
	    {.za_name = "defer", .za_lua_type = LUA_TBOOLEAN},
	    {NULL, NULL}
	}
};

static int
zcp_synctask_destroy(lua_State *state, boolean_t sync)
{
	int err;
	const char *dsname = lua_tostring(state, 1);
	zcp_run_info_t *ri = zcp_run_info(state);

	boolean_t issnap = (strchr(dsname, '@') != NULL);

	if (!issnap && !lua_isnil(state, 2)) {
		return (luaL_error(state,
		    "'deferred' kwarg only supported for snapshots: %s",
		    dsname));
	}

	if (issnap) {
		boolean_t defer = B_FALSE;

		if (!lua_isnil(state, 2)) {
			defer = lua_toboolean(state, 2);
		}

		err = dsl_destroy_snapshot_check(dsname, defer, ri->zri_tx);
		if (err == EIO) {
			return (luaL_error(state,
			    "I/O error while accessing dataset '%s'", dsname));
		}
		if (sync && err == 0) {
			dsl_destroy_snapshot_sync(dsname, defer, ri->zri_tx);
		}
	} else {
		dsl_destroy_head_arg_t args;

		args.ddha_name = dsname;

		err = dsl_destroy_head_check(&args, ri->zri_tx);
		if (err == EIO) {
			return (luaL_error(state,
			    "I/O error while accessing dataset '%s'", dsname));
		}
		if (sync && err == 0) {
			dsl_destroy_head_sync(&args, ri->zri_tx);
		}
	}

	return (err);
}

static int
zcp_synctask_func(lua_State *state)
{
	int err;

	zcp_synctask_info_t *info = lua_touserdata(state, lua_upvalueindex(1));
	boolean_t sync = lua_toboolean(state, lua_upvalueindex(2));
	zcp_run_info_t *ri = zcp_run_info(state);
	dsl_pool_t *dp = ri->zri_pool;

	/* MOS space is triple-dittoed, so we multiply by 3. */
	uint64_t funcspace = (info->blocks_modified << DST_AVG_BLKSHIFT) * 3;

	zcp_parse_args(state, info->name, info->pargs, info->kwargs);

	err = 0;
	if (info->space_check != ZFS_SPACE_CHECK_NONE && funcspace > 0) {
		uint64_t quota = dsl_pool_adjustedsize(dp,
		    info->space_check == ZFS_SPACE_CHECK_RESERVED) -
		    metaslab_class_get_deferred(spa_normal_class(dp->dp_spa));
		uint64_t used = dsl_dir_phys(dp->dp_root_dir)->dd_used_bytes +
		    ri->zri_space_used;

		if (used + funcspace > quota) {
			err = SET_ERROR(ENOSPC);
		}
	}

	if (err == 0) {
		err = info->func(state, sync);
	}

	if (err == 0) {
		ri->zri_space_used += funcspace;
	}

	lua_pushnumber(state, (lua_Number)err);
	return (1);
}

int
zcp_load_synctask_lib(lua_State *state, boolean_t sync)
{
	int i;
	zcp_synctask_info_t *zcp_synctask_funcs[] = {
		&zcp_synctask_destroy_info,
		NULL
	};

	lua_newtable(state);

	for (i = 0; zcp_synctask_funcs[i] != NULL; i++) {
		zcp_synctask_info_t *info = zcp_synctask_funcs[i];
		lua_pushlightuserdata(state, info);
		lua_pushboolean(state, sync);
		lua_pushcclosure(state, &zcp_synctask_func, 2);
		lua_setfield(state, -2, info->name);
		info++;
	}

	return (1);
}
