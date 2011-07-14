/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/* Copyright (c) 2011 by Delphix. All rights reserved. */

/*
 * NDMP property management
 */

#include "ndmp_impl.h"

typedef struct ndmp_prop_def {
	const char	*sc_name;
	const char	*sc_value;
} ndmp_prop_def_t;

/*
 * Any changes to the order of this table's entries need to be reflected in the
 * ndmp_prop_t enumeration.
 */
ndmp_prop_def_t ndmp_propdef_table[] =
{
	{"dar-support",			"true" },
	{"token-maxseq",		"9" },
	{"max-version",			"4" },
	{"min-version",			"2" },
	{"socket-css",			"65" },
	{"socket-crs",			"80" },
	{"mover-recordsize",		"60" },
	{"tcp-port",			"10000" },
	{"drive-type",			"sysv" },
	{"local-tape",			"true" },
};

static const char **
ndmp_get_prop_table(ndmp_session_t *session)
{
	if (session->ns_server != NULL)
		return (session->ns_server->ns_props);
	else
		return (session->ns_client->nc_props);
}

/*
 * Loads all the NDMP configuration parameters and sets up the
 * property table.
 */
int
ndmp_load_prop(ndmp_session_t *session)
{
	const char **table = ndmp_get_prop_table(session);
	ndmp_prop_t id;
	ndmp_prop_def_t *propdef;
	const char *value;

	ndmp_debug(session, "Properties");

	for (id = 0; id < NDMP_MAXALL; id++) {
		propdef = &ndmp_propdef_table[id];
		value = session->ns_conf->nc_get_prop(propdef->sc_name);

		if (value != NULL)
			table[id] = value;
		else
			table[id] = propdef->sc_value;

		ndmp_debug(session, "  %s = %s", propdef->sc_name, table[id]);
	}

	return (0);
}

/*
 * Return the value of the specified property.
 */
const char *
ndmp_get_prop(ndmp_session_t *session, ndmp_prop_t id)
{
	assert(id < NDMP_MAXALL);

	return (ndmp_get_prop_table(session)[id]);
}

/*
 * Return the value of a boolean config param.  Returns B_TRUE if config is set
 * to "true", B_FALSE otherwise.
 */
boolean_t
ndmp_get_prop_boolean(ndmp_session_t *session, ndmp_prop_t id)
{
	const char *val = ndmp_get_prop(session, id);

	return (strcmp(val, "true") == 0);
}

/*
 * Returns the integer value of a property.
 */
int
ndmp_get_prop_int(ndmp_session_t *session, ndmp_prop_t id)
{
	const char *val = ndmp_get_prop(session, id);

	return (atoi(val));
}
