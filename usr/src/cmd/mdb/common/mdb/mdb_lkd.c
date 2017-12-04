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

/*
 * Linux Kdump Target
 */

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_conf.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb.h>

#include <lkd.h>

typedef struct lt_data {
	char *l_symfile;		/* Symbol table pathname */
	char *l_lkdfile;		/* Core file pathname */
	void *l_cookie;			/* Cookie for liblkd routines */
	mdb_io_t *l_fio;		/* File i/o backend */
	mdb_gelf_file_t *l_file;	/* ELF file object */
	mdb_gelf_symtab_t *l_symtab;	/* Standard symbol table */
	mdb_gelf_symtab_t *l_dynsym;	/* Dynamic symbol table */
	unsigned long long l_offset;	/* KASLR offset */
} lt_data_t;

static const char *
lt_name(mdb_tgt_t *t)
{
	return ("lkd");
}

static void
lt_destroy(mdb_tgt_t *t)
{
	lt_data_t *lt = t->t_data;

	if (lt->l_dynsym != NULL)
		mdb_gelf_symtab_destroy(lt->l_dynsym);

	if (lt->l_symtab != NULL)
		mdb_gelf_symtab_destroy(lt->l_symtab);

	if (lt->l_file != NULL)
		mdb_gelf_destroy(lt->l_file);

	if (lt->l_fio != NULL)
		mdb_io_destroy(lt->l_fio);

	if (lt->l_lkdfile != NULL)
		strfree(lt->l_lkdfile);

	if (lt->l_symfile != NULL)
		strfree(lt->l_symfile);

	if (lt->l_cookie != NULL)
		lkd_close(lt->l_cookie);

	mdb_free(lt, sizeof (lt_data_t));
}

static ssize_t
lt_vread(mdb_tgt_t *t, void *buf, size_t nbytes, uintptr_t addr)
{
	lt_data_t *lt = t->t_data;
	ssize_t rval;

	if ((rval = lkd_kread(lt->l_cookie, addr, buf, nbytes)) == -1)
		return (set_errno(EMDB_NOMAP));

	return (rval);
}

static ssize_t
lt_pread(mdb_tgt_t *t, void *buf, size_t nbytes, physaddr_t addr)
{
	lt_data_t *lt = t->t_data;
	ssize_t rval;

	if ((rval = lkd_pread(lt->l_cookie, addr, buf, nbytes)) == -1)
		return (set_errno(EMDB_NOMAP));

	return (rval);
}

static int
lt_lookup_by_name(mdb_tgt_t *t, const char *obj, const char *name,
    GElf_Sym *symp, mdb_syminfo_t *sip)
{
	lt_data_t *lt = t->t_data;

	if (mdb_gelf_symtab_lookup_by_name(lt->l_symtab, name,
	    symp, &sip->sym_id) == 0) {
		sip->sym_table = MDB_TGT_SYMTAB;

		/*
		 * To account for KASLR, we need to increment the value
		 * of the symbol found in the symbol table by the KASLR
		 * offset.
		 */
		symp->st_value += lt->l_offset;

		return (0);
	}

	return (set_errno(EMDB_NOSYM));
}

static int
lt_lookup_by_addr(mdb_tgt_t *t, uintptr_t addr, uint_t flags,
    char *buf, size_t nbytes, GElf_Sym *symp, mdb_syminfo_t *sip)
{
	lt_data_t *lt = t->t_data;

	/*
	 * To account for KASLR, we need to decrement the address we're
	 * looking up by the KASLR offset, prior performing the lookup.
	 */
	addr -= lt->l_offset;

	if (mdb_gelf_symtab_lookup_by_addr(lt->l_symtab, addr,
	    flags, buf, nbytes, symp, &sip->sym_id) == 0) {
		strncpy(buf, mdb_gelf_sym_name(lt->l_symtab, symp), nbytes);
		sip->sym_table = MDB_TGT_SYMTAB;

		/*
		 * To account for KASLR, we need to increment the value
		 * of the symbol found in the symbol table by the KASLR
		 * offset.
		 */
		symp->st_value += lt->l_offset;

		return (0);
	}

	return (set_errno(EMDB_NOSYMADDR));
}

static const mdb_tgt_ops_t lt_ops = {
	(int (*)()) mdb_tgt_notsup,			/* t_setflags */
	(int (*)()) mdb_tgt_notsup,			/* t_setcontext */
	(void (*)()) mdb_tgt_notsup,			/* t_activate */
	(void (*)()) mdb_tgt_notsup,			/* t_deactivate */
	(void (*)()) mdb_tgt_notsup,			/* t_periodic */
	lt_destroy,					/* t_destroy */
	lt_name,					/* t_name */
	(const char *(*)()) mdb_conf_isa,		/* t_isa */
	(const char *(*)()) mdb_conf_platform,		/* t_platform */
	(int (*)()) mdb_tgt_notsup,			/* t_uname */
	(int (*)()) mdb_tgt_notsup,			/* t_dmodel */
	(ssize_t (*)()) mdb_tgt_notsup,			/* t_aread */
	(ssize_t (*)()) mdb_tgt_notsup,			/* t_awrite */
	lt_vread,					/* t_vread */
	(ssize_t (*)()) mdb_tgt_notsup,			/* t_vwrite */
	lt_pread,					/* t_pread */
	(ssize_t (*)()) mdb_tgt_notsup,			/* t_pwrite */
	lt_vread,					/* t_fread */
	(ssize_t (*)()) mdb_tgt_notsup,			/* t_fwrite */
	(ssize_t (*)()) mdb_tgt_notsup,			/* t_ioread */
	(ssize_t (*)()) mdb_tgt_notsup,			/* t_iowrite */
	(int (*)()) mdb_tgt_notsup,			/* t_vtop */
	lt_lookup_by_name,				/* t_lookup_by_name */
	lt_lookup_by_addr,				/* t_lookup_by_addr */
	(int (*)()) mdb_tgt_notsup,			/* t_symbol_iter */
	(int (*)()) mdb_tgt_notsup,			/* t_mapping_iter */
	(int (*)()) mdb_tgt_notsup,			/* t_object_iter */
	(const mdb_map_t *(*)()) mdb_tgt_notsup,	/* t_addr_to_map */
	(const mdb_map_t *(*)()) mdb_tgt_notsup,	/* t_name_to_map */
	(struct ctf_file *(*)()) mdb_tgt_notsup,	/* t_addr_to_ctf */
	(struct ctf_file *(*)()) mdb_tgt_notsup,	/* t_name_to_ctf */
	(int (*)()) mdb_tgt_notsup,			/* t_status */
	(int (*)()) mdb_tgt_notsup,			/* t_run */
	(int (*)()) mdb_tgt_notsup,			/* t_step */
	(int (*)()) mdb_tgt_notsup,			/* t_step_out */
	(int (*)()) mdb_tgt_notsup,			/* t_step_branch */
	(int (*)()) mdb_tgt_notsup,			/* t_next */
	(int (*)()) mdb_tgt_notsup,			/* t_cont */
	(int (*)()) mdb_tgt_notsup,			/* t_signal */
	(int (*)()) mdb_tgt_notsup,			/* t_add_vbrkpt */
	(int (*)()) mdb_tgt_notsup,			/* t_add_sbrkpt */
	(int (*)()) mdb_tgt_notsup,			/* t_add_pwapt */
	(int (*)()) mdb_tgt_notsup,			/* t_add_vwapt */
	(int (*)()) mdb_tgt_notsup,			/* t_add_iowapt */
	(int (*)()) mdb_tgt_notsup,			/* t_add_sysenter */
	(int (*)()) mdb_tgt_notsup,			/* t_add_sysexit */
	(int (*)()) mdb_tgt_notsup,			/* t_add_signal */
	(int (*)()) mdb_tgt_notsup,			/* t_add_fault */
	(int (*)()) mdb_tgt_notsup,			/* t_getareg */
	(int (*)()) mdb_tgt_notsup,			/* t_putareg */
	(int (*)()) mdb_tgt_notsup,			/* t_stack_iter */
	(int (*)()) mdb_tgt_notsup			/* t_auxv */
};

int
mdb_lkd_tgt_create(mdb_tgt_t *t, int argc, const char *argv[])
{

	if (argc != 2)
		return (set_errno(EINVAL));

	lt_data_t *lt = mdb_zalloc(sizeof (lt_data_t), UM_SLEEP);

	lt->l_symfile = strdup(argv[0]);
	lt->l_lkdfile = strdup(argv[1]);

	lt->l_cookie = lkd_open(lt->l_symfile, lt->l_lkdfile, NULL,
	    (t->t_flags & MDB_TGT_F_RDWR) ? O_RDWR : O_RDONLY,
	    (char *)mdb.m_pname);
	if (lt->l_cookie == NULL)
		goto err;

	lt->l_fio = mdb_fdio_create_path(NULL, lt->l_symfile, O_RDONLY, 0);
	if (lt->l_fio == NULL)
		goto err;

	/*
	 * The Linux kernel's memory may be offset due to KASLR. The
	 * amount to which it is offset is defined in the "vmcoreinfo"
	 * portion of the kernel dump file, specified as KERNELOFFSET.
	 * We need this value in order to properly map the address
	 * values of symbols in the ELF kernel binary, to their actual
	 * memory location within the dump file. Thus, we read in this
	 * value from the dump file, and then store it to be used when
	 * comparing the ELF symbol values to memory locations within
	 * the kernel dump file.
	 */

	char *offset = lkd_vmcoreinfo_lookup(lt->l_cookie, "KERNELOFFSET");
	if (offset == NULL)
		goto err;

	lt->l_offset = strtoull(offset, NULL, 16);

	free(offset);

	lt->l_file = mdb_gelf_create(lt->l_fio, ET_EXEC, GF_FILE);
	if (lt->l_file == NULL)
		goto err;

	lt->l_symtab =
	    mdb_gelf_symtab_create_file(lt->l_file, SHT_SYMTAB, MDB_TGT_SYMTAB);

	lt->l_dynsym =
	    mdb_gelf_symtab_create_file(lt->l_file, SHT_DYNSYM, MDB_TGT_DYNSYM);

	t->t_ops = &lt_ops;
	t->t_data = lt;

	(void) mdb_dis_select("amd64");

	return (0);

err:
	if (lt->l_dynsym != NULL)
		mdb_gelf_symtab_destroy(lt->l_dynsym);

	if (lt->l_symtab != NULL)
		mdb_gelf_symtab_destroy(lt->l_symtab);

	if (lt->l_file != NULL)
		mdb_gelf_destroy(lt->l_file);

	if (lt->l_fio != NULL)
		mdb_io_destroy(lt->l_fio);

	if (lt->l_lkdfile != NULL)
		strfree(lt->l_lkdfile);

	if (lt->l_symfile != NULL)
		strfree(lt->l_symfile);

	if (lt->l_cookie != NULL)
		lkd_close(lt->l_cookie);

	mdb_free(lt, sizeof (lt_data_t));

	return (-1);
}
