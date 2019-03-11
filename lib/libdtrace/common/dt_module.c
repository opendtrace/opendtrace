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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 * Copyright (c) 2016, Pedro Giffuni.  All rights reserved.
 */
/*
 * Portions Copyright Microsoft Corporation.
 */

#include <sys/types.h>
#ifndef _WIN32
#ifdef illumos
#include <sys/modctl.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/sysmacros.h>
#include <sys/elf.h>
#include <sys/task.h>
#else
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/stat.h>
#endif
#endif
#include <unistd.h>
#ifdef illumos
#include <project.h>
#endif
#include <strings.h>
#include <stdlib.h>
#include <libelf.h>
#include <limits.h>
#include <assert.h>
#include <errno.h>
#include <dirent.h>
#if !defined(illumos) && !defined(_WIN32)
#include <fcntl.h>
#include <libproc_compat.h>
#endif

#include <dt_strtab.h>
#include <dt_module.h>
#include <dt_impl.h>

#ifdef _WIN32

#include <cvconst.h>
#include <oaidl.h>


struct dt_strmap_table_entry {
    struct dt_strmap_table_entry* next;
    char string[1];
};

struct dt_strmap_table {
    intptr_t buckets;
    struct dt_strmap_table_entry* entries[1];
};

static void*
dt_strmap_create(int buckets)
{
	size_t size =
		sizeof(intptr_t) +
		sizeof(struct dt_strmap_table_entry*) * buckets;

	struct dt_strmap_table* table = malloc(size);
	if (NULL != table) {
		memset(table, 0, size);
		table->buckets = buckets;
	}

	return table;
}

static void
dt_strmap_destroy(void* map)
{
	struct dt_strmap_table* table = (struct dt_strmap_table*)map;
	int i;
	for (i = 0; i < table->buckets; i++) {
		struct dt_strmap_table_entry* entry = table->entries[i];
		struct dt_strmap_table_entry* next;
		while (NULL != entry) {
			next = entry->next;
			free(entry);
			entry = next;
		}
	}

	free(table);
	return;
}

static const char*
dt_strmap_add(void* map, const char* str)
{
	struct dt_strmap_table* table = (struct dt_strmap_table*)map;
	ulong_t hash = dt_strtab_hash(str, NULL);
	struct dt_strmap_table_entry* p;
	struct dt_strmap_table_entry** pentry =
	    &table->entries[hash % table->buckets];

	while (NULL != (p = *pentry)) {
		if (!strcmp(str, p->string)) {
			return p->string;
		}

		pentry = &p->next;
	}

	p = malloc(sizeof(struct dt_strmap_table_entry*) + strlen(str) + 1);
	if (NULL == p) {
		return NULL;
	}

	p->next = NULL;
	strcpy(p->string, str);
	*pentry = p;
	return p->string;
}

struct dt_idmap {
	int growby;
	int size;
	_Field_size_opt_(size) uint32_t* p2c;
};

static void
dt_idmap_destroy(void* pmap)
{
	struct dt_idmap* map = (struct dt_idmap*)pmap;
	assert(NULL != map);

	if (NULL != map->p2c) {
		free(map->p2c);
	}
	free(map);
	return;
}

static void*
dt_idmap_create(int growby)
{
	struct dt_idmap* map;
	uint32_t i;

	map = malloc(sizeof(struct dt_idmap));
	if (NULL == map) {
		goto exit;
	}

	map->growby = map->size = growby;
	map->p2c = malloc(map->size * sizeof(uint32_t));
	if (NULL == map->p2c) {
		dt_idmap_destroy(map);
		map = NULL;
		goto exit;
	}

	for (i = 0; i < map->size; i++) {
		map->p2c[i] = CTF_ERR;
	}

exit:
	return map;
}

static int
dt_idmap_add(void* pmap, ULONG PdbIndex, ctf_id_t id)
{
	struct dt_idmap* map = (struct dt_idmap*)pmap;
	uint32_t idmax = PdbIndex;
	uint32_t *p2cnew;
	uint32_t i;

	assert(CTF_ERR != id);

	if (idmax >= map->size) {
		idmax += map->growby;
		if (idmax < map->size) {
			return -1;
		}
		p2cnew = realloc(map->p2c, idmax * sizeof(uint32_t));
		if (NULL == p2cnew) {
			return -1;
		}

		for (i = map->size; i < idmax; i += 1) {
			p2cnew[i] = CTF_ERR;
		}

		map->p2c = p2cnew;
		map->size = idmax;
	}

	_Analysis_assume_(PdbIndex < map->size);
	map->p2c[PdbIndex] = id;
	return 0;
}

static ctf_id_t
dt_idmap_p2c(void* pmap, ULONG PdbIndex)
{
	struct dt_idmap* map = (struct dt_idmap*)pmap;
	assert(NULL != map);
	if (PdbIndex >= map->size) {
		return CTF_ERR;
	}
	return map->p2c[PdbIndex];
}

static uint_t
dt_module_syminit(dt_module_t *dmp)
{
	if (-1 == dmp->dm_symbol_base) {
		return 0;
	}

	if (0 == dmp->dm_symbol_base) {
		BOOL RedirectionDisabled;
		PVOID OldRedirectionDisabled;
		RedirectionDisabled = Wow64DisableWow64FsRedirection(&OldRedirectionDisabled);
		dmp->dm_symbol_base = SymLoadModuleEx(dmp->dm_prochandle,
						      NULL,
						      dmp->dm_file,
						      NULL,
						      dmp->dm_image_base,
						      0,
						      NULL,
						      0);
		if (RedirectionDisabled) {
			Wow64RevertWow64FsRedirection(OldRedirectionDisabled);
		}
		if (0 == dmp->dm_symbol_base) {
			return 0;
		}
	}

	if (NULL == dmp->dm_strmap) {
		dmp->dm_strmap = dt_strmap_create(_dtrace_strbuckets);
		if (NULL == dmp->dm_strmap) {
			return 0;
		}
	}

	if (NULL == dmp->dm_idmap) {
		dmp->dm_idmap = dt_idmap_create(_dtrace_strbuckets);
		if (NULL == dmp->dm_idmap) {
			return 0;
		}
	}

	return 1;
}

static GElf_Sym *
dt_module_symlookup(dt_module_t *dmp, GElf_Addr addr, const char *name,
    GElf_Sym *symp, uint_t *idp)
{
	struct {
		SYMBOL_INFO s;
		char buf[256];
	} sym = {0};
	DWORD64 disp;

	if (!dt_module_syminit(dmp)) {
		return NULL;
	}

	sym.s.SizeOfStruct = sizeof(SYMBOL_INFO);
	sym.s.MaxNameLen = sizeof(sym.buf);

	if (NULL == name) {
		addr = dmp->dm_symbol_base + (addr - dmp->dm_image_base);
		if (!SymFromAddr(dmp->dm_prochandle, addr, &disp, &sym.s)) {
			dt_dprintf("failed to locate symbol at %p in '%s'\n",
				   (void*)(intptr_t)addr, dmp->dm_file);
			return NULL;
		}
	} else {
		if (!SymFromName(dmp->dm_prochandle, name, &sym.s)) {
			dt_dprintf("failed to locate symbol '%s' in '%s'\n",
				   name, dmp->dm_file);
			return NULL;
		}
	}

	symp->st_namep = dt_strmap_add(dmp->dm_strmap, sym.s.Name);
	if (NULL == symp->st_namep) {
		return NULL;
	}

	symp->st_value = dmp->dm_image_base + (sym.s.Address - sym.s.ModBase);
	symp->st_size = sym.s.Size;
	symp->st_type_idx = sym.s.TypeIndex;
	symp->st_tag = sym.s.Tag;
	*idp = sym.s.Index;

	return symp;
}

static GElf_Sym *
dt_module_symaddr(dt_module_t *dmp, GElf_Addr addr,
    GElf_Sym *symp, uint_t *idp)
{
	return dt_module_symlookup(dmp, addr, NULL, symp, idp);
}

static GElf_Sym *
dt_module_symname(dt_module_t *dmp, const char *name,
    GElf_Sym *symp, uint_t *idp)
{
	return dt_module_symlookup(dmp, 0, name, symp, idp);
}

static ctf_id_t
dt_module_import_type(dt_module_t *dmp, const char *name, ULONG typeIdx);

static char*
dt_module_symbol_name(dt_module_t *dmp, uint32_t type_idx, void** nameStorage)
{
	WCHAR* symNameW = NULL;
	char* symName;
	int i;

	if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, type_idx,
			    TI_GET_SYMNAME, &symNameW) ||
	    (NULL == symNameW)) {

		dt_dprintf("failed to locate symbol by type %d in '%s'\n",
			   type_idx, dmp->dm_file);
		*nameStorage = NULL;
		return NULL;
	}

	symName = (char*)symNameW;
	for (i = 0; ; i += 1) {
		if (0 == (symName[i] = (char)symNameW[i])) {
			break;
		}
	}

	*nameStorage = symNameW;
	return symName;
}

static ctf_id_t
dt_module_import_basetype(dt_module_t *dmp, ULONG typeIdx)
{
	ULONG baseType;
	ULONG64 length;
	ctf_id_t symIdx = CTF_ERR;
	ctf_encoding_t enc = {0};
	uint_t kind;
	char* name;
        int sign = 0;

	if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, typeIdx,
			    TI_GET_BASETYPE, &baseType)) {
		dt_dprintf("failed to get basetype for type %d in '%s'\n",
			   typeIdx, dmp->dm_file);
		goto exit;
	}

	if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, typeIdx,
			    TI_GET_LENGTH, &length)) {
		dt_dprintf("failed to get size for type %d in '%s'\n",
			   typeIdx, dmp->dm_file);
		goto exit;
	}

	switch (baseType) {
	case btWChar:
	case btChar:
		enc.cte_format = CTF_INT_SIGNED | CTF_INT_CHAR;
		enc.cte_bits = length * 8;
		switch (length) {
		case 1:
			name = "char";
			break;

		case 2:
			name = "wchar_t";
			break;

		default:
			dt_dprintf("failed to import base type %08lx length %08lx\n", baseType, length);
			goto exit;
		}

		symIdx = ctf_add_integer(dmp->dm_ctfp, CTF_ADD_ROOT, name, &enc);
		break;

	case btVoid:
	case btInt:
	case btLong:
		enc.cte_format = CTF_INT_SIGNED;
		sign = 1;
	case btUInt:
	case btULong:
		assert(((btULong != baseType) && (btLong != baseType)) || (length == 4));
		enc.cte_bits = length * 8;
		switch (length) {
		case 0:
			name = "void";
			break;

		case 1:
			name = sign ? "char" : "unsigned char";
			enc.cte_format |= CTF_INT_CHAR;
			break;

		case 2:
			name = sign ? "short" : "unsigned short";
			break;

		case 4:
			name = sign ? "long" : "unsigned long";
			break;

		case 8:
			name = sign ? "long long" : "unsigned long long";
			break;

		default:
			dt_dprintf("failed to import base type %08lx length %08lx\n", baseType, length);
			goto exit;
		}

		symIdx = ctf_add_integer(dmp->dm_ctfp, CTF_ADD_ROOT, name, &enc);
		break;

	case btFloat :
		enc.cte_bits = length * 8;
		switch (length) {
		case 4:
			name = "float";
			enc.cte_format = CTF_FP_SINGLE;
			break;

		case 8:
			enc.cte_format = CTF_FP_DOUBLE;
			name = "double";
			break;

		default:
			dt_dprintf("failed to import base type %08lx length %08lx\n", baseType, length);
			goto exit;
		}

		symIdx = ctf_add_float(dmp->dm_ctfp, CTF_ADD_ROOT, name, &enc);
		break;

	case btBool:
		enc.cte_format = CTF_INT_BOOL;
		enc.cte_bits = length * 8;
		switch (length) {
		case 1:
			name = "bool";
			break;

		case 4:
			name = "BOOL";
			break;

		default:
			dt_dprintf("failed to import base type %08lx length %08lx\n", baseType, length);
			goto exit;
		}

		symIdx = ctf_add_integer(dmp->dm_ctfp, CTF_ADD_ROOT, name, &enc);
		break;

	case btHresult:
		enc.cte_format = CTF_INT_SIGNED;
		enc.cte_bits = 32;
		symIdx = ctf_add_integer(dmp->dm_ctfp, CTF_ADD_ROOT, "HRESULT", &enc);
		break;

	default:
		dt_dprintf("failed to import base type %08lx length %08lx\n", baseType, length);
		goto exit;
	}

	if (CTF_ERR == symIdx) {
		goto exit;
	}

	if (0 != dt_idmap_add(dmp->dm_idmap, typeIdx, symIdx)) {
		ctf_delete_type(dmp->dm_ctfp, symIdx);
		symIdx = CTF_ERR;
		goto exit;
	}

exit:
	return symIdx;
}

static ctf_id_t
dt_module_import_bitfield(dt_module_t *dmp, ULONG typeIdx)
{
	ULONG bitPos;
	ULONG64 bitLength;
	ctf_id_t typeId = CTF_ERR;
	ctf_encoding_t enc = {0};

	if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, typeIdx,
			    TI_GET_BITPOSITION, &bitPos)) {
		goto exit;
	}

	if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, typeIdx,
			    TI_GET_LENGTH, &bitLength)) {
		dt_dprintf("failed to get bitfield length for type %d in '%s'\n",
			   typeIdx, dmp->dm_file);
		goto exit;
	}

	enc.cte_offset = bitPos;
	enc.cte_bits = bitLength;
	typeId = ctf_add_integer(dmp->dm_ctfp, CTF_ADD_ROOT, NULL, &enc);
	if (CTF_ERR == typeId) {
		goto exit;
	}

	ctf_update(dmp->dm_ctfp);

exit:
	return typeId;
}

static ctf_id_t
dt_module_import_udt(dt_module_t *dmp, ULONG typeIdx)
{
	char* symName;
	void* nameStorage = NULL;
	ctf_id_t symIdx = CTF_ERR;
	ctf_id_t symIdxChild;
	TI_FINDCHILDREN_PARAMS* children = NULL;
	ULONG childCount;
	ULONG childIdx;
	ULONG childTypeIdx;
	ULONG childOffset;
	ULONG i;
	ULONG udtKind;
	ULONG64 offset;

	symName = dt_module_symbol_name(dmp, typeIdx, &nameStorage);

	if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, typeIdx,
			    TI_GET_UDTKIND, &udtKind)) {
		dt_dprintf("failed to get udt kind for type %d in '%s'\n",
			   typeIdx, dmp->dm_file);
		goto exit;
	}

	switch (udtKind) {
	case UdtStruct:
	case UdtClass:
	case UdtInterface:
		symIdx = ctf_add_struct(dmp->dm_ctfp, CTF_ADD_ROOT, symName);
		break;

	case UdtUnion:
		symIdx = ctf_add_union(dmp->dm_ctfp, CTF_ADD_ROOT, symName);
		break;

	default:
		goto exit;
	}

	if (CTF_ERR == symIdx) {
		goto exit;
	}

	if (0 != dt_idmap_add(dmp->dm_idmap, typeIdx, symIdx)) {
		ctf_delete_type(dmp->dm_ctfp, symIdx);
		symIdx = CTF_ERR;
		goto exit;
	}

	if (NULL != nameStorage) {
		LocalFree(nameStorage);
		nameStorage = NULL;
	}

	if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, typeIdx,
			    TI_GET_CHILDRENCOUNT, &childCount) || (0 == childCount)) {

		goto exit;
	}

	children = malloc(sizeof(TI_FINDCHILDREN_PARAMS) + childCount * sizeof(ULONG));
	if (NULL == children) {
		goto exit;
	}

	children->Count = childCount;
	children->Start = 0;

	if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, typeIdx,
			    TI_FINDCHILDREN, children)) {
		dt_dprintf("failed to get fields for type %d in '%s'\n",
			   typeIdx, dmp->dm_file);
		goto exit;
	}

	for (i = 0; i < childCount; i++) {
		childIdx = children->ChildId[i];

		if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, childIdx,
				TI_GET_OFFSET, &childOffset)) {
			continue;
		}

		if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, childIdx,
				TI_GET_TYPEID, &childTypeIdx)) {
			dt_dprintf("failed to get type for child %d of type %d in '%s'\n",
				   childIdx, typeIdx, dmp->dm_file);
			goto exit;
		}

		symIdxChild = dt_module_import_bitfield(dmp, childIdx);
		if (CTF_ERR == symIdxChild) {
			symIdxChild = dt_module_import_type(dmp, NULL, childTypeIdx);
			if (CTF_ERR == symIdxChild) {
				goto exit;
			}
		}

		symName = dt_module_symbol_name(dmp, childIdx, &nameStorage);

		if (0 != ctf_add_member_at(dmp->dm_ctfp, symIdx, symName,
					   symIdxChild, childOffset)) {
			goto exit;
		}

		LocalFree(nameStorage);
		nameStorage = NULL;
	}

exit:
	if (NULL != nameStorage) {
		LocalFree(nameStorage);
	}

	if (NULL != children) {
		free(children);
	}

	return symIdx;
}

static ctf_id_t
dt_module_import_typedef(dt_module_t *dmp, ULONG typeIdx)
{
	char* symName;
	void* nameStorage = NULL;
	ctf_id_t symIdx = CTF_ERR;
	ctf_id_t symIdxType;
	ULONG typeIdxType;

	if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, typeIdx,
			    TI_GET_TYPEID, &typeIdxType)) {
		dt_dprintf("failed to get typedef type for %d in '%s'\n",
			   typeIdx, dmp->dm_file);
		goto exit;
	}

	symIdxType = dt_module_import_type(dmp, NULL, typeIdxType);
	if (CTF_ERR == symIdxType) {
		goto exit;
	}

	symName = dt_module_symbol_name(dmp, typeIdx, &nameStorage);

	symIdx = ctf_add_typedef(dmp->dm_ctfp, CTF_ADD_ROOT, symName, symIdxType);
	if (CTF_ERR == symIdx) {
		goto exit;
	}

	if (0 != dt_idmap_add(dmp->dm_idmap, typeIdx, symIdx)) {
		ctf_delete_type(dmp->dm_ctfp, symIdx);
		symIdx = CTF_ERR;
		goto exit;
	}

exit:
	if (NULL != nameStorage) {
		LocalFree(nameStorage);
	}

	return symIdx;
}

static ctf_id_t
dt_module_import_pointer(dt_module_t *dmp, ULONG typeIdx)
{
	ctf_id_t symIdx = CTF_ERR;
	ctf_id_t symIdxType = CTF_ERR;
	ULONG typeIdxType;

	if (0 != typeIdx) {
		if (SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, typeIdx,
				   TI_GET_TYPEID, &typeIdxType) &&
		    (0 != typeIdxType)) {
			symIdxType = dt_module_import_type(dmp, NULL, typeIdxType);
		}
	}

	if (CTF_ERR == symIdxType) {
		/* Pointers work with a fallback to undefined type */
		ctf_encoding_t enc = {0};
		char buf[32];
		snprintf(buf, sizeof(buf), "__notype__%lx", typeIdx);
		symIdxType = ctf_add_integer(dmp->dm_ctfp, CTF_ADD_ROOT, buf, &enc);
		if (CTF_ERR == symIdxType) {
			goto exit;
		}

		ctf_update(dmp->dm_ctfp);
	}

	symIdx = ctf_type_pointer(dmp->dm_ctfp, symIdxType);
	if (CTF_ERR == symIdx) {
		symIdx = ctf_add_pointer(dmp->dm_ctfp, CTF_ADD_ROOT, symIdxType);
		if (CTF_ERR == symIdx) {
			goto exit;
		}
	}

	if (0 != dt_idmap_add(dmp->dm_idmap, typeIdx, symIdx)) {
		ctf_delete_type(dmp->dm_ctfp, symIdx);
		symIdx = CTF_ERR;
		goto exit;
	}

exit:
	return symIdx;
}

static ctf_id_t
dt_module_import_function(dt_module_t *dmp, ULONG typeIdx)
{
	ctf_id_t symIdx = CTF_ERR;
	ctf_funcinfo_t finfo = {0};
	ULONG typeIdxReturn;
	TI_FINDCHILDREN_PARAMS* params = NULL;
	ctf_id_t* paramsIdx = NULL;
	ULONG paramCount;
	ULONG param;
	ULONG paramTypeIdx;
	ULONG i;
	ULONG baseType;

	if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, typeIdx,
			    TI_GET_TYPEID, &typeIdxReturn)) {
		dt_dprintf("failed to get return function type for %d in '%s'\n",
			   typeIdx, dmp->dm_file);
		goto exit;
	}

	finfo.ctc_return = dt_module_import_type(dmp, NULL, typeIdxReturn);
	if (CTF_ERR == finfo.ctc_return) {
		goto exit;
	}

	if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, typeIdx,
			    TI_GET_CHILDRENCOUNT, &paramCount)) {
		dt_dprintf("failed to get param count for function type %d in '%s'\n",
			   typeIdx, dmp->dm_file);
		goto exit;
	}

	if (0 != paramCount) {
		paramsIdx = malloc(paramCount * sizeof(ctf_id_t));
		if (NULL == paramsIdx) {
			goto exit;
		}

		params = malloc(sizeof(TI_FINDCHILDREN_PARAMS) + paramCount * sizeof(ULONG));
		if (NULL == params) {
			goto exit;
		}

		params->Count = paramCount;
		params->Start = 0;

		if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, typeIdx,
				    TI_FINDCHILDREN, params)) {
			dt_dprintf("failed to get params for function type %d in '%s'\n",
				   typeIdx, dmp->dm_file);
			goto exit;
		}

		for (i = 0; i < paramCount; i++) {
			param = params->ChildId[i];
			if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, param,
					    TI_GET_TYPEID, &paramTypeIdx)) {
				dt_dprintf("failed to get param type for function type %d in '%s'\n",
					   typeIdx, dmp->dm_file);
				goto exit;
			}

			if (((i + 1) == paramCount) &&
			    SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, paramTypeIdx,
					   TI_GET_BASETYPE, &baseType) &&
			    (btNoType == baseType)) {

				finfo.ctc_flags |= CTF_FUNC_VARARG;
				paramCount -= 1;
				break;
			}

			paramsIdx[i] = dt_module_import_type(dmp, NULL, paramTypeIdx);
			if (CTF_ERR == paramsIdx[i]) {
				goto exit;
			}
		}
	}

	finfo.ctc_argc = paramCount;
	symIdx = ctf_add_function(dmp->dm_ctfp, CTF_ADD_ROOT, &finfo, paramsIdx);
	if (CTF_ERR == symIdx) {
		goto exit;
	}

	if (0 != dt_idmap_add(dmp->dm_idmap, typeIdx, symIdx)) {
		ctf_delete_type(dmp->dm_ctfp, symIdx);
		symIdx = CTF_ERR;
		goto exit;
	}

exit:

	if (NULL != paramsIdx) {
		free(paramsIdx);
	}

	if (NULL != params) {
		free(params);
	}

	return symIdx;
}

static ctf_id_t
dt_module_import_array(dt_module_t *dmp, ULONG typeIdx)
{
	ctf_id_t symIdx = CTF_ERR;
	ctf_arinfo_t ainfo = {0};
	ULONG typeIdxElement;
	ULONG typeIdxIndex;
	ULONG64 length;
	ULONG64 lengthElement;

	if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, typeIdx,
			    TI_GET_TYPEID, &typeIdxElement)) {
		dt_dprintf("failed to get array element type for %d in '%s'\n",
			   typeIdx, dmp->dm_file);
		goto exit;
	}

	if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, typeIdxElement,
			    TI_GET_LENGTH, &lengthElement)) {
		dt_dprintf("failed to get element size for %d in '%s'\n",
			   typeIdx, dmp->dm_file);
		goto exit;
	}

	if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, typeIdx,
			    TI_GET_LENGTH, &length)) {
		dt_dprintf("failed to get array size for %d in '%s'\n",
			   typeIdx, dmp->dm_file);
		goto exit;
	}

	if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, typeIdx,
			    TI_GET_ARRAYINDEXTYPEID, &typeIdxIndex)) {
		dt_dprintf("failed to get array index type for %d in '%s'\n",
			   typeIdx, dmp->dm_file);
		goto exit;
	}

	ainfo.ctr_contents = dt_module_import_type(dmp, NULL, typeIdxElement);
	if (CTF_ERR == ainfo.ctr_contents) {
		goto exit;
	}

	ainfo.ctr_index = dt_module_import_type(dmp, NULL, typeIdxIndex);
	if (CTF_ERR == ainfo.ctr_index) {
		goto exit;
	}

	if (0 != length && 0 != lengthElement) {
		ainfo.ctr_nelems = length / lengthElement;
	}

	symIdx = ctf_add_array(dmp->dm_ctfp, CTF_ADD_ROOT, &ainfo);
	if (CTF_ERR == symIdx) {
		goto exit;
	}

	if (0 != dt_idmap_add(dmp->dm_idmap, typeIdx, symIdx)) {
		ctf_delete_type(dmp->dm_ctfp, symIdx);
		symIdx = CTF_ERR;
		goto exit;
	}

exit:
	return symIdx;
}

static ctf_id_t
dt_module_import_enum(dt_module_t *dmp, ULONG typeIdx)
{
	char* symName;
	void* nameStorage = NULL;
	ctf_id_t symIdx = CTF_ERR;
	TI_FINDCHILDREN_PARAMS* children = NULL;
	ULONG childCount;
	ULONG childIdx;
	ULONG i;
	VARIANT v = {0};
	int value;

	symName = dt_module_symbol_name(dmp, typeIdx, &nameStorage);

	symIdx = ctf_add_enum(dmp->dm_ctfp, CTF_ADD_ROOT, symName);
	if (CTF_ERR == symIdx) {
		goto exit;
	}

	if (0 != dt_idmap_add(dmp->dm_idmap, typeIdx, symIdx)) {
		ctf_delete_type(dmp->dm_ctfp, symIdx);
		symIdx = CTF_ERR;
		goto exit;
	}

	LocalFree(nameStorage);
	nameStorage = NULL;

	if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, typeIdx,
			    TI_GET_CHILDRENCOUNT, &childCount) || (0 == childCount)) {
		dt_dprintf("failed to get enum size for %d in '%s'\n",
			   typeIdx, dmp->dm_file);
		goto exit;
	}

	children = malloc(sizeof(TI_FINDCHILDREN_PARAMS) + childCount * sizeof(ULONG));
	if (NULL == children) {
		goto exit;
	}

	children->Count = childCount;
	children->Start = 0;

	if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, typeIdx,
			    TI_FINDCHILDREN, children)) {
		dt_dprintf("failed to get enum elements for %d in '%s'\n",
			   typeIdx, dmp->dm_file);
		goto exit;
	}

	for (i = 0; i < childCount; i++) {
		childIdx = children->ChildId[i];
		if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, childIdx,
				    TI_GET_VALUE, &v)) {
			dt_dprintf("failed to get enum element for %d in '%s'\n",
				   typeIdx, dmp->dm_file);
			goto exit;
		}

		if (NULL == (symName = dt_module_symbol_name(dmp, childIdx, &nameStorage))) {
			goto exit;
		}

		switch (V_VT(&v)) {
		case VT_I1: case VT_UI1:
			value = V_I1(&v);
			break;
		case VT_I2: case VT_UI2:
			value = V_I2(&v);
			break;
		case VT_I4: case VT_UI4:
			value = V_I4(&v);
			break;
		default:
			dt_dprintf("unsupported type %04lx of the enum for '%s'\n", V_VT(&v), symName);
			goto exit;
		}

		if (CTF_ERR == ctf_add_enumerator(dmp->dm_ctfp, symIdx, symName, value)) {
			goto exit;
		}

		LocalFree(nameStorage);
		nameStorage = NULL;
	}

exit:
	if (NULL != nameStorage) {
		LocalFree(nameStorage);
	}

	if (NULL != children) {
		free(children);
	}

	return symIdx;
}

static BOOL CALLBACK
dt_module_type_enum_callback(PSYMBOL_INFO SymInfo, ULONG Size,
			     PVOID UserContext)
{
	*(uint32_t*)UserContext = SymInfo->Index;
	return FALSE;
}

extern void ctf_set_no_type_errno(ctf_file_t *);

static ctf_id_t
dt_module_import_type(dt_module_t *dmp, const char *name, ULONG typeIdx)
{
	ULONG symTag;
	ctf_id_t symIdx = CTF_ERR;

	if (NULL == dmp->dm_file) {
		goto exit;
	}

	if (!dt_module_syminit(dmp)) {
		goto exit;
	}

	if (NULL != name) {
		typeIdx = 0;
		if (!SymEnumTypesByName(dmp->dm_prochandle, dmp->dm_symbol_base,
					name, dt_module_type_enum_callback, &typeIdx) ||
		    (0 == typeIdx)) {
			dt_dprintf("failed to find type '%s' in '%s'\n",
				   name, dmp->dm_file);
			goto exit;
		}
	}

	symIdx = dt_idmap_p2c(dmp->dm_idmap, typeIdx);
	if (CTF_ERR != symIdx) {
		goto exit;
	}

	if (0 == typeIdx) {
		/*
		 * Create and use a dummy pointer type for index '0' to provide
		 * limited support for type-stripped PDBs
		 */

		symIdx = dt_module_import_pointer(dmp, 0);
		ctf_update(dmp->dm_ctfp);
		goto exit;
	}

	if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base, typeIdx,
			    TI_GET_SYMTAG, &symTag)) {

		dt_dprintf("failed to get type tag  %d' in '%s'\n",
			   typeIdx, dmp->dm_file);
		goto exit;
	}

	switch (symTag) {
	case SymTagBaseType:
		symIdx = dt_module_import_basetype(dmp, typeIdx);
		break;

	case SymTagUDT:
		symIdx = dt_module_import_udt(dmp, typeIdx);
		break;

	case SymTagTypedef:
		symIdx = dt_module_import_typedef(dmp, typeIdx);
		break;

	case SymTagPointerType:
		symIdx = dt_module_import_pointer(dmp, typeIdx);
		break;

	case SymTagFunctionType:
		symIdx = dt_module_import_function(dmp, typeIdx);
		break;

	case SymTagArrayType:
		symIdx = dt_module_import_array(dmp, typeIdx);
		break;

	case SymTagEnum:
		symIdx = dt_module_import_enum(dmp, typeIdx);
		break;

	default:
		dt_dprintf("unsupported tag %04lx\n", symTag);
		goto exit;
	}

	ctf_update(dmp->dm_ctfp);

exit:
	if (CTF_ERR == symIdx && NULL != dmp->dm_ctfp) {
		ctf_set_no_type_errno(dmp->dm_ctfp);
	}
	return symIdx;
}

static BOOL CALLBACK
dt_module_enumtypes_proc(PSYMBOL_INFO SymInfo, ULONG  SymbolSize, PVOID UserContext)
{
	dt_module_t *dmp = (dt_module_t *)UserContext;
	dt_module_import_type(dmp, NULL, SymInfo->TypeIndex);
	return TRUE;
}

static int
dt_module_import_types(dt_module_t *dmp)
{
	SymEnumTypes(dmp->dm_prochandle, dmp->dm_symbol_base,
		     dt_module_enumtypes_proc, dmp);
	return 0;
}

ctf_id_t
dt_module_function_typeid(dt_module_t *dmp, const char *name)
{
	GElf_Sym sym;
	uint_t symid;
	if (NULL == dt_module_symname(dmp, name, &sym, &symid))
		return CTF_ERR;

	ULONG SymTag;
	if (!SymGetTypeInfo(dmp->dm_prochandle, dmp->dm_symbol_base,
			    sym.st_type_idx, TI_GET_SYMTAG, &SymTag))
		return CTF_ERR;

	if (SymTagFunctionType != SymTag)
		return CTF_ERR;

	return dt_module_import_type(dmp, NULL, sym.st_type_idx);
}

#else

static const char *dt_module_strtab; /* active strtab for qsort callbacks */

static void
dt_module_symhash_insert(dt_module_t *dmp, const char *name, uint_t id)
{
	dt_sym_t *dsp = &dmp->dm_symchains[dmp->dm_symfree];
	uint_t h;

	assert(dmp->dm_symfree < dmp->dm_nsymelems + 1);

	dsp->ds_symid = id;
	h = dt_strtab_hash(name, NULL) % dmp->dm_nsymbuckets;
	dsp->ds_next = dmp->dm_symbuckets[h];
	dmp->dm_symbuckets[h] = dmp->dm_symfree++;
}

static uint_t
dt_module_syminit32(dt_module_t *dmp)
{
#if STT_NUM != (STT_TLS + 1)
#error "STT_NUM has grown. update dt_module_syminit32()"
#endif

	Elf32_Sym *sym = dmp->dm_symtab.cts_data;
	const char *base = dmp->dm_strtab.cts_data;
	size_t ss_size = dmp->dm_strtab.cts_size;
	uint_t i, n = dmp->dm_nsymelems;
	uint_t asrsv = 0;

#if defined(__FreeBSD__)
	GElf_Ehdr ehdr;
	int is_elf_obj;

	gelf_getehdr(dmp->dm_elf, &ehdr);
	is_elf_obj = (ehdr.e_type == ET_REL);
#endif

	for (i = 0; i < n; i++, sym++) {
		const char *name = base + sym->st_name;
		uchar_t type = ELF32_ST_TYPE(sym->st_info);

		if (type >= STT_NUM || type == STT_SECTION)
			continue; /* skip sections and unknown types */

		if (sym->st_name == 0 || sym->st_name >= ss_size)
			continue; /* skip null or invalid names */

		if (sym->st_value != 0 &&
		    (ELF32_ST_BIND(sym->st_info) != STB_LOCAL || sym->st_size)) {
			asrsv++; /* reserve space in the address map */

#if defined(__FreeBSD__)
			sym->st_value += (Elf_Addr) dmp->dm_reloc_offset;
			if (is_elf_obj && sym->st_shndx != SHN_UNDEF &&
			    sym->st_shndx < ehdr.e_shnum)
				sym->st_value +=
				    dmp->dm_sec_offsets[sym->st_shndx];
#endif
		}

		dt_module_symhash_insert(dmp, name, i);
	}

	return (asrsv);
}

static uint_t
dt_module_syminit64(dt_module_t *dmp)
{
#if STT_NUM != (STT_TLS + 1)
#error "STT_NUM has grown. update dt_module_syminit64()"
#endif

	Elf64_Sym *sym = dmp->dm_symtab.cts_data;
	const char *base = dmp->dm_strtab.cts_data;
	size_t ss_size = dmp->dm_strtab.cts_size;
	uint_t i, n = dmp->dm_nsymelems;
	uint_t asrsv = 0;

#if defined(__FreeBSD__)
	GElf_Ehdr ehdr;
	int is_elf_obj;

	gelf_getehdr(dmp->dm_elf, &ehdr);
	is_elf_obj = (ehdr.e_type == ET_REL);
#endif

	for (i = 0; i < n; i++, sym++) {
		const char *name = base + sym->st_name;
		uchar_t type = ELF64_ST_TYPE(sym->st_info);

		if (type >= STT_NUM || type == STT_SECTION)
			continue; /* skip sections and unknown types */

		if (sym->st_name == 0 || sym->st_name >= ss_size)
			continue; /* skip null or invalid names */

		if (sym->st_value != 0 &&
		    (ELF64_ST_BIND(sym->st_info) != STB_LOCAL || sym->st_size)) {
			asrsv++; /* reserve space in the address map */
#if defined(__FreeBSD__)
			sym->st_value += (Elf_Addr) dmp->dm_reloc_offset;
			if (is_elf_obj && sym->st_shndx != SHN_UNDEF &&
			    sym->st_shndx < ehdr.e_shnum)
				sym->st_value +=
				    dmp->dm_sec_offsets[sym->st_shndx];
#endif
		}

		dt_module_symhash_insert(dmp, name, i);
	}

	return (asrsv);
}

/*
 * Sort comparison function for 32-bit symbol address-to-name lookups.	We sort
 * symbols by value.  If values are equal, we prefer the symbol that is
 * non-zero sized, typed, not weak, or lexically first, in that order.
 */
static int
dt_module_symcomp32(const void *lp, const void *rp)
{
	Elf32_Sym *lhs = *((Elf32_Sym **)lp);
	Elf32_Sym *rhs = *((Elf32_Sym **)rp);

	if (lhs->st_value != rhs->st_value)
		return (lhs->st_value > rhs->st_value ? 1 : -1);

	if ((lhs->st_size == 0) != (rhs->st_size == 0))
		return (lhs->st_size == 0 ? 1 : -1);

	if ((ELF32_ST_TYPE(lhs->st_info) == STT_NOTYPE) !=
	    (ELF32_ST_TYPE(rhs->st_info) == STT_NOTYPE))
		return (ELF32_ST_TYPE(lhs->st_info) == STT_NOTYPE ? 1 : -1);

	if ((ELF32_ST_BIND(lhs->st_info) == STB_WEAK) !=
	    (ELF32_ST_BIND(rhs->st_info) == STB_WEAK))
		return (ELF32_ST_BIND(lhs->st_info) == STB_WEAK ? 1 : -1);

	return (strcmp(dt_module_strtab + lhs->st_name,
	    dt_module_strtab + rhs->st_name));
}

/*
 * Sort comparison function for 64-bit symbol address-to-name lookups.	We sort
 * symbols by value.  If values are equal, we prefer the symbol that is
 * non-zero sized, typed, not weak, or lexically first, in that order.
 */
static int
dt_module_symcomp64(const void *lp, const void *rp)
{
	Elf64_Sym *lhs = *((Elf64_Sym **)lp);
	Elf64_Sym *rhs = *((Elf64_Sym **)rp);

	if (lhs->st_value != rhs->st_value)
		return (lhs->st_value > rhs->st_value ? 1 : -1);

	if ((lhs->st_size == 0) != (rhs->st_size == 0))
		return (lhs->st_size == 0 ? 1 : -1);

	if ((ELF64_ST_TYPE(lhs->st_info) == STT_NOTYPE) !=
	    (ELF64_ST_TYPE(rhs->st_info) == STT_NOTYPE))
		return (ELF64_ST_TYPE(lhs->st_info) == STT_NOTYPE ? 1 : -1);

	if ((ELF64_ST_BIND(lhs->st_info) == STB_WEAK) !=
	    (ELF64_ST_BIND(rhs->st_info) == STB_WEAK))
		return (ELF64_ST_BIND(lhs->st_info) == STB_WEAK ? 1 : -1);

	return (strcmp(dt_module_strtab + lhs->st_name,
	    dt_module_strtab + rhs->st_name));
}

static void
dt_module_symsort32(dt_module_t *dmp)
{
	Elf32_Sym *symtab = (Elf32_Sym *)dmp->dm_symtab.cts_data;
	Elf32_Sym **sympp = (Elf32_Sym **)dmp->dm_asmap;
	const dt_sym_t *dsp = dmp->dm_symchains + 1;
	uint_t i, n = dmp->dm_symfree;

	for (i = 1; i < n; i++, dsp++) {
		Elf32_Sym *sym = symtab + dsp->ds_symid;
		if (sym->st_value != 0 &&
		    (ELF32_ST_BIND(sym->st_info) != STB_LOCAL || sym->st_size))
			*sympp++ = sym;
	}

	dmp->dm_aslen = (uint_t)(sympp - (Elf32_Sym **)dmp->dm_asmap);
	assert(dmp->dm_aslen <= dmp->dm_asrsv);

	dt_module_strtab = dmp->dm_strtab.cts_data;
	qsort(dmp->dm_asmap, dmp->dm_aslen,
	    sizeof (Elf32_Sym *), dt_module_symcomp32);
	dt_module_strtab = NULL;
}

static void
dt_module_symsort64(dt_module_t *dmp)
{
	Elf64_Sym *symtab = (Elf64_Sym *)dmp->dm_symtab.cts_data;
	Elf64_Sym **sympp = (Elf64_Sym **)dmp->dm_asmap;
	const dt_sym_t *dsp = dmp->dm_symchains + 1;
	uint_t i, n = dmp->dm_symfree;

	for (i = 1; i < n; i++, dsp++) {
		Elf64_Sym *sym = symtab + dsp->ds_symid;
		if (sym->st_value != 0 &&
		    (ELF64_ST_BIND(sym->st_info) != STB_LOCAL || sym->st_size))
			*sympp++ = sym;
	}

	dmp->dm_aslen = (uint_t)(sympp - (Elf64_Sym **)dmp->dm_asmap);
	assert(dmp->dm_aslen <= dmp->dm_asrsv);

	dt_module_strtab = dmp->dm_strtab.cts_data;
	qsort(dmp->dm_asmap, dmp->dm_aslen,
	    sizeof (Elf64_Sym *), dt_module_symcomp64);
	dt_module_strtab = NULL;
}

static GElf_Sym *
dt_module_symgelf32(const Elf32_Sym *src, GElf_Sym *dst)
{
	if (dst != NULL) {
		dst->st_name = src->st_name;
		dst->st_info = src->st_info;
		dst->st_other = src->st_other;
		dst->st_shndx = src->st_shndx;
		dst->st_value = src->st_value;
		dst->st_size = src->st_size;
	}

	return (dst);
}

static GElf_Sym *
dt_module_symgelf64(const Elf64_Sym *src, GElf_Sym *dst)
{
	if (dst != NULL)
		bcopy(src, dst, sizeof (GElf_Sym));

	return (dst);
}

static GElf_Sym *
dt_module_symname32(dt_module_t *dmp, const char *name,
    GElf_Sym *symp, uint_t *idp)
{
	const Elf32_Sym *symtab = dmp->dm_symtab.cts_data;
	const char *strtab = dmp->dm_strtab.cts_data;

	const Elf32_Sym *sym;
	const dt_sym_t *dsp;
	uint_t i, h;

	if (dmp->dm_nsymelems == 0)
		return (NULL);

	h = dt_strtab_hash(name, NULL) % dmp->dm_nsymbuckets;

	for (i = dmp->dm_symbuckets[h]; i != 0; i = dsp->ds_next) {
		dsp = &dmp->dm_symchains[i];
		sym = symtab + dsp->ds_symid;

		if (strcmp(name, strtab + sym->st_name) == 0) {
			if (idp != NULL)
				*idp = dsp->ds_symid;
			return (dt_module_symgelf32(sym, symp));
		}
	}

	return (NULL);
}

static GElf_Sym *
dt_module_symname64(dt_module_t *dmp, const char *name,
    GElf_Sym *symp, uint_t *idp)
{
	const Elf64_Sym *symtab = dmp->dm_symtab.cts_data;
	const char *strtab = dmp->dm_strtab.cts_data;

	const Elf64_Sym *sym;
	const dt_sym_t *dsp;
	uint_t i, h;

	if (dmp->dm_nsymelems == 0)
		return (NULL);

	h = dt_strtab_hash(name, NULL) % dmp->dm_nsymbuckets;

	for (i = dmp->dm_symbuckets[h]; i != 0; i = dsp->ds_next) {
		dsp = &dmp->dm_symchains[i];
		sym = symtab + dsp->ds_symid;

		if (strcmp(name, strtab + sym->st_name) == 0) {
			if (idp != NULL)
				*idp = dsp->ds_symid;
			return (dt_module_symgelf64(sym, symp));
		}
	}

	return (NULL);
}

static GElf_Sym *
dt_module_symaddr32(dt_module_t *dmp, GElf_Addr addr,
    GElf_Sym *symp, uint_t *idp)
{
	const Elf32_Sym **asmap = (const Elf32_Sym **)dmp->dm_asmap;
	const Elf32_Sym *symtab = dmp->dm_symtab.cts_data;
	const Elf32_Sym *sym;

	uint_t i, mid, lo = 0, hi = dmp->dm_aslen - 1;
	Elf32_Addr v;

	if (dmp->dm_aslen == 0)
		return (NULL);

	while (hi - lo > 1) {
		mid = (lo + hi) / 2;
		if (addr >= asmap[mid]->st_value)
			lo = mid;
		else
			hi = mid;
	}

	i = addr < asmap[hi]->st_value ? lo : hi;
	sym = asmap[i];
	v = sym->st_value;

	/*
	 * If the previous entry has the same value, improve our choice.  The
	 * order of equal-valued symbols is determined by the comparison func.
	 */
	while (i-- != 0 && asmap[i]->st_value == v)
		sym = asmap[i];

	if (addr - sym->st_value < MAX(sym->st_size, 1)) {
		if (idp != NULL)
			*idp = (uint_t)(sym - symtab);
		return (dt_module_symgelf32(sym, symp));
	}

	return (NULL);
}

static GElf_Sym *
dt_module_symaddr64(dt_module_t *dmp, GElf_Addr addr,
    GElf_Sym *symp, uint_t *idp)
{
	const Elf64_Sym **asmap = (const Elf64_Sym **)dmp->dm_asmap;
	const Elf64_Sym *symtab = dmp->dm_symtab.cts_data;
	const Elf64_Sym *sym;

	uint_t i, mid, lo = 0, hi = dmp->dm_aslen - 1;
	Elf64_Addr v;

	if (dmp->dm_aslen == 0)
		return (NULL);

	while (hi - lo > 1) {
		mid = (lo + hi) / 2;
		if (addr >= asmap[mid]->st_value)
			lo = mid;
		else
			hi = mid;
	}

	i = addr < asmap[hi]->st_value ? lo : hi;
	sym = asmap[i];
	v = sym->st_value;

	/*
	 * If the previous entry has the same value, improve our choice.  The
	 * order of equal-valued symbols is determined by the comparison func.
	 */
	while (i-- != 0 && asmap[i]->st_value == v)
		sym = asmap[i];

	if (addr - sym->st_value < MAX(sym->st_size, 1)) {
		if (idp != NULL)
			*idp = (uint_t)(sym - symtab);
		return (dt_module_symgelf64(sym, symp));
	}

	return (NULL);
}

static const dt_modops_t dt_modops_32 = {
	dt_module_syminit32,
	dt_module_symsort32,
	dt_module_symname32,
	dt_module_symaddr32
};

static const dt_modops_t dt_modops_64 = {
	dt_module_syminit64,
	dt_module_symsort64,
	dt_module_symname64,
	dt_module_symaddr64
};

#endif

#ifdef _WIN32
dt_module_t *
dt_module_lookup_by_name_ext(dtrace_hdl_t *dtp, const char *name)
{
	size_t match_len;
	uint_t n, i;
	dt_module_t *dmp;

	dmp = dt_list_next(&dtp->dt_modlist);
	n = dtp->dt_nmods;

	if (strrchr(name, '.') != NULL) {
		for (; n > 0; n--, dmp = dt_list_next(dmp)) {
			if (_stricmp(dmp->dm_name, name) == 0)
				return (dmp);
		}

	} else {
		match_len = strlen(name);
		for (; n > 0; n--, dmp = dt_list_next(dmp)) {
			if ((_strnicmp(dmp->dm_name, name, match_len) == 0) &&
			    (('\0' == dmp->dm_name[match_len]) ||
			     ((dmp->dm_name + match_len) == strrchr(dmp->dm_name, '.')))) {
				return (dmp);
			}
		}
	}

	return NULL;
}
#endif

dt_module_t *
dt_module_lookup_by_name(dtrace_hdl_t *dtp, const char *name)
{
	uint_t h = dt_strtab_hash(name, NULL) % dtp->dt_modbuckets;
	dt_module_t *dmp;

	for (dmp = dtp->dt_mods[h]; dmp != NULL; dmp = dmp->dm_next) {
		if (strcmp(dmp->dm_name, name) == 0)
			return (dmp);
	}

#ifdef _WIN32
	if ((dmp = dt_module_lookup_by_name_ext(dtp, name)) != NULL)
		return (dmp);
#endif

	return (NULL);
}

dt_module_t *
dt_module_create(dtrace_hdl_t *dtp, const char *name)
{
	long pid;
	char *eptr;
	dt_ident_t *idp;
	uint_t h;
	dt_module_t *dmp;

	if ((dmp = dt_module_lookup_by_name(dtp, name)) != NULL)
		return (dmp);

	if ((dmp = malloc(sizeof (dt_module_t))) == NULL)
		return (NULL); /* caller must handle allocation failure */

	h = dt_strtab_hash(name, NULL) % dtp->dt_modbuckets;
	bzero(dmp, sizeof (dt_module_t));
	(void) strlcpy(dmp->dm_name, name, sizeof (dmp->dm_name));
	dt_list_append(&dtp->dt_modlist, dmp);
	dmp->dm_next = dtp->dt_mods[h];
	dtp->dt_mods[h] = dmp;
	dtp->dt_nmods++;

#ifndef _WIN32
	if (dtp->dt_conf.dtc_ctfmodel == CTF_MODEL_LP64)
		dmp->dm_ops = &dt_modops_64;
	else
		dmp->dm_ops = &dt_modops_32;
#endif

	/*
	 * Modules for userland processes are special. They always refer to a
	 * specific process and have a copy of their CTF data from a specific
	 * instant in time. Any dt_module_t that begins with 'pid' is a module
	 * for a specific process, much like how any probe description that
	 * begins with 'pid' is special. pid123 refers to process 123. A module
	 * that is just 'pid' refers specifically to pid$target. This is
	 * generally done as D does not currently allow for macros to be
	 * evaluated when working with types.
	 */
	if (strncmp(dmp->dm_name, "pid", 3) == 0) {
		errno = 0;
		if (dmp->dm_name[3] == '\0') {
			idp = dt_idhash_lookup(dtp->dt_macros, "target");
			if (idp != NULL && idp->di_id != 0)
				dmp->dm_pid = idp->di_id;
		} else {
			pid = strtol(dmp->dm_name + 3, &eptr, 10);
			if (errno == 0 && *eptr == '\0')
				dmp->dm_pid = (pid_t)pid;
			else
				dt_dprintf("encountered malformed pid "
				    "module: %s\n", dmp->dm_name);
		}
	}

	return (dmp);
}

/*ARGSUSED*/
dt_module_t *
dt_module_lookup_by_ctf(dtrace_hdl_t *dtp, ctf_file_t *ctfp)
{
	return (ctfp ? ctf_getspecific(ctfp) : NULL);
}

#ifndef _WIN32

#ifdef __FreeBSD__
dt_kmodule_t *
dt_kmodule_lookup(dtrace_hdl_t *dtp, const char *name)
{
	uint_t h = dt_strtab_hash(name, NULL) % dtp->dt_modbuckets;
	dt_kmodule_t *dkmp;

	for (dkmp = dtp->dt_kmods[h]; dkmp != NULL; dkmp = dkmp->dkm_next) {
		if (strcmp(dkmp->dkm_name, name) == 0)
			return (dkmp);
	}

	return (NULL);
}
#endif

static int
dt_module_load_sect(dtrace_hdl_t *dtp, dt_module_t *dmp, ctf_sect_t *ctsp)
{
	const char *s;
	size_t shstrs;
	GElf_Shdr sh;
	Elf_Data *dp;
	Elf_Scn *sp;

	if (elf_getshdrstrndx(dmp->dm_elf, &shstrs) == -1)
		return (dt_set_errno(dtp, EDT_NOTLOADED));

	for (sp = NULL; (sp = elf_nextscn(dmp->dm_elf, sp)) != NULL; ) {
		if (gelf_getshdr(sp, &sh) == NULL || sh.sh_type == SHT_NULL ||
		    (s = elf_strptr(dmp->dm_elf, shstrs, sh.sh_name)) == NULL)
			continue; /* skip any malformed sections */

		if (sh.sh_type == ctsp->cts_type &&
		    sh.sh_entsize == ctsp->cts_entsize &&
		    strcmp(s, ctsp->cts_name) == 0)
			break; /* section matches specification */
	}

	/*
	 * If the section isn't found, return success but leave cts_data set
	 * to NULL and cts_size set to zero for our caller.
	 */
	if (sp == NULL || (dp = elf_getdata(sp, NULL)) == NULL)
		return (0);

#ifdef illumos
	ctsp->cts_data = dp->d_buf;
#else
	if ((ctsp->cts_data = malloc(dp->d_size)) == NULL)
		return (0);
	memcpy(ctsp->cts_data, dp->d_buf, dp->d_size);
#endif
	ctsp->cts_size = dp->d_size;

	dt_dprintf("loaded %s [%s] (%lu bytes)\n",
	    dmp->dm_name, ctsp->cts_name, (ulong_t)ctsp->cts_size);

	return (0);
}

typedef struct dt_module_cb_arg {
	struct ps_prochandle *dpa_proc;
	dtrace_hdl_t *dpa_dtp;
	dt_module_t *dpa_dmp;
	uint_t dpa_count;
} dt_module_cb_arg_t;

/* ARGSUSED */
static int
dt_module_load_proc_count(void *arg, const prmap_t *prmap, const char *obj)
{
	ctf_file_t *fp;
	dt_module_cb_arg_t *dcp = arg;

	/* Try to grab a ctf container if it exists */
	fp = Pname_to_ctf(dcp->dpa_proc, obj);
	if (fp != NULL)
		dcp->dpa_count++;
	return (0);
}

/* ARGSUSED */
static int
dt_module_load_proc_build(void *arg, const prmap_t *prmap, const char *obj)
{
	ctf_file_t *fp;
	char buf[MAXPATHLEN], *p;
	dt_module_cb_arg_t *dcp = arg;
	int count = dcp->dpa_count;
	Lmid_t lmid;

	fp = Pname_to_ctf(dcp->dpa_proc, obj);
	if (fp == NULL)
		return (0);
	fp = ctf_dup(fp);
	if (fp == NULL)
		return (0);
	dcp->dpa_dmp->dm_libctfp[count] = fp;
	/*
	 * While it'd be nice to simply use objname here, because of our prior
	 * actions we'll always get a resolved object name to its on disk file.
	 * Like the pid provider, we need to tell a bit of a lie here. The type
	 * that the user thinks of is in terms of the libraries they requested,
	 * eg. libc.so.1, they don't care about the fact that it's
	 * libc_hwcap.so.1.
	 */
	(void) Pobjname(dcp->dpa_proc, prmap->pr_vaddr, buf, sizeof (buf));
	if ((p = strrchr(buf, '/')) == NULL)
		p = buf;
	else
		p++;

	/*
	 * If for some reason we can't find a link map id for this module, which
	 * would be really quite weird. We instead just say the link map id is
	 * zero.
	 */
	if (Plmid(dcp->dpa_proc, prmap->pr_vaddr, &lmid) != 0)
		lmid = 0;

	if (lmid == 0)
		dcp->dpa_dmp->dm_libctfn[count] = strdup(p);
	else
		(void) asprintf(&dcp->dpa_dmp->dm_libctfn[count],
		    "LM%x`%s", lmid, p);
	if (dcp->dpa_dmp->dm_libctfn[count] == NULL)
		return (1);
	ctf_setspecific(fp, dcp->dpa_dmp);
	dcp->dpa_count++;
	return (0);
}

/*
 * We've been asked to load data that belongs to another process. As such we're

 * going to pgrab it at this instant, load everything that we might ever care
 * about, and then drive on. The reason for this is that the process that we're
 * interested in might be changing. As long as we have grabbed it, then this
 * can't be a problem for us.
 *
 * For now, we're actually going to punt on most things and just try to get CTF
 * data, nothing else. Basically this is only useful as a source of type
 * information, we can't go and do the stacktrace lookups, etc.
 */
static int
dt_module_load_proc(dtrace_hdl_t *dtp, dt_module_t *dmp)
{
	struct ps_prochandle *p;
	dt_module_cb_arg_t arg;

	/*
	 * Note that on success we do not release this hold. We must hold this
	 * for our life time.
	 */
	p = dt_proc_grab(dtp, dmp->dm_pid, 0, PGRAB_RDONLY | PGRAB_FORCE);
	if (p == NULL) {
		dt_dprintf("failed to grab pid: %d\n", (int)dmp->dm_pid);
		return (dt_set_errno(dtp, EDT_CANTLOAD));
	}
	dt_proc_lock(dtp, p);

	arg.dpa_proc = p;
	arg.dpa_dtp = dtp;
	arg.dpa_dmp = dmp;
	arg.dpa_count = 0;
	if (Pobject_iter_resolved(p, dt_module_load_proc_count, &arg) != 0) {
		dt_dprintf("failed to iterate objects\n");
		dt_proc_unlock(dtp, p);
		dt_proc_release(dtp, p);
		return (dt_set_errno(dtp, EDT_CANTLOAD));
	}

	if (arg.dpa_count == 0) {
		dt_dprintf("no ctf data present\n");
		dt_proc_unlock(dtp, p);
		dt_proc_release(dtp, p);
		return (dt_set_errno(dtp, EDT_CANTLOAD));
	}

	dmp->dm_libctfp = calloc(arg.dpa_count, sizeof (ctf_file_t *));
	if (dmp->dm_libctfp == NULL) {
		dt_proc_unlock(dtp, p);
		dt_proc_release(dtp, p);
		return (dt_set_errno(dtp, EDT_NOMEM));
	}

	dmp->dm_libctfn = calloc(arg.dpa_count, sizeof (char *));
	if (dmp->dm_libctfn == NULL) {
		free(dmp->dm_libctfp);
		dt_proc_unlock(dtp, p);
		dt_proc_release(dtp, p);
		return (dt_set_errno(dtp, EDT_NOMEM));
	}

	dmp->dm_nctflibs = arg.dpa_count;

	arg.dpa_count = 0;
	if (Pobject_iter_resolved(p, dt_module_load_proc_build, &arg) != 0) {
		dt_proc_unlock(dtp, p);
		dt_module_unload(dtp, dmp);
		dt_proc_release(dtp, p);
		return (dt_set_errno(dtp, EDT_CANTLOAD));
	}
	assert(arg.dpa_count == dmp->dm_nctflibs);
	dt_dprintf("loaded %d ctf modules for pid %d\n", arg.dpa_count,
	    (int)dmp->dm_pid);

	dt_proc_unlock(dtp, p);
	dt_proc_release(dtp, p);
	dmp->dm_flags |= DT_DM_LOADED;

	return (0);
}

#else

typedef struct dt_module_cb_arg {
	dtrace_hdl_t *dpa_dtp;
	dt_module_t *dpa_dmp;
	uint_t dpa_allocated;
} dt_module_cb_arg_t;

static BOOL CALLBACK dt_module_load_proc_EnumModulesCallback(PCSTR ModuleName, DWORD64 BaseOfDll, PVOID UserContext)
{
	dt_module_cb_arg_t* ctx = (dt_module_cb_arg_t*)UserContext;
	dt_module_t *dmp;
	dt_module_t **newp;
	const uint_t incr = 10;
	IMAGEHLP_MODULE64 ihm = {0};

	ihm.SizeOfStruct = sizeof(ihm);
	if (!SymGetModuleInfo64(ctx->dpa_dmp->dm_prochandle, BaseOfDll, &ihm)) {
		return TRUE;
	}

	if (ctx->dpa_allocated == ctx->dpa_dmp->dm_npidmods) {
		newp = realloc(ctx->dpa_dmp->dm_pidmods,
			       (sizeof(dt_module_t *) *
				(ctx->dpa_allocated + incr)));
		if (NULL == newp) {
			return TRUE;
		}
		ctx->dpa_dmp->dm_pidmods = newp;
                ctx->dpa_allocated += incr;
	}

	if ((dmp = malloc(sizeof (dt_module_t))) == NULL) {
		return TRUE;
	}

	bzero(dmp, sizeof (dt_module_t));
	(void) strlcpy(dmp->dm_name, ihm.ModuleName, sizeof (dmp->dm_name));
	(void) strlcpy(dmp->dm_file, ihm.ImageName, sizeof (dmp->dm_file));
	dmp->dm_prochandle = ctx->dpa_dmp->dm_prochandle;
	dmp->dm_image_base = BaseOfDll;
	dmp->dm_symbol_base = dmp->dm_image_base;
	dmp->dm_flags |= DT_DM_LOADED;

	ctx->dpa_dmp->dm_pidmods[ctx->dpa_dmp->dm_npidmods++] = dmp;
	return TRUE;
}

static int
dt_module_load_proc(dtrace_hdl_t *dtp, dt_module_t *dmp)
{
	dmp->dm_phdl = dt_proc_grab(dtp, dmp->dm_pid, 0, PGRAB_RDONLY | PGRAB_FORCE);
	if (dmp->dm_phdl == NULL) {
		dt_dprintf("failed to grab pid: %d\n", (int)dmp->dm_pid);
		return (dt_set_errno(dtp, EDT_CANTLOAD));
	}

	dmp->dm_prochandle = proc_gethandle(dmp->dm_phdl);

	dt_module_cb_arg_t ctx;
	ctx.dpa_dtp = dtp;
	ctx.dpa_dmp = dmp;
	ctx.dpa_allocated = 0;

	if (!SymEnumerateModules64(dmp->dm_prochandle,
				   dt_module_load_proc_EnumModulesCallback,
				   &ctx)) {
		dt_dprintf("failed to list modules for pid: %d\n", (int)dmp->dm_pid);
		dt_proc_release(dtp, dmp->dm_phdl);
		dmp->dm_phdl = NULL;
		dmp->dm_prochandle = NULL;
		return (dt_set_errno(dtp, EDT_CANTLOAD));
	}

	dt_dprintf("loaded %d ctf modules for pid %d\n", dmp->dm_npidmods,
	    (int)dmp->dm_pid);

	dmp->dm_flags |= DT_DM_LOADED;
	return (0);
}

#endif

int
dt_module_load(dtrace_hdl_t *dtp, dt_module_t *dmp)
{
	if (dmp->dm_flags & DT_DM_LOADED)
		return (0); /* module is already loaded */

	if (dmp->dm_pid != 0)
		return (dt_module_load_proc(dtp, dmp));

#ifdef _WIN32
	dmp->dm_prochandle = GetCurrentProcess();

	if (dmp->dm_flags & DT_DM_KERNEL) {
		dmp->dm_flags |= DT_DM_LOADED;
		return 0;
	}

	if ('\0' == dmp->dm_file[0]) {
		HMODULE Mod = GetModuleHandleA(dmp->dm_name);
		if (NULL != Mod) {
			dmp->dm_image_base = (GElf_Addr)(ULONG_PTR)Mod;
			GetModuleFileNameA(Mod, dmp->dm_file, MAXPATHLEN);
		}
	}

	if ('\0' == dmp->dm_file[0]) {
		PVOID OldRedirectionDisabled;
		BOOL RedirectionDisabled =
		    Wow64DisableWow64FsRedirection(&OldRedirectionDisabled);
		DWORD len = SearchPathA(NULL, dmp->dm_name, NULL,
					MAXPATHLEN, dmp->dm_file, NULL);
		if (RedirectionDisabled) {
			Wow64RevertWow64FsRedirection(OldRedirectionDisabled);
		}

		if ((0 == len) || (len >= MAXPATHLEN)) {
			dmp->dm_file[0] = '\0';
		}
	}

	if ('\0' == dmp->dm_file[0]) {
		strcpy(dmp->dm_file, dmp->dm_name);
	}

	if (!dt_module_syminit(dmp)) {
		return (dt_set_errno(dtp, EDT_NOMOD));
	}

	dmp->dm_flags |= DT_DM_LOADED;
	return 0;
#else

	dmp->dm_ctdata.cts_name = ".SUNW_ctf";
	dmp->dm_ctdata.cts_type = SHT_PROGBITS;
	dmp->dm_ctdata.cts_flags = 0;
	dmp->dm_ctdata.cts_data = NULL;
	dmp->dm_ctdata.cts_size = 0;
	dmp->dm_ctdata.cts_entsize = 0;
	dmp->dm_ctdata.cts_offset = 0;

	dmp->dm_symtab.cts_name = ".symtab";
	dmp->dm_symtab.cts_type = SHT_SYMTAB;
	dmp->dm_symtab.cts_flags = 0;
	dmp->dm_symtab.cts_data = NULL;
	dmp->dm_symtab.cts_size = 0;
	dmp->dm_symtab.cts_entsize = dmp->dm_ops == &dt_modops_64 ?
	    sizeof (Elf64_Sym) : sizeof (Elf32_Sym);
	dmp->dm_symtab.cts_offset = 0;

	dmp->dm_strtab.cts_name = ".strtab";
	dmp->dm_strtab.cts_type = SHT_STRTAB;
	dmp->dm_strtab.cts_flags = 0;
	dmp->dm_strtab.cts_data = NULL;
	dmp->dm_strtab.cts_size = 0;
	dmp->dm_strtab.cts_entsize = 0;
	dmp->dm_strtab.cts_offset = 0;

	/*
	 * Attempt to load the module's CTF section, symbol table section, and
	 * string table section.  Note that modules may not contain CTF data:
	 * this will result in a successful load_sect but data of size zero.
	 * We will then fail if dt_module_getctf() is called, as shown below.
	 */
	if (dt_module_load_sect(dtp, dmp, &dmp->dm_ctdata) == -1 ||
	    dt_module_load_sect(dtp, dmp, &dmp->dm_symtab) == -1 ||
	    dt_module_load_sect(dtp, dmp, &dmp->dm_strtab) == -1) {
		dt_module_unload(dtp, dmp);
		return (-1); /* dt_errno is set for us */
	}

	/*
	 * Allocate the hash chains and hash buckets for symbol name lookup.
	 * This is relatively simple since the symbol table is of fixed size
	 * and is known in advance.  We allocate one extra element since we
	 * use element indices instead of pointers and zero is our sentinel.
	 */
	dmp->dm_nsymelems =
	    dmp->dm_symtab.cts_size / dmp->dm_symtab.cts_entsize;

	dmp->dm_nsymbuckets = _dtrace_strbuckets;
	dmp->dm_symfree = 1;		/* first free element is index 1 */

	dmp->dm_symbuckets = calloc(dmp->dm_nsymbuckets, sizeof (uint_t));
	dmp->dm_symchains = calloc(dmp->dm_nsymelems + 1, sizeof (dt_sym_t));

	if (dmp->dm_symbuckets == NULL || dmp->dm_symchains == NULL) {
		dt_module_unload(dtp, dmp);
		return (dt_set_errno(dtp, EDT_NOMEM));
	}

	/*
	 * Iterate over the symbol table data buffer and insert each symbol
	 * name into the name hash if the name and type are valid.  Then
	 * allocate the address map, fill it in, and sort it.
	 */
	dmp->dm_asrsv = dmp->dm_ops->do_syminit(dmp);

	dt_dprintf("hashed %s [%s] (%u symbols)\n",
	    dmp->dm_name, dmp->dm_symtab.cts_name, dmp->dm_symfree - 1);

	if ((dmp->dm_asmap = malloc(sizeof (void *) * dmp->dm_asrsv)) == NULL) {
		dt_module_unload(dtp, dmp);
		return (dt_set_errno(dtp, EDT_NOMEM));
	}

	dmp->dm_ops->do_symsort(dmp);

	dt_dprintf("sorted %s [%s] (%u symbols)\n",
	    dmp->dm_name, dmp->dm_symtab.cts_name, dmp->dm_aslen);

	dmp->dm_flags |= DT_DM_LOADED;
	return (0);
#endif
}

int
dt_module_hasctf(dtrace_hdl_t *dtp, dt_module_t *dmp)
{
#ifdef _WIN32
	if (dmp->dm_pid != 0 && dmp->dm_npidmods > 0)
		return (1);
#else
	if (dmp->dm_pid != 0 && dmp->dm_nctflibs > 0)
		return (1);
#endif
	return (dt_module_getctf(dtp, dmp) != NULL);
}

ctf_file_t *
dt_module_getctf(dtrace_hdl_t *dtp, dt_module_t *dmp)
{
	const char *parent;
	dt_module_t *pmp;
	ctf_file_t *pfp;
	int model;

	if (dmp->dm_ctfp != NULL || dt_module_load(dtp, dmp) != 0)
		return (dmp->dm_ctfp);

#ifdef _WIN32

	model = CTF_MODEL_NATIVE;

	if (dtp->dt_conf.dtc_ctfmodel != model) {
		(void) dt_set_errno(dtp, EDT_DATAMODEL);
		return (NULL);
	}

	dmp->dm_ctfp = ctf_create(&dtp->dt_ctferr);
	if (dmp->dm_ctfp == NULL) {
		(void) dt_set_errno(dtp, EDT_CTF);
		return (NULL);
	}

	/* Too expensice - types will be imported as needed */
	/*dt_module_import_types(dmp);*/

#else

	if (dmp->dm_ops == &dt_modops_64)
		model = CTF_MODEL_LP64;
	else
		model = CTF_MODEL_ILP32;

	/*
	 * If the data model of the module does not match our program data
	 * model, then do not permit CTF from this module to be opened and
	 * returned to the compiler.  If we support mixed data models in the
	 * future for combined kernel/user tracing, this can be removed.
	 */
	if (dtp->dt_conf.dtc_ctfmodel != model) {
		(void) dt_set_errno(dtp, EDT_DATAMODEL);
		return (NULL);
	}

	if (dmp->dm_ctdata.cts_size == 0) {
		(void) dt_set_errno(dtp, EDT_NOCTF);
		return (NULL);
	}

	dmp->dm_ctfp = ctf_bufopen(&dmp->dm_ctdata,
	    &dmp->dm_symtab, &dmp->dm_strtab, &dtp->dt_ctferr);

	if (dmp->dm_ctfp == NULL) {
		(void) dt_set_errno(dtp, EDT_CTF);
		return (NULL);
	}

#endif

	(void) ctf_setmodel(dmp->dm_ctfp, model);
	ctf_setspecific(dmp->dm_ctfp, dmp);

	if ((parent = ctf_parent_name(dmp->dm_ctfp)) != NULL) {
		if ((pmp = dt_module_create(dtp, parent)) == NULL ||
		    (pfp = dt_module_getctf(dtp, pmp)) == NULL) {
			if (pmp == NULL)
				(void) dt_set_errno(dtp, EDT_NOMEM);
			goto err;
		}

		if (ctf_import(dmp->dm_ctfp, pfp) == CTF_ERR) {
			dtp->dt_ctferr = ctf_errno(dmp->dm_ctfp);
			(void) dt_set_errno(dtp, EDT_CTF);
			goto err;
		}
	}

	dt_dprintf("loaded CTF container for %s (%p)\n",
	    dmp->dm_name, (void *)dmp->dm_ctfp);

	return (dmp->dm_ctfp);

err:
	ctf_close(dmp->dm_ctfp);
	dmp->dm_ctfp = NULL;

	return (NULL);
}

/*ARGSUSED*/
void
dt_module_unload(dtrace_hdl_t *dtp, dt_module_t *dmp)
{
	int i;

	ctf_close(dmp->dm_ctfp);
	dmp->dm_ctfp = NULL;

#if !defined(illumos) && !defined(_WIN32)
	if (dmp->dm_ctdata.cts_data != NULL) {
		free(dmp->dm_ctdata.cts_data);
	}
	if (dmp->dm_symtab.cts_data != NULL) {
		free(dmp->dm_symtab.cts_data);
	}
	if (dmp->dm_strtab.cts_data != NULL) {
		free(dmp->dm_strtab.cts_data);
	}
#endif

#ifdef _WIN32
	if (dmp->dm_pidmods != NULL) {
		for (i = 0; i < dmp->dm_npidmods; i++) {
			if (dmp != dmp->dm_pidmods[i]) {
				dt_module_unload(dtp, dmp->dm_pidmods[i]);
				free(dmp->dm_pidmods[i]);
			}
		}
		free(dmp->dm_pidmods);
		dmp->dm_pidmods = NULL;
		dmp->dm_npidmods = 0;
	}
#else
	if (dmp->dm_libctfp != NULL) {
		for (i = 0; i < dmp->dm_nctflibs; i++) {
			ctf_close(dmp->dm_libctfp[i]);
			free(dmp->dm_libctfn[i]);
		}
		free(dmp->dm_libctfp);
		free(dmp->dm_libctfn);
		dmp->dm_libctfp = NULL;
		dmp->dm_nctflibs = 0;
	}
#endif

#ifndef _WIN32
	bzero(&dmp->dm_ctdata, sizeof (ctf_sect_t));
	bzero(&dmp->dm_symtab, sizeof (ctf_sect_t));
	bzero(&dmp->dm_strtab, sizeof (ctf_sect_t));

	if (dmp->dm_symbuckets != NULL) {
		free(dmp->dm_symbuckets);
		dmp->dm_symbuckets = NULL;
	}

	if (dmp->dm_symchains != NULL) {
		free(dmp->dm_symchains);
		dmp->dm_symchains = NULL;
	}

	if (dmp->dm_asmap != NULL) {
		free(dmp->dm_asmap);
		dmp->dm_asmap = NULL;
	}
#if defined(__FreeBSD__)
	if (dmp->dm_sec_offsets != NULL) {
		free(dmp->dm_sec_offsets);
		dmp->dm_sec_offsets = NULL;
	}
#endif
	dmp->dm_symfree = 0;
	dmp->dm_nsymbuckets = 0;
	dmp->dm_nsymelems = 0;
	dmp->dm_asrsv = 0;
	dmp->dm_aslen = 0;
#endif

#ifdef _WIN32
	dmp->dm_image_base = 0;
	dmp->dm_image_size = 0;
#else
	dmp->dm_text_va = 0;
	dmp->dm_text_size = 0;
	dmp->dm_data_va = 0;
	dmp->dm_data_size = 0;
	dmp->dm_bss_va = 0;
	dmp->dm_bss_size = 0;
#endif

	if (dmp->dm_extern != NULL) {
		dt_idhash_destroy(dmp->dm_extern);
		dmp->dm_extern = NULL;
	}

#ifdef _WIN32
	if ((0 != dmp->dm_symbol_base) && (-1 != dmp->dm_symbol_base))
		SymUnloadModule64(dmp->dm_prochandle, dmp->dm_symbol_base);
	dmp->dm_symbol_base = 0;

	if (NULL != dmp->dm_strmap)
		dt_strmap_destroy(dmp->dm_strmap);
	dmp->dm_strmap = NULL;

	if (NULL != dmp->dm_idmap)
		dt_idmap_destroy(dmp->dm_idmap);
	dmp->dm_idmap = NULL;

	dmp->dm_prochandle = NULL;
	if (NULL != dmp->dm_phdl) {
		if (dtp->dt_procs != NULL)
			dt_proc_release(dtp, dmp->dm_phdl);
		dmp->dm_phdl = NULL;
	}
#else
	(void) elf_end(dmp->dm_elf);
	dmp->dm_elf = NULL;
#endif

	dmp->dm_pid = 0;

	dmp->dm_flags &= ~DT_DM_LOADED;
}

void
dt_module_destroy(dtrace_hdl_t *dtp, dt_module_t *dmp)
{
	uint_t h = dt_strtab_hash(dmp->dm_name, NULL) % dtp->dt_modbuckets;
	dt_module_t **dmpp = &dtp->dt_mods[h];

	dt_list_delete(&dtp->dt_modlist, dmp);
	assert(dtp->dt_nmods != 0);
	dtp->dt_nmods--;

	/*
	 * Now remove this module from its hash chain.  We expect to always
	 * find the module on its hash chain, so in this loop we assert that
	 * we don't run off the end of the list.
	 */
	while (*dmpp != dmp) {
		dmpp = &((*dmpp)->dm_next);
		assert(*dmpp != NULL);
	}

	*dmpp = dmp->dm_next;

	dt_module_unload(dtp, dmp);
	free(dmp);
}


/*
 * Insert a new external symbol reference into the specified module.  The new
 * symbol will be marked as undefined and is assigned a symbol index beyond
 * any existing cached symbols from this module.  We use the ident's di_data
 * field to store a pointer to a copy of the dtrace_syminfo_t for this symbol.
 */
dt_ident_t *
dt_module_extern(dtrace_hdl_t *dtp, dt_module_t *dmp,
    const char *name, const dtrace_typeinfo_t *tip)
{
	dtrace_syminfo_t *sip;
	dt_ident_t *idp;
	uint_t id;
	uint_t idmin;

#ifdef _WIN32
	idmin = 0x10000;
#else
	idmin = dmp->dm_nsymelems;
#endif

	if (dmp->dm_extern == NULL && (dmp->dm_extern = dt_idhash_create(
	    "extern", NULL, idmin, UINT_MAX)) == NULL) {
		(void) dt_set_errno(dtp, EDT_NOMEM);
		return (NULL);
	}

	if (dt_idhash_nextid(dmp->dm_extern, &id) == -1) {
		(void) dt_set_errno(dtp, EDT_SYMOFLOW);
		return (NULL);
	}

	if ((sip = malloc(sizeof (dtrace_syminfo_t))) == NULL) {
		(void) dt_set_errno(dtp, EDT_NOMEM);
		return (NULL);
	}

	idp = dt_idhash_insert(dmp->dm_extern, name, DT_IDENT_SYMBOL, 0, id,
	    _dtrace_symattr, 0, &dt_idops_thaw, NULL, dtp->dt_gen);

	if (idp == NULL) {
		(void) dt_set_errno(dtp, EDT_NOMEM);
		free(sip);
		return (NULL);
	}

	sip->dts_object = dmp->dm_name;
	sip->dts_name = idp->di_name;
	sip->dts_id = idp->di_id;

	idp->di_data = sip;
	idp->di_ctfp = tip->dtt_ctfp;
	idp->di_type = tip->dtt_type;

	return (idp);
}

const char *
dt_module_modelname(dt_module_t *dmp)
{
#ifdef _WIN32
#ifdef _WIN64
	return ("64-bit");
#else
	return ("32-bit");
#endif
#else
	if (dmp->dm_ops == &dt_modops_64)
		return ("64-bit");
	else
		return ("32-bit");
#endif
}

/* ARGSUSED */
int
dt_module_getlibid(dtrace_hdl_t *dtp, dt_module_t *dmp, const ctf_file_t *fp)
{
	int i;

#ifdef _WIN32
	for (i = 0; i < dmp->dm_npidmods; i++) {
		if (dmp->dm_pidmods[i]->dm_ctfp == fp)
			return (i);
	}
#else
	for (i = 0; i < dmp->dm_nctflibs; i++) {
		if (dmp->dm_libctfp[i] == fp)
			return (i);
	}
#endif

	return (-1);
}

#ifdef _WIN32
dt_module_t *
dt_module_getctfmod(dtrace_hdl_t *dtp, dt_module_t *dmp, const char *name)
{
	int i;
	size_t match_len;
	dt_module_t *dmpi;

	if (strrchr(name, '.') != NULL) {
		for (i = 0; i < dmp->dm_npidmods; i++) {
			dmpi = dmp->dm_pidmods[i];
			if (_stricmp(dmpi->dm_name, name) == 0) {
				return (dmpi);
			}
		}
	} else {
		match_len = strlen(name);
		for (i = 0; i < dmp->dm_npidmods; i++) {
			dmpi = dmp->dm_pidmods[i];
			if ((_strnicmp(dmpi->dm_name, name, match_len) == 0) &&
			    (('\0' == dmpi->dm_name[match_len]) ||
			     ((dmpi->dm_name + match_len) == strrchr(dmpi->dm_name, '.')))) {
				return (dmpi);
			}
		}
	}

	return (NULL);
}

#else

/* ARGSUSED */
ctf_file_t *
dt_module_getctflib(dtrace_hdl_t *dtp, dt_module_t *dmp, const char *name)
{
	int i;

	for (i = 0; i < dmp->dm_nctflibs; i++) {
		if (strcmp(dmp->dm_libctfn[i], name) == 0)
			return (dmp->dm_libctfp[i]);
	}

	return (NULL);
}

#endif

/*
 * Update our module cache by adding an entry for the specified module 'name'.
 * We create the dt_module_t and populate it using /system/object/<name>/.
 *
 * On FreeBSD, the module name is passed as the full module file name,
 * including the path.
 */
static void
#ifdef illumos
dt_module_update(dtrace_hdl_t *dtp, const char *name)
#elif defined(_WIN32)
dt_module_update(dtrace_hdl_t *dtp, void* base_address)
#else
dt_module_update(dtrace_hdl_t *dtp, struct kld_file_stat *k_stat)
#endif
{
#ifdef _WIN32

	dt_module_t *dmp;
	char driver_path[MAXPATHLEN];
	char* name;
	PIMAGE_NT_HEADERS headers;
	HANDLE fh = INVALID_HANDLE_VALUE;
	HANDLE section = NULL;
	PVOID view = NULL;
	BOOL RedirectionDisabled;
	PVOID OldRedirectionDisabled;

	if (!GetDeviceDriverFileNameA(base_address, driver_path, sizeof(driver_path)))
		goto exit;

	if (driver_path[0] == '\\' && driver_path[1] == '?' &&
	    driver_path[2] == '?' && driver_path[3] == '\\') {

		driver_path[1] = '\\';

	} else {
		const char SystemRootPrefix[] = "\\SystemRoot\\";
		int len;
		char expanded[MAXPATHLEN];

		if (!_strnicmp(driver_path, SystemRootPrefix,
			       sizeof(SystemRootPrefix) - 1)) {

			len = GetEnvironmentVariableA("SYSTEMROOT", expanded,
						      sizeof(expanded));

			if ((len > 0) &&
			    ((sizeof(driver_path) - len) >
			     ((strlen(driver_path) + 1) - (sizeof(SystemRootPrefix) - 3)))) {

				strcat(expanded, driver_path + (sizeof(SystemRootPrefix) - 2));
				strcpy(driver_path, expanded);
			}
		}
	}

	name = strrchr(driver_path, '\\');
	if (NULL == name)
		name = driver_path;
	else
		name += 1;

	if (!strcmp(name, "ntoskrnl.exe")) {
		name = "nt";
	}

	RedirectionDisabled = Wow64DisableWow64FsRedirection(&OldRedirectionDisabled);
	fh = CreateFileA(driver_path, GENERIC_READ,
			 (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE),
			 NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (RedirectionDisabled) {
		Wow64RevertWow64FsRedirection(OldRedirectionDisabled);
	}

	if (INVALID_HANDLE_VALUE == fh) {
		dt_dprintf("failed to open %s: %08lx\n", driver_path, GetLastError());
		goto exit;
	}

	section = CreateFileMappingW(fh, NULL, PAGE_READONLY, 0, 0, NULL);
	if (NULL == section) {
		dt_dprintf("failed to open %s: %08lx\n", driver_path, GetLastError());
		goto exit;
	}

	view = MapViewOfFile(section, FILE_MAP_READ, 0, 0, 0);
	if (NULL == view) {
		dt_dprintf("failed to open %s: %08lx\n", driver_path, GetLastError());
		goto exit;
	}

	headers = ImageNtHeader(view);
	if (NULL == headers) {
		dt_dprintf("failed to open %s: %08lx\n", driver_path, GetLastError());
		goto exit;
	}

	dmp = dt_module_create(dtp, name);
	if (NULL == dmp) {
		dt_dprintf("failed to open %s: %s\n", driver_path, strerror(errno));
		goto exit;
	}

	strcpy(dmp->dm_file, driver_path);
	dmp->dm_flags |= DT_DM_KERNEL | DT_DM_PRIMARY | DT_DM_LOADED;
	dmp->dm_image_base = (GElf_Addr)base_address;
	dmp->dm_image_size = headers->OptionalHeader.SizeOfImage;
	dmp->dm_prochandle = GetCurrentProcess();

exit:
	if (INVALID_HANDLE_VALUE != fh) {
		CloseHandle(fh);
	}

	if (NULL != section) {
		CloseHandle(section);
	}

	if (NULL != view) {
		UnmapViewOfFile(view);
	}

	return;

#else
	char fname[MAXPATHLEN];
	struct stat64 st;
	int fd, err, bits;
#ifdef __FreeBSD__
	struct module_stat ms;
	dt_kmodule_t *dkmp;
	uint_t h;
	int modid;
#endif

	dt_module_t *dmp;
	const char *s;
	size_t shstrs;
	GElf_Shdr sh;
	Elf_Data *dp;
	Elf_Scn *sp;

#ifdef illumos
	(void) snprintf(fname, sizeof (fname),
	    "%s/%s/object", OBJFS_ROOT, name);
#else
	GElf_Ehdr ehdr;
	GElf_Phdr ph;
	char name[MAXPATHLEN];
	uintptr_t mapbase, alignmask;
	int i = 0;
	int is_elf_obj;

	(void) strlcpy(name, k_stat->name, sizeof(name));
	(void) strlcpy(fname, k_stat->pathname, sizeof(fname));
#endif

	if ((fd = open(fname, O_RDONLY)) == -1 || fstat64(fd, &st) == -1 ||
	    (dmp = dt_module_create(dtp, name)) == NULL) {
		dt_dprintf("failed to open %s: %s\n", fname, strerror(errno));
		(void) close(fd);
		return;
	}

	/*
	 * Since the module can unload out from under us (and /system/object
	 * will return ENOENT), tell libelf to cook the entire file now and
	 * then close the underlying file descriptor immediately.  If this
	 * succeeds, we know that we can continue safely using dmp->dm_elf.
	 */
	dmp->dm_elf = elf_begin(fd, ELF_C_READ, NULL);
	err = elf_cntl(dmp->dm_elf, ELF_C_FDREAD);
	(void) close(fd);

	if (dmp->dm_elf == NULL || err == -1 ||
	    elf_getshdrstrndx(dmp->dm_elf, &shstrs) == -1) {
		dt_dprintf("failed to load %s: %s\n",
		    fname, elf_errmsg(elf_errno()));
		dt_module_destroy(dtp, dmp);
		return;
	}

	switch (gelf_getclass(dmp->dm_elf)) {
	case ELFCLASS32:
		dmp->dm_ops = &dt_modops_32;
		bits = 32;
		break;
	case ELFCLASS64:
		dmp->dm_ops = &dt_modops_64;
		bits = 64;
		break;
	default:
		dt_dprintf("failed to load %s: unknown ELF class\n", fname);
		dt_module_destroy(dtp, dmp);
		return;
	}
#if defined(__FreeBSD__)
	mapbase = (uintptr_t)k_stat->address;
	gelf_getehdr(dmp->dm_elf, &ehdr);
	is_elf_obj = (ehdr.e_type == ET_REL);
	if (is_elf_obj) {
		dmp->dm_sec_offsets =
		    malloc(ehdr.e_shnum * sizeof(*dmp->dm_sec_offsets));
		if (dmp->dm_sec_offsets == NULL) {
			dt_dprintf("failed to allocate memory\n");
			dt_module_destroy(dtp, dmp);
			return;
		}
	}
#endif
	/*
	 * Iterate over the section headers locating various sections of
	 * interest and use their attributes to flesh out the dt_module_t.
	 */
	for (sp = NULL; (sp = elf_nextscn(dmp->dm_elf, sp)) != NULL; ) {
		if (gelf_getshdr(sp, &sh) == NULL || sh.sh_type == SHT_NULL ||
		    (s = elf_strptr(dmp->dm_elf, shstrs, sh.sh_name)) == NULL)
			continue; /* skip any malformed sections */
#if defined(__FreeBSD__)
		if (sh.sh_size == 0)
			continue;
		if (sh.sh_type == SHT_PROGBITS || sh.sh_type == SHT_NOBITS) {
			alignmask = sh.sh_addralign - 1;
			mapbase += alignmask;
			mapbase &= ~alignmask;
			sh.sh_addr = mapbase;
			if (is_elf_obj)
				dmp->dm_sec_offsets[elf_ndxscn(sp)] = sh.sh_addr;
			mapbase += sh.sh_size;
		}
#endif
		if (strcmp(s, ".text") == 0) {
			dmp->dm_text_size = sh.sh_size;
			dmp->dm_text_va = sh.sh_addr;
		} else if (strcmp(s, ".data") == 0) {
			dmp->dm_data_size = sh.sh_size;
			dmp->dm_data_va = sh.sh_addr;
		} else if (strcmp(s, ".bss") == 0) {
			dmp->dm_bss_size = sh.sh_size;
			dmp->dm_bss_va = sh.sh_addr;
		} else if (strcmp(s, ".info") == 0 &&
		    (dp = elf_getdata(sp, NULL)) != NULL) {
			bcopy(dp->d_buf, &dmp->dm_info,
			    MIN(sh.sh_size, sizeof (dmp->dm_info)));
		} else if (strcmp(s, ".filename") == 0 &&
		    (dp = elf_getdata(sp, NULL)) != NULL) {
			(void) strlcpy(dmp->dm_file,
			    dp->d_buf, sizeof (dmp->dm_file));
		}
	}

	dmp->dm_flags |= DT_DM_KERNEL;
#ifdef illumos
	dmp->dm_modid = (int)OBJFS_MODID(st.st_ino);
#else
	/*
	 * Include .rodata and special sections into .text.
	 * This depends on default section layout produced by GNU ld
	 * for ELF objects and libraries:
	 * [Text][R/O data][R/W data][Dynamic][BSS][Non loadable]
	 */
	dmp->dm_text_size = dmp->dm_data_va - dmp->dm_text_va;
#if defined(__i386__)
	/*
	 * Find the first load section and figure out the relocation
	 * offset for the symbols. The kernel module will not need
	 * relocation, but the kernel linker modules will.
	 */
	for (i = 0; gelf_getphdr(dmp->dm_elf, i, &ph) != NULL; i++) {
		if (ph.p_type == PT_LOAD) {
			dmp->dm_reloc_offset = k_stat->address - ph.p_vaddr;
			break;
		}
	}
#endif
#endif /* illumos */

	if (dmp->dm_info.objfs_info_primary)
		dmp->dm_flags |= DT_DM_PRIMARY;

#ifdef __FreeBSD__
	ms.version = sizeof(ms);
	for (modid = kldfirstmod(k_stat->id); modid > 0;
	    modid = modnext(modid)) {
		if (modstat(modid, &ms) != 0) {
			dt_dprintf("modstat failed for id %d in %s: %s\n",
			    modid, k_stat->name, strerror(errno));
			continue;
		}
		if (dt_kmodule_lookup(dtp, ms.name) != NULL)
			continue;

		dkmp = malloc(sizeof (*dkmp));
		if (dkmp == NULL) {
			dt_dprintf("failed to allocate memory\n");
			dt_module_destroy(dtp, dmp);
			return;
		}

		h = dt_strtab_hash(ms.name, NULL) % dtp->dt_modbuckets;
		dkmp->dkm_next = dtp->dt_kmods[h];
		dkmp->dkm_name = strdup(ms.name);
		dkmp->dkm_module = dmp;
		dtp->dt_kmods[h] = dkmp;
	}
#endif

	dt_dprintf("opened %d-bit module %s (%s) [%d]\n",
	    bits, dmp->dm_name, dmp->dm_file, dmp->dm_modid);
#endif
}

/*
 * Unload all the loaded modules and then refresh the module cache with the
 * latest list of loaded modules and their address ranges.
 */
void
dtrace_update(dtrace_hdl_t *dtp)
{
	dt_module_t *dmp;
#ifdef illumos
	DIR *dirp;
#elif defined(__FreeBSD__)
	int fileid;
#elif defined(_WIN32)
	PVOID* driver_bases;
	DWORD driver_count, cb, i;
#endif

	for (dmp = dt_list_next(&dtp->dt_modlist);
	    dmp != NULL; dmp = dt_list_next(dmp))
		dt_module_unload(dtp, dmp);

#ifdef illumos
	/*
	 * Open /system/object and attempt to create a libdtrace module for
	 * each kernel module that is loaded on the current system.
	 */
	if (!(dtp->dt_oflags & DTRACE_O_NOSYS) &&
	    (dirp = opendir(OBJFS_ROOT)) != NULL) {
		struct dirent *dp;

		while ((dp = readdir(dirp)) != NULL) {
			if (dp->d_name[0] != '.')
				dt_module_update(dtp, dp->d_name);
		}

		(void) closedir(dirp);
	}

#elif defined(__FreeBSD__)

	/*
	 * Use FreeBSD's kernel loader interface to discover what kernel
	 * modules are loaded and create a libdtrace module for each one.
	 */
	for (fileid = kldnext(0); fileid > 0; fileid = kldnext(fileid)) {
		struct kld_file_stat k_stat;
		k_stat.version = sizeof(k_stat);
		if (kldstat(fileid, &k_stat) == 0)
			dt_module_update(dtp, &k_stat);
	}

#elif defined(_WIN32)

	/*
	 * Use Win32 psapi interface to enumerate all kernel modules
	 * and create a libdtrace module for each one.
	 */
	driver_bases = NULL;
	driver_count = 0;
	cb = 0;
	while (EnumDeviceDrivers(driver_bases, driver_count * sizeof(PVOID), &cb)) {
		if (cb <= driver_count * sizeof(PVOID)) {
			break;
		}

		if (driver_bases)
			free(driver_bases);
		driver_bases = malloc(cb);
		if (!driver_bases)
			break;
		driver_count = cb / sizeof(PVOID);
		cb = 0;
	}

	if (driver_bases) {
		for (i = 0; i < cb / sizeof(void*); i++) {
			dt_module_update(dtp, driver_bases[i]);
		}
		free(driver_bases);
	}

#endif

	/*
	 * Look up all the macro identifiers and set di_id to the latest value.
	 * This code collaborates with dt_lex.l on the use of di_id.  We will
	 * need to implement something fancier if we need to support non-ints.
	 */
#ifdef _WIN32
	dt_idhash_lookup(dtp->dt_macros, "pid")->di_id = GetCurrentProcessId();
	dtp->dt_exec = dt_module_lookup_by_name(dtp, "nt");
#else
	dt_idhash_lookup(dtp->dt_macros, "egid")->di_id = getegid();
	dt_idhash_lookup(dtp->dt_macros, "euid")->di_id = geteuid();
	dt_idhash_lookup(dtp->dt_macros, "gid")->di_id = getgid();
	dt_idhash_lookup(dtp->dt_macros, "pid")->di_id = getpid();
	dt_idhash_lookup(dtp->dt_macros, "pgid")->di_id = getpgid(0);
	dt_idhash_lookup(dtp->dt_macros, "ppid")->di_id = getppid();
#ifdef illumos
	dt_idhash_lookup(dtp->dt_macros, "projid")->di_id = getprojid();
#endif
	dt_idhash_lookup(dtp->dt_macros, "sid")->di_id = getsid(0);
#ifdef illumos
	dt_idhash_lookup(dtp->dt_macros, "taskid")->di_id = gettaskid();
#endif
	dt_idhash_lookup(dtp->dt_macros, "uid")->di_id = getuid();

	/*
	 * Cache the pointers to the modules representing the base executable
	 * and the run-time linker in the dtrace client handle. Note that on
	 * x86 krtld is folded into unix, so if we don't find it, use unix
	 * instead.
	 */
	dtp->dt_exec = dt_module_lookup_by_name(dtp, "genunix");
	dtp->dt_rtld = dt_module_lookup_by_name(dtp, "krtld");
	if (dtp->dt_rtld == NULL)
		dtp->dt_rtld = dt_module_lookup_by_name(dtp, "unix");
#endif
	/*
	 * If this is the first time we are initializing the module list,
	 * remove the module for genunix from the module list and then move it
	 * to the front of the module list.  We do this so that type and symbol
	 * queries encounter genunix and thereby optimize for the common case
	 * in dtrace_lookup_by_name() and dtrace_lookup_by_type(), below.
	 */
	if (dtp->dt_exec != NULL &&
	    dtp->dt_cdefs == NULL && dtp->dt_ddefs == NULL) {
		dt_list_delete(&dtp->dt_modlist, dtp->dt_exec);
		dt_list_prepend(&dtp->dt_modlist, dtp->dt_exec);
	}
}

static dt_module_t *
dt_module_from_object(dtrace_hdl_t *dtp, const char *object)
{
	int err = EDT_NOMOD;
	dt_module_t *dmp;

	switch ((uintptr_t)object) {
	case (uintptr_t)DTRACE_OBJ_EXEC:
		dmp = dtp->dt_exec;
		break;
	case (uintptr_t)DTRACE_OBJ_RTLD:
		dmp = dtp->dt_rtld;
		break;
	case (uintptr_t)DTRACE_OBJ_CDEFS:

		dmp = dtp->dt_cdefs;
		break;
	case (uintptr_t)DTRACE_OBJ_DDEFS:
		dmp = dtp->dt_ddefs;
		break;
	default:
		dmp = dt_module_create(dtp, object);
		err = EDT_NOMEM;
	}

	if (dmp == NULL)
		(void) dt_set_errno(dtp, err);

	return (dmp);
}

/*
 * Exported interface to look up a symbol by name.  We return the GElf_Sym and
 * complete symbol information for the matching symbol.
 */
int
dtrace_lookup_by_name(dtrace_hdl_t *dtp, const char *object, const char *name,
    GElf_Sym *symp, dtrace_syminfo_t *sip)
{
	dt_module_t *dmp;
	dt_ident_t *idp;
	uint_t n, id;
	GElf_Sym sym;

	uint_t mask = 0; /* mask of dt_module flags to match */
	uint_t bits = 0; /* flag bits that must be present */

	if (object != DTRACE_OBJ_EVERY &&
	    object != DTRACE_OBJ_KMODS &&
	    object != DTRACE_OBJ_UMODS) {
		if ((dmp = dt_module_from_object(dtp, object)) == NULL)
			return (-1); /* dt_errno is set for us */

		if (dt_module_load(dtp, dmp) == -1)
			return (-1); /* dt_errno is set for us */
		n = 1;

	} else {
		if (object == DTRACE_OBJ_KMODS)
			mask = bits = DT_DM_KERNEL;
		else if (object == DTRACE_OBJ_UMODS)
			mask = DT_DM_KERNEL;

		dmp = dt_list_next(&dtp->dt_modlist);
		n = dtp->dt_nmods;
	}

	if (symp == NULL)
		symp = &sym;

	for (; n > 0; n--, dmp = dt_list_next(dmp)) {
		if ((dmp->dm_flags & mask) != bits)
			continue; /* failed to match required attributes */

		if (dt_module_load(dtp, dmp) == -1)
			continue; /* failed to load symbol table */

#ifdef _WIN32
		if (dt_module_symname(dmp, name, symp, &id) != NULL) {
#else
		if (dmp->dm_ops->do_symname(dmp, name, symp, &id) != NULL) {
#endif
			if (sip != NULL) {
				sip->dts_object = dmp->dm_name;
#ifdef _WIN32
				sip->dts_name = (const char *)symp->st_namep;
#else
				sip->dts_name = (const char *)
				    dmp->dm_strtab.cts_data + symp->st_name;
#endif
				sip->dts_id = id;
			}
			return (0);
		}
		if (dmp->dm_extern != NULL &&
		    (idp = dt_idhash_lookup(dmp->dm_extern, name)) != NULL) {
			if (symp != &sym) {
#ifdef _WIN32
				// TODO:
#else
				symp->st_name = (uintptr_t)idp->di_name;
				symp->st_info =
				    GELF_ST_INFO(STB_GLOBAL, STT_NOTYPE);
				symp->st_other = 0;
				symp->st_shndx = SHN_UNDEF;
				symp->st_value = 0;
				symp->st_size =
				    ctf_type_size(idp->di_ctfp, idp->di_type);
#endif
			}

			if (sip != NULL) {
				sip->dts_object = dmp->dm_name;
				sip->dts_name = idp->di_name;
				sip->dts_id = idp->di_id;
			}

			return (0);
		}
	}

	return (dt_set_errno(dtp, EDT_NOSYM));
}

/*
 * Exported interface to look up a symbol by address.  We return the GElf_Sym
 * and complete symbol information for the matching symbol.
 */
int
dtrace_lookup_by_addr(dtrace_hdl_t *dtp, GElf_Addr addr,
    GElf_Sym *symp, dtrace_syminfo_t *sip)
{
	dt_module_t *dmp;
	uint_t id;
	const dtrace_vector_t *v = dtp->dt_vector;

	if (v != NULL)
		return (v->dtv_lookup_by_addr(dtp->dt_varg, addr, symp, sip));

	for (dmp = dt_list_next(&dtp->dt_modlist); dmp != NULL;
	    dmp = dt_list_next(dmp)) {
#ifdef _WIN32
		if (addr - dmp->dm_image_base < dmp->dm_image_size)
#else
		if (addr - dmp->dm_text_va < dmp->dm_text_size ||
		    addr - dmp->dm_data_va < dmp->dm_data_size ||
		    addr - dmp->dm_bss_va < dmp->dm_bss_size)
#endif
			break;
	}

	if (dmp == NULL)
		return (dt_set_errno(dtp, EDT_NOSYMADDR));

	if (dt_module_load(dtp, dmp) == -1)
		return (-1); /* dt_errno is set for us */


	id = 0;
	if (symp != NULL) {
#ifdef _WIN32
		if (dt_module_symaddr(dmp, addr, symp, &id) == NULL)
#else
		if (dmp->dm_ops->do_symaddr(dmp, addr, symp, &id) == NULL)
#endif
			return (dt_set_errno(dtp, EDT_NOSYMADDR));
	}

	if (sip != NULL) {
		sip->dts_object = dmp->dm_name;

		if (symp != NULL) {
#ifdef _WIN32
			sip->dts_name = symp->st_namep;
#else
			sip->dts_name = (const char *)
			    dmp->dm_strtab.cts_data + symp->st_name;
#endif
			sip->dts_id = id;
		} else {
			sip->dts_name = NULL;
			sip->dts_id = 0;
		}
	}

	return (0);
}

int
dtrace_lookup_by_type(dtrace_hdl_t *dtp, const char *object, const char *name,
    dtrace_typeinfo_t *tip)
{
	dtrace_typeinfo_t ti;
	dt_module_t *dmp;
	int found = 0;
	ctf_id_t id;
	uint_t n, i;
	int justone;
	ctf_file_t *fp;
	char *buf, *p, *q;

	uint_t mask = 0; /* mask of dt_module flags to match */
	uint_t bits = 0; /* flag bits that must be present */

	if (object != DTRACE_OBJ_EVERY &&
	    object != DTRACE_OBJ_KMODS &&
	    object != DTRACE_OBJ_UMODS) {
		if ((dmp = dt_module_from_object(dtp, object)) == NULL)
			return (-1); /* dt_errno is set for us */

		if (dt_module_load(dtp, dmp) == -1)
			return (-1); /* dt_errno is set for us */
		n = 1;
		justone = 1;
	} else {
		if (object == DTRACE_OBJ_KMODS)
			mask = bits = DT_DM_KERNEL;
		else if (object == DTRACE_OBJ_UMODS)
			mask = DT_DM_KERNEL;

		dmp = dt_list_next(&dtp->dt_modlist);
		n = dtp->dt_nmods;
		justone = 0;
	}

	if (tip == NULL)
		tip = &ti;

	for (; n > 0; n--, dmp = dt_list_next(dmp)) {
		if ((dmp->dm_flags & mask) != bits)
			continue; /* failed to match required attributes */

		/*
		 * If we can't load the CTF container, continue on to the next
		 * module.  If our search was scoped to only one module then
		 * return immediately leaving dt_errno unmodified.
		 */
		if (dt_module_hasctf(dtp, dmp) == 0) {
			if (justone)
				return (-1);
			continue;
		}

		/*
		 * Look up the type in the module's CTF container.  If our
		 * match is a forward declaration tag, save this choice in
		 * 'tip' and keep going in the hope that we will locate the
		 * underlying structure definition.  Otherwise just return.
		 */
		if (dmp->dm_pid == 0) {
			id = ctf_lookup_by_name(dmp->dm_ctfp, name);
#ifdef _WIN32
			if (CTF_ERR == id && justone) {
				id = dt_module_import_type(dmp, name, 0);
			}
#endif
			fp = dmp->dm_ctfp;
		} else {
			if ((p = strchr(name, '`')) != NULL) {
				buf = strdup(name);
				if (buf == NULL)
					return (dt_set_errno(dtp, EDT_NOMEM));
				p = strchr(buf, '`');
				if ((q = strchr(p + 1, '`')) != NULL)
					p = q;
				*p = '\0';
#ifdef _WIN32
				id = CTF_ERR;
				dt_module_t *dmpi = dt_module_getctfmod(dtp, dmp, buf);
				if (NULL != dmpi) {
					fp = dt_module_getctf(dtp, dmpi);
					if (NULL != fp) {
						p += 1;
						id = ctf_lookup_by_name(fp, p);
						if (justone && (id == CTF_ERR))
							id = dt_module_import_type(dmpi, p, 0);
					}
				}
#else
				fp = dt_module_getctflib(dtp, dmp, buf);
				if (fp == NULL || (id = ctf_lookup_by_name(fp,
				    p + 1)) == CTF_ERR)
					id = CTF_ERR;
#endif
				free(buf);
			} else {
#ifdef _WIN32
				for (i = 0; i < dmp->dm_npidmods; i++) {
					fp = dt_module_getctf(dtp, dmp->dm_pidmods[i]);
					if (fp == NULL)
						continue;
					if ((id = ctf_lookup_by_name(fp, name)) != CTF_ERR)
						break;
					if (justone && (id = dt_module_import_type(dmp->dm_pidmods[i],
					                         name, 0) != CTF_ERR))
						break;
				}
#else
				for (i = 0; i < dmp->dm_nctflibs; i++) {
					fp = dmp->dm_libctfp[i];
					id = ctf_lookup_by_name(fp, name);
					if (id != CTF_ERR)
						break;
				}
#endif
			}
		}
		if (id != CTF_ERR) {
			tip->dtt_object = dmp->dm_name;
			tip->dtt_ctfp = fp;
			tip->dtt_type = id;
			if (ctf_type_kind(fp, ctf_type_resolve(fp, id)) !=
			    CTF_K_FORWARD)
				return (0);

			found++;
		}
	}

	if (found == 0)
		return (dt_set_errno(dtp, EDT_NOTYPE));

	return (0);
}

int
dtrace_symbol_type(dtrace_hdl_t *dtp, const GElf_Sym *symp,
    const dtrace_syminfo_t *sip, dtrace_typeinfo_t *tip)
{
	dt_module_t *dmp;

	tip->dtt_object = NULL;
	tip->dtt_ctfp = NULL;
	tip->dtt_type = CTF_ERR;
	tip->dtt_flags = 0;

	if ((dmp = dt_module_lookup_by_name(dtp, sip->dts_object)) == NULL)
		return (dt_set_errno(dtp, EDT_NOMOD));

#ifdef _WIN32
	if (symp->st_tag == SymTagNull) {
#else
	if (symp->st_shndx == SHN_UNDEF && dmp->dm_extern != NULL) {
#endif
		dt_ident_t *idp =
		    dt_idhash_lookup(dmp->dm_extern, sip->dts_name);

		if (idp == NULL)
			return (dt_set_errno(dtp, EDT_NOSYM));

		tip->dtt_ctfp = idp->di_ctfp;
		tip->dtt_type = idp->di_type;

#ifdef _WIN32
	} else if (symp->st_tag != SymTagFunction) {
#else
	} else if (GELF_ST_TYPE(symp->st_info) != STT_FUNC) {
#endif
		if (dt_module_getctf(dtp, dmp) == NULL)
			return (-1); /* errno is set for us */

		tip->dtt_ctfp = dmp->dm_ctfp;
#ifdef _WIN32
		tip->dtt_type = dt_module_import_type(dmp, NULL, symp->st_type_idx);
#else
		tip->dtt_type = ctf_lookup_by_symbol(dmp->dm_ctfp, sip->dts_id);
#endif
		if (tip->dtt_type == CTF_ERR) {
			dtp->dt_ctferr = ctf_errno(tip->dtt_ctfp);
			return (dt_set_errno(dtp, EDT_CTF));
		}
	} else {
		tip->dtt_ctfp = DT_FPTR_CTFP(dtp);
		tip->dtt_type = DT_FPTR_TYPE(dtp);
	}

	tip->dtt_object = dmp->dm_name;
	return (0);
}

static dtrace_objinfo_t *
dt_module_info(const dt_module_t *dmp, dtrace_objinfo_t *dto)
{
	dto->dto_name = dmp->dm_name;
	dto->dto_file = dmp->dm_file;
	dto->dto_id = dmp->dm_modid;
	dto->dto_flags = 0;

	if (dmp->dm_flags & DT_DM_KERNEL)
		dto->dto_flags |= DTRACE_OBJ_F_KERNEL;
	if (dmp->dm_flags & DT_DM_PRIMARY)
		dto->dto_flags |= DTRACE_OBJ_F_PRIMARY;

#ifdef _WIN32
	dto->dto_image_base = dmp->dm_image_base;
	dto->dto_image_size = dmp->dm_image_size;
#else
	dto->dto_text_va = dmp->dm_text_va;
	dto->dto_text_size = dmp->dm_text_size;
	dto->dto_data_va = dmp->dm_data_va;
	dto->dto_data_size = dmp->dm_data_size;
	dto->dto_bss_va = dmp->dm_bss_va;
	dto->dto_bss_size = dmp->dm_bss_size;
#endif
	return (dto);
}

int
dtrace_object_iter(dtrace_hdl_t *dtp, dtrace_obj_f *func, void *data)
{
	const dt_module_t *dmp = dt_list_next(&dtp->dt_modlist);
	dtrace_objinfo_t dto;
	int rv;

	for (; dmp != NULL; dmp = dt_list_next(dmp)) {
		if ((rv = (*func)(dtp, dt_module_info(dmp, &dto), data)) != 0)
			return (rv);
	}

	return (0);
}

int
dtrace_object_info(dtrace_hdl_t *dtp, const char *object, dtrace_objinfo_t *dto)
{
	dt_module_t *dmp;

	if (object == DTRACE_OBJ_EVERY || object == DTRACE_OBJ_KMODS ||
	    object == DTRACE_OBJ_UMODS || dto == NULL)
		return (dt_set_errno(dtp, EINVAL));

	if ((dmp = dt_module_from_object(dtp, object)) == NULL)
		return (-1); /* dt_errno is set for us */

	if (dt_module_load(dtp, dmp) == -1)
		return (-1); /* dt_errno is set for us */

	(void) dt_module_info(dmp, dto);
	return (0);
}

