/*-------------------------------------------------------------------------
 *
 * udo.h
 *		Declarations for execution of UDO functions.
 *
 *
 * Copyright (c) 2021, Moritz Sichert
 *
 * src/include/executor/udo.c
 *
 *-------------------------------------------------------------------------
 */
#include "executor/udo.h"

#include "access/htup_details.h"
#include "catalog/pg_proc.h"
#include "fmgr.h"
#include "utils/syscache.h"

#include <dlfcn.h>

static bool udoRuntimeLoaded = false;

udo_handle (*udo_cxxudo_init)(const char* cppSource, size_t cppSourceLen,
							  const char* udoClassName,
							  size_t udoClassNameLen);
void (*udo_cxxudo_destroy)(udo_handle handle);
const char* (*udo_error_message)(udo_handle handle);
void (*udo_cache_handle)(udo_handle handle, uint64_t cacheKey);
udo_handle (*udo_get_cached_handle)(uint64_t cacheKey);
udo_errno (*udo_cxxudo_analyze)(udo_handle handle);
udo_errno (*udo_get_arguments)(udo_handle handle, udo_arguments* args);
udo_errno (*udo_get_output_attributes)(udo_handle handle,
									   udo_attribute_descr_array* attrDescrs);
udo_errno (*udo_get_input_attributes)(udo_handle handle,
									  udo_attribute_descr_array* attrDescrs);
size_t (*udo_get_size)(udo_handle handle);
udo_errno (*udo_cxxudo_compile)(udo_handle handle);
udo_errno (*udo_cxxudo_link)(udo_handle handle,
							 udo_cxx_functors functors,
							 udo_cxx_allocation_funcs allocationFuncs,
							 int64_t tlsBlockOffset,
							 uint64_t tlsBlockSize,
							 udo_cxx_functions* functions);
void* (*udo_cxxudo_get_constructor_arg)(udo_handle handle);

void ensure_udo_runtime_loaded(void)
{
	void *udoLibHandle;

	if (udoRuntimeLoaded)
		return;

	udo_cxxudo_init = load_external_function("libudoruntime_pg.so",
											 "udo_cxxudo_init", true,
											 &udoLibHandle);
	udo_cxxudo_destroy = lookup_external_function(udoLibHandle,
												  "udo_cxxudo_destroy");
	udo_error_message = lookup_external_function(udoLibHandle,
												 "udo_error_message");
	udo_cache_handle = lookup_external_function(udoLibHandle,
												"udo_cache_handle");
	udo_get_cached_handle = lookup_external_function(udoLibHandle,
													 "udo_get_cached_handle");
	udo_cxxudo_analyze = lookup_external_function(udoLibHandle,
												  "udo_cxxudo_analyze");
	udo_get_arguments = lookup_external_function(udoLibHandle,
												 "udo_get_arguments");
	udo_get_output_attributes = lookup_external_function(udoLibHandle,
														 "udo_get_output_attributes");
	udo_get_input_attributes = lookup_external_function(udoLibHandle,
														"udo_get_input_attributes");
	udo_get_size = lookup_external_function(udoLibHandle,
											"udo_get_size");
	udo_cxxudo_compile = lookup_external_function(udoLibHandle,
												  "udo_cxxudo_compile");
	udo_cxxudo_link = lookup_external_function(udoLibHandle,
											   "udo_cxxudo_link");
	udo_cxxudo_get_constructor_arg = lookup_external_function(
		udoLibHandle, "udo_cxxudo_get_constructor_arg");

	udoRuntimeLoaded = true;
}

char* udo_error_message_copy(udo_handle handle)
{
	const char* error_message;
	char* error_message_copy;
	size_t msg_len;

	error_message = udo_error_message(handle);
	msg_len = strlen(error_message);
	error_message_copy = palloc(msg_len + 1);
	memcpy(error_message_copy, error_message, msg_len + 1);

	return error_message_copy;
}

udo_handle udo_cxxudo_analyze_cached(Oid funcOid)
{
	HeapTuple tuple;
	Form_pg_proc procform;
	Datum tmp;
	bool isnull;
	text *cxx_src_text;
	const char *cxx_src;
	size_t cxx_src_len;
	const char *class_name;
	size_t class_name_len;
	udo_handle handle;
	udo_errno err;
	udo_arguments udo_args;
	int funcIndex;
	int scalarIndex;
	int nargs;

	ensure_udo_runtime_loaded();

	handle = udo_get_cached_handle((uint64_t) funcOid);
	if (handle)
		return handle;

	tuple = SearchSysCache1(PROCOID, ObjectIdGetDatum(funcOid));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for function %u", funcOid);
	procform = (Form_pg_proc) GETSTRUCT(tuple);

	tmp = SysCacheGetAttr(PROCOID, tuple, Anum_pg_proc_probin, &isnull);
	if (isnull)
		elog(ERROR, "null probin");

	cxx_src_text = pg_detoast_datum_packed((text *) DatumGetPointer(tmp));
	cxx_src = VARDATA_ANY(cxx_src_text);
	cxx_src_len = VARSIZE_ANY_EXHDR(cxx_src_text);

	tmp = SysCacheGetAttr(PROCOID, tuple, Anum_pg_proc_prosrc, &isnull);
	if (isnull)
		elog(ERROR, "null prosrc");
	class_name = VARDATA_ANY(DatumGetPointer(tmp));
	class_name_len = VARSIZE_ANY_EXHDR(DatumGetPointer(tmp));

	handle = udo_cxxudo_init(cxx_src, cxx_src_len, class_name, class_name_len);

	err = udo_cxxudo_analyze(handle);
	if (err != 0)
		goto udo_err;

	err = udo_get_arguments(handle, &udo_args);
	if (err != 0)
		goto udo_err;

	funcIndex = 0;
	scalarIndex = 0;
	nargs = 0;
	for (; funcIndex < procform->proargtypes.dim1; ++funcIndex) {
		Oid argType = procform->proargtypes.values[funcIndex];

		if (argType != RECORDOID)
			++nargs;

		if (argType == RECORDOID) {
			if (udo_args.numTableArguments == 0) {
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_FUNCTION_DEFINITION),
						 errmsg("UDO function definition has table argument "
								"but C++ UDO does not")));
			}
		} else if (scalarIndex < udo_args.numScalarArguments) {
			Oid udoArgType = udo_args.pgTypeOids[scalarIndex];
			++scalarIndex;

			if (argType != udoArgType) {
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_FUNCTION_DEFINITION),
						 errmsg("Mismatching type for scalar argument of UDO: "
								"found %u in function definition but %u in C++ UDO",
								argType, udoArgType)));
			}
		}
	}

	if (nargs != udo_args.numScalarArguments) {
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_FUNCTION_DEFINITION),
				 errmsg("Mismatching number of scalar arguments: "
						"found %i in function definition but %zu in C++ UDO",
						nargs, udo_args.numScalarArguments)));
	}

	ReleaseSysCache(tuple);

	udo_cache_handle(handle, (uint64_t) funcOid);

	return handle;

udo_err:
	ReleaseSysCache(tuple);
	{
		char* error_message = udo_error_message_copy(handle);
		udo_cxxudo_destroy(handle);
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_FUNCTION_DEFINITION),
				 errmsg("Invalid UDO C++ code: %s",
						error_message)));
	}
	return NULL;
}
