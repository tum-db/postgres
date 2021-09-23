/*-------------------------------------------------------------------------
 *
 * udo.h
 *		Declarations for execution of UDO functions.
 *
 *
 * Copyright (c) 2021, Moritz Sichert
 *
 * src/include/executor/udo.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef UDO_H
#define UDO_H

#include "postgres.h"

struct udo_opaque_impl;
typedef struct udo_opaque_impl *udo_handle;
typedef int udo_errno;

typedef struct udo_arguments {
	size_t numScalarArguments;
	size_t numTableArguments;
	Oid* pgTypeOids;
} udo_arguments;

typedef struct udo_attribute_descr {
	const char* name;
	size_t size;
	size_t alignment;
	Oid pgTypeOid;
} udo_attribute_descr;

typedef struct udo_attribute_descr_array {
	size_t size;
	udo_attribute_descr* attributes;
} udo_attribute_descr_array;

typedef struct udo_functor {
	void *func;
	void *state;
} udo_functor;

typedef struct udo_cxx_functors {
	udo_functor produceOutputTupleFunctor;
	udo_functor printDebugFunctor;
	udo_functor getRandomFunctor;
} udo_cxx_functors;

typedef struct udo_cxx_allocation_funcs {
	void *malloc;
	void *calloc;
	void *realloc;
	void *posixMemalign;
	void *free;
} udo_cxx_allocation_funcs;

typedef struct udo_cxx_functions {
	void *globalConstructor;
	void *globalDestructor;
	void *threadInit;
	void *constructor;
	void *destructor;
	void *consume;
	void *extraWork;
	void *postProduce;
} udo_cxx_functions;

extern udo_handle (*udo_cxxudo_init)(const char* cxxSource,
									 size_t cxxSourceLen,
									 const char* udoClassName,
									 size_t udoClassNameLen);
extern void (*udo_cxxudo_destroy)(udo_handle handle);
extern const char* (*udo_error_message)(udo_handle handle);
extern void (*udo_cache_handle)(udo_handle handle, uint64_t cacheKey);
extern udo_handle (*udo_get_cached_handle)(uint64_t cacheKey);
extern udo_errno (*udo_cxxudo_analyze)(udo_handle handle);
extern udo_errno (*udo_get_arguments)(udo_handle handle, udo_arguments* args);
extern udo_errno (*udo_get_output_attributes)(udo_handle handle,
											  udo_attribute_descr_array* attrDescrs);
extern udo_errno (*udo_get_input_attributes)(udo_handle handle,
											 udo_attribute_descr_array* attrDescrs);
extern size_t (*udo_get_size)(udo_handle handle);
extern udo_errno (*udo_cxxudo_compile)(udo_handle handle);
extern udo_errno (*udo_cxxudo_link)(udo_handle handle,
									udo_cxx_functors functors,
									udo_cxx_allocation_funcs allocationFuncs,
									int64_t tlsBlockOffset,
									uint64_t tlsBlockSize,
									udo_cxx_functions* functions);
extern void* (*udo_cxxudo_get_constructor_arg)(udo_handle handle);

/*
 * Ensure that the UDO runtime is loaded
 */
void ensure_udo_runtime_loaded(void);

/*
 * Get a copy of the current UDO error message
 */
char* udo_error_message_copy(udo_handle handle);

/*
 * Analyze the UDO with the given Oid and return the handle. The result of this
 * function is cached.
 */
udo_handle udo_cxxudo_analyze_cached(Oid funcOid);

#endif
