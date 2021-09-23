/*-------------------------------------------------------------------------
 *
 * nodeUdo.c
 *	  Routines to handle calls to UDOs
 *
 * Copyright (c) 2021, Moritz Sichert
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "executor/nodeUDO.h"
#include "catalog/pg_collation_d.h"
#include "catalog/pg_type_d.h"
#include "executor/executor.h"
#include "executor/udo.h"
#include "miscadmin.h"
#include "utils/builtins.h"

#define UDO_STACK_SIZE (1ull << 18)
#define UDO_LOCAL_STATE_SIZE 16

struct udo_jmp_state {
	uintptr_t rbx;
	uintptr_t rbp;
	uintptr_t r12;
	uintptr_t r13;
	uintptr_t r14;
	uintptr_t r15;
	uintptr_t rsp;
	uintptr_t rip;
};

#define UDO_JMP_STATE_SIZE (sizeof(struct udo_jmp_state))

typedef struct UDOTupleAttr {
	Oid			typeOid;
	size_t		storageOffset;
	size_t		size;
} UDOTupleAttr;

typedef struct UDOTupleDesc {
	int			natts;
	size_t		totalSize;
	UDOTupleAttr attrs[FLEXIBLE_ARRAY_MEMBER];
} UDOTupleDesc;

static UDOTupleDesc *build_udo_tuple_desc(udo_attribute_descr_array udoAttrs)
{
	size_t totalSize = 0;
	UDOTupleDesc *desc = palloc(sizeof(UDOTupleDesc) + udoAttrs.size * sizeof(UDOTupleAttr));

	desc->natts = udoAttrs.size;

	for (size_t i = 0; i < udoAttrs.size; ++i) {
		udo_attribute_descr *attr = &udoAttrs.attributes[i];
		UDOTupleAttr *descAttr = &desc->attrs[i];
		size_t size;
		size_t alignment;

		switch (attr->pgTypeOid) {
			case BOOLOID:
				size = 1;
				alignment = 1;
				break;
			case INT2OID:
				size = 2;
				alignment = 2;
				break;
			case INT4OID:
			case FLOAT4OID:
				size = 4;
				alignment = 4;
				break;
			case INT8OID:
			case FLOAT8OID:
				size = 8;
				alignment = 8;
				break;
			case TEXTOID:
				size = 16;
				alignment = 8;
				break;
			default:
				/* This should have been detected earlier, when the UDO node
				 * was constructed */
				elog(ERROR, "type %u cannot be used in UDOs", attr->pgTypeOid);
				return NULL;
		}

		/* Correctly align the offset */
		totalSize = (totalSize + alignment - 1) & (~alignment + 1);

		descAttr->typeOid = attr->pgTypeOid;
		descAttr->storageOffset = totalSize;
		descAttr->size = size;

		totalSize += size;
	}

	desc->totalSize = totalSize;

	return desc;
}

#define UDO_SHORT_STRING_LIMIT 12

static void convert_tuple_to_udo(UDOTupleDesc *desc, TupleTableSlot *slot, void *output)
{
	if (slot->tts_nvalid < desc->natts)
		slot->tts_ops->getsomeattrs(slot, desc->natts);

	Assert(desc->natts == slot->tts_nvalid);

	for (int i = 0; i < desc->natts; ++i) {
		UDOTupleAttr* attr = &desc->attrs[i];
		Datum value = slot->tts_values[i];
		char *attrPtr = ((char *) output) + attr->storageOffset;

		if (slot->tts_isnull[i])
			ereport(ERROR,
					(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
					 errmsg("Got NULL value in UDO table argument")));


		if (attr->typeOid == TEXTOID) {
			text *strText;
			const char* str;
			uint32_t strLen;

			strText = pg_detoast_datum_packed((text *) DatumGetPointer(value));
			str = VARDATA_ANY(strText);
			strLen = VARSIZE_ANY_EXHDR(strText);

			memcpy(attrPtr, &strLen, sizeof(uint32_t));
			if (strLen <= UDO_SHORT_STRING_LIMIT) {
				memcpy(attrPtr + sizeof(uint32_t), str, strLen);
			} else {
				uintptr_t strUintptr = (uintptr_t) str;
				strUintptr |= 1ull << 62;
				memset(attrPtr + sizeof(uint32_t), 0, sizeof(uint32_t));
				memcpy(attrPtr + 2 * sizeof(uint32_t), &strUintptr, sizeof(uintptr_t));
			}
		} else {
			memcpy(attrPtr, &value, attr->size);
		}
	}
}

static void extract_tuple_from_udo(UDOTupleDesc *desc, const void *tuple, Datum *values)
{
	for (int i = 0; i < desc->natts; ++i) {
		UDOTupleAttr* attr = &desc->attrs[i];
		const char *attrPtr = ((const char *) tuple) + attr->storageOffset;

		if (attr->typeOid == TEXTOID) {
			text *strText;
			uint32_t strLen;
			const char *strPtr;

			memcpy(&strLen, attrPtr, sizeof(uint32_t));
			if (strLen <= UDO_SHORT_STRING_LIMIT) {
				strPtr = attrPtr + sizeof(uint32_t);
			} else {
				uintptr_t strUintptr;
				memcpy(&strUintptr, attrPtr + 2 * sizeof(uint32_t), sizeof(uintptr_t));
				strUintptr &= ~(3ull << 62);
				strPtr = (const char *) strUintptr;
			}

			strText = cstring_to_text_with_len(strPtr, strLen);
			memcpy(&values[i], &strText, sizeof(text*));
		} else {
			memcpy(&values[i], attrPtr, attr->size);
		}
	}
}

static bool extract_slot_from_udo(UDOState *udostate, const void *tuple,
								  TupleTableSlot **slotOut)
{
	TupleTableSlot *slot = udostate->udoSlot;
	UDOTupleDesc *desc = udostate->udoTupleDesc;
	ExprContext *econtext = udostate->ps.ps_ExprContext;

	extract_tuple_from_udo(udostate->udoTupleDesc, tuple, udostate->values);

	slot->tts_values = udostate->values;
	memset(udostate->nullMarkers, 0, desc->natts);
	slot->tts_isnull = udostate->nullMarkers;
	slot->tts_nvalid = desc->natts;
	slot->tts_flags = 0;

	econtext->ecxt_scantuple = slot;
	if (ExecQual(udostate->ps.qual, econtext)) {
		*slotOut = ExecProject(udostate->ps.ps_ProjInfo);
		return true;
	}

	return false;
}

#define UDO_SAVE_JMPSTATE(jmpState, sp, ip) \
	"movq %%rbx, 0(%%" #jmpState ")\n" \
	"movq %%rbp, 8(%%" #jmpState ")\n" \
	"movq %%r12, 16(%%" #jmpState ")\n" \
	"movq %%r13, 24(%%" #jmpState ")\n" \
	"movq %%r14, 32(%%" #jmpState ")\n" \
	"movq %%r15, 40(%%" #jmpState ")\n" \
	"movq %%" #sp ", 48(%%" #jmpState ")\n" \
	"movq %%" #ip ", 56(%%" #jmpState ")\n"

#define UDO_RESTORE_JMPSTATE(jmpState, ip) \
	"movq 0(%%" #jmpState "), %%rbx\n" \
	"movq 8(%%" #jmpState "), %%rbp\n" \
	"movq 16(%%" #jmpState "), %%r12 \n" \
	"movq 24(%%" #jmpState "), %%r13 \n" \
	"movq 32(%%" #jmpState "), %%r14 \n" \
	"movq 40(%%" #jmpState "), %%r15 \n" \
	"movq 48(%%" #jmpState "), %%rsp \n" \
	"movq 56(%%" #jmpState "), %%" #ip " \n"

static __attribute__((naked))
uintptr_t executeUDOCall(UDOState *udostate, void *func)
{
	asm (
		"mov %%rdi, %%rax\n"				/* Load udostate->jmpStateExec into rax */
		"add %[jmpStateOffset], %%rax\n"
		"mov (%%rax), %%rax\n"
		"lea 8(%%rsp), %%rcx\n"				/* Save the stack pointer as it would be after
											   returning from this funtion in rcx. */
		"mov (%%rsp), %%rdx\n"				/* Save the return address of this function in rdx */
		UDO_SAVE_JMPSTATE(rax, rcx, rdx)
		"mov %%rdi, %%rcx\n"				/* Load udostate->newStack + UDO_STACK_SIZE into rcx */
		"add %[newStack], %%rcx\n"
		"mov (%%rcx), %%rcx\n"
		"add %[stackSize], %%rcx\n"
		"mov %%rcx, %%rsp\n"				/* Set the new stack pointer */
		"mov %%rsp, %%rbp\n"				/* Set the new frame pointer */
		"mov %%rax, %%rbx\n"				/* Save the jump state in rbx */

		"sub $8, %%rsp\n"					/* Subtract 8 from the stack pointer so
											 * that it is aligned to 16 B after the call */
		"call *%%rsi\n"						/* Do the actual call. The udostate
											 * argument is still in rdi. */

		"mov %%rbx, %%rcx\n"				/* Write the jump state pointer to rcx */
		UDO_RESTORE_JMPSTATE(rcx, rsi)
		"sub $8, %%rsp\n"					/* Fix the stack pointer to point to where the return
											 * address of this function is stored. */
		"retq\n"							/* Return normally to the caller of this function.
											 * This will propagate the return value of the called
											 * function */

		:
		: [jmpStateOffset] "i" (offsetof(UDOState, jmpStateExec)),
		  [newStack] "i" (offsetof(UDOState, newStack)),
		  [stackSize] "i" (UDO_STACK_SIZE)
		: "memory"
	);
}

static __attribute__((naked))
void collectTuple(udo_functor *functor, void* globalState, void* localState, void* tuple)
{
	asm (
		"mov %%rcx, %%rax\n"				/* Move tuple argument to rax. This will be used as a
											 * return value when switching to executeUDOCall. */
		"add %[stateOffset], %%rdi\n"		/* Load the udostate from the functor state into rdi */
		"mov (%%rdi), %%rdi\n"
		"mov %%rdi, %%rcx\n"				/* Load &udostate->suspended into rcx */
		"add %[suspendedOffset], %%rcx\n"
		"movb $1, (%%rcx)\n"				/* Set udostate->suspended to true */
		"mov %%rdi, %%rcx\n"				/* Load udostate->jmpStateExec into rcx */
		"add %[jmpStateExec], %%rcx\n"
		"mov (%%rcx), %%rcx\n"
		"mov %%rdi, %%rdx\n"				/* Load udostate->jmpStateCollect into rdx */
		"add %[jmpStateCollect], %%rdx\n"
		"mov (%%rdx), %%rdx\n"
		"lea 8(%%rsp), %%rsi\n"				/* Save the stack pointer as it would be after
											   returning from this funtion in rsi. */
		"mov (%%rsp), %%r8\n"				/* Save the return address of this function in r8 */
		UDO_SAVE_JMPSTATE(rdx, rsi, r8)		/* Save the state of this call in jmpStateCollect */
		UDO_RESTORE_JMPSTATE(rcx, rsi)		/* Restore the state from jmpStateExec */
		"jmp *%%rsi\n"						/* Jump to the caller of executeUDOCall */
		:
		: [stateOffset] "i" (offsetof(udo_functor, state)),
		  [suspendedOffset] "i" (offsetof(UDOState, suspended)),
		  [jmpStateExec] "i" (offsetof(UDOState, jmpStateExec)),
		  [jmpStateCollect] "i" (offsetof(UDOState, jmpStateCollect))
		: "memory"
	);
}

static __attribute__((naked))
uintptr_t resumeUDOCall(UDOState *udostate)
{
	asm (
		"mov %%rdi, %%rax\n"				/* Load udostate->jmpStateExec into rax */
		"add %[jmpStateExec], %%rax\n"
		"mov (%%rax), %%rax\n"
		"lea 8(%%rsp), %%rcx\n"				/* Save the stack pointer as it would be after
											   returning from this funtion in rcx. */
		"mov (%%rsp), %%rdx\n"				/* Save the return address of this function in rdx */
		UDO_SAVE_JMPSTATE(rax, rcx, rdx)

		"mov %%rdi, %%rax\n"				/* Load udostate->jmpStateCollect into rax */
		"add %[jmpStateCollect], %%rax\n"
		"mov (%%rax), %%rax\n"

		UDO_RESTORE_JMPSTATE(rax, rcx)
		"jmp *%%rcx"						/* Jump to the caller of collectTuple */
		:
		: [jmpStateExec] "i" (offsetof(UDOState, jmpStateExec)),
		  [jmpStateCollect] "i" (offsetof(UDOState, jmpStateCollect))
		: "memory"
	);
}

#define UDO_VARARGS_INTARG(reg) \
	"cmp %%r10, %%r11\n" \
	"je 0f\n" \
	"mov (%%r10), %%" #reg "\n" \
	"add $8, %%r10\n"

#define UDO_VARARGS_FLOATARG(reg) \
	"cmp %%r12, %%r13\n" \
	"je 0f\n" \
	"movsd (%%r12), %%" #reg "\n" \
	"add $8, %%r12\n"

static __attribute__((naked))
uintptr_t callVarargs(void* func, uintptr_t* intArgs, size_t numIntArgs,
					  double* floatArgs, size_t numFloatArgs)
{
	asm (
		"push %%r12\n"					/* Save r12 */
		"push %%r13\n"					/* Save r13 */

		"mov %%rdi, %%rax\n"			/* Move the function address to rax */

		"mov %%rsi, %%r10\n"			/* Move intArgs to r10 */
		"lea (%%rsi, %%rdx, 8), %%r11\n" /* Write intArgs + numIntArgs to r11 */

		"mov %%rcx, %%r12\n"			/* Move floatArgs to r12 */
		"lea (%%rcx, %%r8, 8), %%r13\n"	/* Write floatArgs + numFloatArgs to r13 */

		UDO_VARARGS_INTARG(rdi)			/* Write int arg 1 to rdi if it exists */
		UDO_VARARGS_INTARG(rsi)			/* Write int arg 2 to rsi if it exists */
		UDO_VARARGS_INTARG(rdx)			/* Write int arg 3 to rdx if it exists */
		UDO_VARARGS_INTARG(rcx)			/* Write int arg 4 to rcx if it exists */
		UDO_VARARGS_INTARG(r8)			/* Write int arg 5 to r8 if it exists */
		UDO_VARARGS_INTARG(r9)			/* Write int arg 6 to r9 if it exists */
		"0:\n"

		UDO_VARARGS_FLOATARG(xmm0)		/* Write float arg 1 to xmm0 if it exists */
		UDO_VARARGS_FLOATARG(xmm1)		/* Write float arg 2 to xmm1 if it exists */
		UDO_VARARGS_FLOATARG(xmm2)		/* Write float arg 3 to xmm2 if it exists */
		UDO_VARARGS_FLOATARG(xmm3)		/* Write float arg 4 to xmm3 if it exists */
		UDO_VARARGS_FLOATARG(xmm4)		/* Write float arg 5 to xmm4 if it exists */
		UDO_VARARGS_FLOATARG(xmm5)		/* Write float arg 6 to xmm5 if it exists */
		UDO_VARARGS_FLOATARG(xmm6)		/* Write float arg 7 to xmm6 if it exists */
		UDO_VARARGS_FLOATARG(xmm7)		/* Write float arg 8 to xmm7 if it exists */
		"0:\n"

		"pop %%r13\n"					/* Restore r13 */
		"pop %%r12\n"					/* Restore r12 */

		"jmp *%%rax\n"					/* Do tail call to the function */
		:
		:
		: "memory"
	);
}

static void UDOSwitchTo_CollectInput(UDOState *udostate);
static void UDOSwitchTo_ExtraWork(UDOState *udostate);
static void UDOSwitchTo_PostProduce(UDOState *udostate);
static TupleTableSlot *UDOCollectInput(UDOState *udostate);
static TupleTableSlot *UDOExtraWork(UDOState *udostate);
static TupleTableSlot *UDOPostProduce(UDOState *udostate);

static TupleTableSlot *
ExecUDO(PlanState *pstate)
{
	UDOState *udostate = castNode(UDOState, pstate);

	switch (udostate->lstate) {
		case UDO_COLLECT_INPUT:
			return UDOCollectInput(udostate);
		case UDO_EXTRA_WORK:
			return UDOExtraWork(udostate);
		case UDO_POST_PRODUCE:
			return UDOPostProduce(udostate);
		case UDO_DONE:
			return NULL;
	}

	return NULL;
}

static void UDOSwitchTo_CollectInput(UDOState *udostate)
{
	PlanState *outerState = outerPlanState(udostate);
	if (outerState) {
		udostate->lstate = UDO_COLLECT_INPUT;
		memset(udostate->localState, 0, UDO_LOCAL_STATE_SIZE);
	} else {
		UDOSwitchTo_ExtraWork(udostate);
	}
}

static void UDOSwitchTo_ExtraWork(UDOState *udostate)
{
	if (udostate->udoFunctions.extraWork) {
		udostate->lstate = UDO_EXTRA_WORK;
		memset(udostate->localState, 0, UDO_LOCAL_STATE_SIZE);
	} else {
		UDOSwitchTo_PostProduce(udostate);
	}
}

static void UDOSwitchTo_PostProduce(UDOState *udostate)
{
	if (udostate->udoFunctions.postProduce) {
		udostate->lstate = UDO_POST_PRODUCE;
		memset(udostate->localState, 0, UDO_LOCAL_STATE_SIZE);
	} else {
		udostate->lstate = UDO_DONE;
	}
}

static uintptr_t callUDOConsume(UDOState* udostate)
{
	void (*consume)(void*,void*,void*,void*,void*) = udostate->udoFunctions.consume;

	consume(NULL, NULL, udostate->udoState, udostate->localState,
			udostate->inputTuple);

	/* Returning 0 here means that executeUDOCall(..., callUDOConsume) below
	 * will receive NULL as a return value. */
	return 0;
}

static TupleTableSlot *UDOCollectInput(UDOState *udostate)
{
	TupleTableSlot *slot;

	for (;;) {
		if (udostate->suspended) {
			/* Resume the call to consume */
			void *tuple;

			udostate->suspended = false;

			tuple = (void *) resumeUDOCall(udostate);
			if (tuple) {
				Assert(udostate->suspended);
				if (extract_slot_from_udo(udostate, tuple, &slot))
					return slot;
			}
		} else {
			/* Do a regular call to consume */
			PlanState *outerNode = outerPlanState(udostate);
			UDOTupleDesc *udoTupleDesc = udostate->inputUdoTupleDesc;
			TupleTableSlot *inputSlot;
			void *tuple;

			inputSlot = ExecProcNode(outerNode);
			if (TupIsNull(inputSlot)) {
				Assert(!udostate->suspended);

				UDOSwitchTo_ExtraWork(udostate);
				return ExecUDO((PlanState *) udostate);
			}

			convert_tuple_to_udo(udoTupleDesc, inputSlot, udostate->inputTuple);
			tuple = (void *) executeUDOCall(udostate, callUDOConsume);
			if (tuple) {
				Assert(udostate->suspended);
				if (extract_slot_from_udo(udostate, tuple, &slot))
					return slot;
			} else {
				udostate->suspended = false;
			}
		}
	}
}

static TupleTableSlot *UDOExtraWork(UDOState *udostate)
{
	/* The extraWork function is not allowed to call produce_output_tuple, so
	 * we don't need to do the execute/resume logic here. */
	uint32_t (*extraWork)(void*,void*,uint32_t) = udostate->udoFunctions.extraWork;
	uint32_t stepId = 0;

	while (stepId != ~(uint32_t)0) {
		uint32_t newStepId = extraWork(udostate->udoState, udostate->localState, stepId);

		if (newStepId != stepId)
			memset(udostate->localState, 0, UDO_LOCAL_STATE_SIZE);

		stepId = newStepId;
	}

	UDOSwitchTo_PostProduce(udostate);
	return ExecUDO((PlanState *) udostate);
}

static uintptr_t callUDOPostProduce(UDOState* udostate)
{
	uint8_t (*postProduce)(void*,void*,void*,void*) = udostate->udoFunctions.postProduce;

	return postProduce(NULL, NULL, udostate->udoState, udostate->localState);
}

static TupleTableSlot *UDOPostProduce(UDOState *udostate)
{
	TupleTableSlot *slot;

	for (;;) {
		uintptr_t ret;
		if (udostate->suspended) {
			/* Resume the call to postProduce */
			udostate->suspended = false;
			ret = resumeUDOCall(udostate);
		} else {
			/* Do a regular call to postProduce */
			ret = executeUDOCall(udostate, callUDOPostProduce);
		}

		if (udostate->suspended) {
			/* postProduce was suspended and generated a tuple, so return that tuple. */
			void *tuple = (void *) ret;
			Assert(tuple);
			if (extract_slot_from_udo(udostate, tuple, &slot))
				return slot;
		} else {
			/* The call returned regularly, so check the boolean return value. */
			bool isDone = ret;
			if (isDone) {
				udostate->lstate = UDO_DONE;
				return NULL;
			}
		}
	}
}

static void udo_print_debug(udo_functor *functor, const char *str, size_t size)
{
	ereport(INFO, errmsg("UDO %u debug message: %*s",
						 (Oid)(uint64_t)functor->state, (int)size, str));
}

static uint64_t udo_get_random(udo_functor *functor)
{
	return rand();
}

static void *udo_malloc(size_t size)
{
	char *ptr = (char *) palloc(size + 16);
	memcpy(ptr + 8, &size, sizeof(size));
	return ptr + 16;
}

static void* udo_calloc(size_t num, size_t size)
{
	char *ptr;
	Assert(num < SIZE_MAX / size);
	ptr = (char *) palloc0(size + 16);
	memcpy(ptr + 8, &size, sizeof(size));
	return ptr + 16;
}

static void* udo_realloc(void *ptr, size_t newSize)
{
	char *charPtr = ((char *) ptr) - 16;
	char *newPtr = (char *) repalloc(charPtr, newSize + 16);
	if (newPtr) {
		memcpy(newPtr + 8, &newSize, sizeof(newSize));
		newPtr += 16;
	}
	return newPtr;
}

static int udo_posix_memalign(void **memptr, size_t alignment, size_t size)
{
	if (size == 0) {
		*memptr = NULL;
		return 0;
	}

	if (alignment < 16) {
		*memptr = udo_malloc(size);
	} else {
		size_t space = size + alignment;
		char *ptr;
		uintptr_t alignedUPtr;
		uintptr_t alignmentU = (uintptr_t) alignment;
		char *alignedPtr;
		size_t sizeValue = ~((size_t) 0);

		// Allocate 16 additional bytes so that we can save the real pointer (so
		// that umbraFree can find the start of the actual allocation) and set
		// the size to ~0 so that udo_free detects this special case.
		ptr = (char *) (udo_malloc(space + 16));

		alignedUPtr = ((uintptr_t) ptr) + 16;
		// Align the pointer to the specified alignment
		alignedUPtr = (alignedUPtr + alignmentU - 1) & ~(alignmentU - 1);

		// Set the size value to ~0
		alignedPtr = (char *) alignedUPtr;
		memcpy(alignedPtr - 8, &sizeValue, sizeof(sizeValue));
		// Store the real pointer returned by udo_malloc
		memcpy(alignedPtr - 16, &ptr, sizeof(ptr));

		*memptr = alignedPtr;
	}

	return 0;
}

static void udo_free(void *ptr)
{
	size_t size;
	char *charPtr = (char *) ptr;

	memcpy(&size, charPtr - 8, sizeof(size));

	if (size == ~((size_t) 0)) {
		memcpy(&charPtr, charPtr - 16, sizeof(charPtr));
	}

	pfree(charPtr - 16);
}

static __attribute__((tls_model("local-exec"), used)) __thread char udo_tls_storage[4096];

UDOState *ExecInitUDO(UDO *node, EState *estate, int eflags)
{
	UDOState *udostate;
	TupleDesc udoDesc;
	UDOTupleDesc *udoTupleDesc;
	Plan *outerPlanNode = outerPlan(node);
	udo_handle handle;
	FuncExpr* fexpr = castNode(FuncExpr, node->funcExpr);
	udo_errno err;
	udo_attribute_descr_array outputAttrs;
	udo_cxx_functors functors;
	udo_cxx_allocation_funcs allocFuncs;
	int64_t tlsOffset;
	void *constructorArg;

	udostate = palloc(sizeof(UDOState) + 2 * UDO_JMP_STATE_SIZE);
	memset(udostate, 0, sizeof(UDOState));
	((Node *) udostate)->type = T_UDOState;
	udostate->ps.plan = (Plan *) node;
	udostate->ps.state = estate;
	udostate->ps.ExecProcNode = ExecUDO;
	udostate->newStack = palloc(UDO_STACK_SIZE);
	udostate->jmpStateExec = ((char *) udostate) + sizeof(UDOState);
	udostate->jmpStateCollect = ((char *) udostate) + sizeof(UDOState) + UDO_JMP_STATE_SIZE;

	ExecAssignExprContext(estate, (PlanState *) udostate);

	if (outerPlanNode)
		outerPlanState(udostate) = ExecInitNode(outerPlanNode, estate, eflags);

	ExecInitResultTupleSlotTL((PlanState *) udostate, &TTSOpsVirtual);
	ExecAssignProjectionInfo((PlanState *) udostate, NULL);

	udostate->ps.qual = ExecInitQual(node->plan.qual, (PlanState *) udostate);

	ensure_udo_runtime_loaded();
	handle = udo_cxxudo_analyze_cached((uint64_t) fexpr->funcid);

	err = udo_cxxudo_compile(handle);
	if (err != 0) {
		char* error_message = udo_error_message_copy(handle);
		udo_cxxudo_destroy(handle);
		ereport(ERROR,
				(errcode(ERRCODE_SYSTEM_ERROR),
				 errmsg("Failed to compile C++ UDO: %s",
						error_message)));
	}

	err = udo_get_output_attributes(handle, &outputAttrs);
	if (err != 0)
		elog(ERROR, "failed getting UDO output attributes");

	udoDesc = CreateTemplateTupleDesc(outputAttrs.size);
	for (int i = 0; i < outputAttrs.size; ++i) {
		udo_attribute_descr *udoAttr = &outputAttrs.attributes[i];
		Oid collation;

		TupleDescInitEntry(udoDesc, i + 1, udoAttr->name, udoAttr->pgTypeOid, -1, 0);

		if (udoAttr->pgTypeOid == TEXTOID)
			collation = DEFAULT_COLLATION_OID;
		else
			collation = InvalidOid;
		TupleDescInitEntryCollation(udoDesc, i + 1, collation);
	}
	udostate->udoDesc = udoDesc;
	udostate->udoSlot = MakeSingleTupleTableSlot(udoDesc, &TTSOpsVirtual);

	udoTupleDesc = build_udo_tuple_desc(outputAttrs);
	udostate->udoTupleDesc = udoTupleDesc;
	udostate->values = palloc0(udoTupleDesc->natts * sizeof(Datum));
	udostate->nullMarkers = palloc0(udoTupleDesc->natts);

	if (outerPlanNode) {
		udo_attribute_descr_array inputAttrs;
		UDOTupleDesc *udoTupleDesc;

		err = udo_get_input_attributes(handle, &inputAttrs);
		if (err != 0)
			elog(ERROR, "failed getting UDO output attributes");

		udoTupleDesc = build_udo_tuple_desc(inputAttrs);

		udostate->inputUdoTupleDesc = udoTupleDesc;
		udostate->inputTuple = palloc(udoTupleDesc->totalSize);
	}

	functors.produceOutputTupleFunctor.func = &collectTuple;
	functors.produceOutputTupleFunctor.state = udostate;
	functors.printDebugFunctor.func = &udo_print_debug;
	functors.printDebugFunctor.state = (void *)(uint64_t)fexpr->funcid;
	functors.getRandomFunctor.func = &udo_get_random;
	functors.getRandomFunctor.state = NULL;

	allocFuncs.malloc = &udo_malloc;
	allocFuncs.calloc = &udo_calloc;
	allocFuncs.realloc = &udo_realloc;
	allocFuncs.posixMemalign = &udo_posix_memalign;
	allocFuncs.free = &udo_free;

#if defined(__x86_64__) && defined(__ELF__)
	asm("lea udo_tls_storage@tpoff, %0"
		: "=r"(tlsOffset));
#else
#error "Unsupported target for thread-local storage"
#endif

	err = udo_cxxudo_link(handle, functors, allocFuncs, tlsOffset,
						  sizeof(udo_tls_storage), &udostate->udoFunctions);
	if (err != 0)
	{
		char* error_message = udo_error_message_copy(handle);
		udo_cxxudo_destroy(handle);
		ereport(ERROR,
				(errcode(ERRCODE_SYSTEM_ERROR),
				 errmsg("Failed to link C++ UDO: %s",
						error_message)));
	}

	udostate->udoSize = udo_get_size(handle);
	udostate->udoState = palloc(udostate->udoSize);
	udostate->localState = palloc(UDO_LOCAL_STATE_SIZE);

	constructorArg = udo_cxxudo_get_constructor_arg(handle);

	((void(*)())udostate->udoFunctions.threadInit)();
	((void(*)(void*))udostate->udoFunctions.globalConstructor)(constructorArg);

	if (udostate->udoFunctions.constructor) {
		udo_arguments args;
		uintptr_t *intArgs = palloc(6 * sizeof(uintptr_t));
		size_t numIntArgs = 0;
		double *floatArgs = palloc(8 * sizeof(double));
		size_t numFloatArgs = 0;
		void (*constructor)() = udostate->udoFunctions.constructor;
		ListCell *lc;
		int i;

		/* First argument of the constructor is always the udo state */
		intArgs[0] = (uintptr_t) udostate->udoState;
		++numIntArgs;

		err = udo_get_arguments(handle, &args);
		if (err != 0)
			elog(ERROR, "failed getting UDO arguments");

		Assert(list_length(fexpr->args) ==
			   args.numScalarArguments + args.numTableArguments);

		i = 0;
		foreach(lc, fexpr->args) {
			Node *arg = lfirst(lc);
			Datum *argValue;

			// Skip table arguments
			if (IsA(arg, SubLink) && ((SubLink *)arg)->subLinkType == UDO_SUBLINK)
				continue;

			argValue = &castNode(Const, arg)->constvalue;

			switch (args.pgTypeOids[i]) {
				case FLOAT4OID: {
					float arg;
					if (numFloatArgs >= 8) {
						elog(ERROR, "Calling UDOs with more than 8 float arguments not implemented");
						return NULL;
					}
					memcpy(&arg, argValue, 4);
					floatArgs[numFloatArgs] = arg;
					++numFloatArgs;
					break;
				};
				case FLOAT8OID: {
					double arg;
					if (numFloatArgs >= 8) {
						elog(ERROR, "Calling UDOs with more than 8 float arguments not implemented");
						return NULL;
					}
					memcpy(&arg, argValue, 8);
					floatArgs[numFloatArgs] = arg;
					++numFloatArgs;
					break;
				};
				case BOOLOID:
				case INT2OID:
				case INT4OID:
				case INT8OID: {
					if (numFloatArgs >= 6) {
						elog(ERROR, "Calling UDOs with more than 5 integer arguments not implemented");
						return NULL;
					}
					intArgs[numIntArgs] = *argValue;
					++numIntArgs;
					break;
				}
				case TEXTOID:
					elog(ERROR, "Calling UDOs with string arguments not implemented");
					return NULL;
			}

			++i;
		}

		callVarargs(constructor, intArgs, numIntArgs, floatArgs, numFloatArgs);
	}

	UDOSwitchTo_CollectInput(udostate);

	return udostate;
}

void ExecEndUDO(UDOState *udostate)
{
	if (outerPlanState(udostate))
		ExecEndNode(outerPlanState(udostate));

	if (udostate->udoFunctions.destructor)
		((void(*)(void*))udostate->udoFunctions.destructor)(udostate->udoState);

	pfree(udostate->newStack);
}
