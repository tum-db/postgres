/*-------------------------------------------------------------------------
 *
 * nodeUDO.h
 *
 *
 *
 * Copyright (c) 2021, Moritz Sichert
 *
 *-------------------------------------------------------------------------
 */
#ifndef NODEUDO_H
#define NODEUDO_H

#include "nodes/execnodes.h"

extern UDOState *ExecInitUDO(UDO *node, EState *estate, int eflags);
extern void ExecEndUDO(UDOState *node);

#endif							/* NODEUDO_H */
