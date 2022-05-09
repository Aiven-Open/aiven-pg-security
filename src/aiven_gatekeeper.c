/* -------------------------------------------------------------------------
 *
 * aiven_gatekeeper.c
 *
 * Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
 *
 * IDENTIFICATION
 *		src/aiven_gatekeeper.c
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/xact.h"
#include "commands/explain.h"
#include "executor/instrument.h"
#include "jit/jit.h"
#include "miscadmin.h"
#include "utils/guc.h"
#include "tcop/utility.h"

PG_MODULE_MAGIC;

void _PG_init(void);
void _PG_fini(void);

/* GUC Variables */

// /* Saved hook values in case of unload */
static ProcessUtility_hook_type prev_ProcessUtility = NULL;

static bool is_elevated(void);
static void gatekeeper_checks(PlannedStmt *pstmt,
							 const char *queryString,
							 bool readOnlyTree,
							 ProcessUtilityContext context,
							 ParamListInfo params,
							 QueryEnvironment *queryEnv,
							 DestReceiver *dest,
							 QueryCompletion *qc);

/* returns true if the session and current user ids are different */
static bool is_elevated()
{
	// current user
	Oid CurrentUserId = GetUserId();
	// session user
	Oid SessionUserId = GetSessionUserId();
	/* if current user != session user we are probably elevated
	 * this is a bit of a dumb check, ideally it would check if
	 * session user is super user. SessionUserIsSuperuser is available
	 * but no getter exists for this
	 */

	return CurrentUserId != SessionUserId;
}

/*
 * Check if this might lead to privilege escalation
 */
static void
gatekeeper_checks(PlannedStmt *pstmt,
				 const char *queryString,
				 bool readOnlyTree,
				 ProcessUtilityContext context,
				 ParamListInfo params,
				 QueryEnvironment *queryEnv,
				 DestReceiver *dest,
				 QueryCompletion *qc)
{

	/* get the utilty statment from the planner
	 * https://github.com/postgres/postgres/blob/24d2b2680a8d0e01b30ce8a41c4eb3b47aca5031/src/backend/tcop/utility.c#L575
	 */
	Node *stmt = pstmt->utilityStmt;
	/* Parse copy statement */
	CopyStmt *copyStmt;

	/* switch between the types to see if we care about this stmt */
	switch (stmt->type)
	{
		// ALTER
		case T_AlterRoleStmt:
		case T_AlterRoleSetStmt:
		// CREATE ROLE
		case T_CreateRoleStmt:
		// DROP ROLE
		case T_DropRoleStmt:
		// GRANT
		case T_GrantRoleStmt:
			// TODO: check if trying to grant superuser?
			if (is_elevated())
			{
				elog(ERROR, "Denied - ROLE modifiers are disabled");
				return;
			}
			break;
		// COPY
		case T_CopyStmt:

			copyStmt = (CopyStmt *)stmt;

			/* check if TO/FROM PROGRAM
			* we deny this regardless of the context we are running in
			*/
			if (copyStmt->is_program)
			{
				elog(ERROR, "Denied - COPY TO/FROM PROGRAM is disabled");
				return;
			}
			/* otherwise, we don't want copy TO/FROM FILE
			* in an elevated context
			*/
			if (copyStmt->filename && is_elevated())
			{
				elog(ERROR, "Denied - COPY TO/FROM FILE is disabled");
				return;
			}
			break;
		default:
			break;
	}

	// execute the actual query
	if (prev_ProcessUtility)
		prev_ProcessUtility(pstmt, queryString, readOnlyTree,
							context, params, queryEnv,
							dest, qc);
	else
		standard_ProcessUtility(pstmt, queryString, readOnlyTree,
								context, params, queryEnv,
								dest, qc);
}

/*
 * Module Load Callback
 */
void _PG_init(void)
{
	/* Define custom GUC variables. */

	/* Install Hooks */
	prev_ProcessUtility = ProcessUtility_hook;
	ProcessUtility_hook = gatekeeper_checks;
}

/*
 * Module unload callback
 */
void _PG_fini(void)
{
	/* Uninstall hooks. */
	ProcessUtility_hook = prev_ProcessUtility;
}