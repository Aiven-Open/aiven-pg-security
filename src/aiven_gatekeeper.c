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
#include "commands/extension.h"
#include "miscadmin.h"
#include "tcop/utility.h"
#include "utils/guc.h"

#include "aiven_gatekeeper.h"

PG_MODULE_MAGIC;

void _PG_init(void);
void _PG_fini(void);

/* GUC Variables */

/* Saved hook values in case of unload */
static ProcessUtility_hook_type prev_ProcessUtility = NULL;

/* returns true if the session and current user ids are different */
static bool
is_elevated(void)
{
    /* if current user != session and the current user is
     * a superuser, but the original session_user is not,
     * we can say that we are in an elevated context.
     */

    Oid currentUserId = GetUserId();
    Oid sessionUserId = GetSessionUserId();

    bool is_superuser;

    /* short circuit if the current and session user are the same
     * saves on a slightly more expensive role fetch
     */
    if (currentUserId == sessionUserId)
    {
        return false;
    }

    is_superuser = superuser_arg(currentUserId);

    /* elevated to supersuser when the session auth user does not have superuser privileges */
    return is_superuser && !session_auth_is_superuser;
}

static bool
is_security_restricted(void)
{
    /* checks if we are in a security_restricted context
     * this occurs during VACUUM, ANALYZE, MATERIAL VIEW etc
     * and has been a source of privilege escalation vulnerabilities
     * like CVE-2020-25695 and CVE-2022-1552
     */
    return InSecurityRestrictedOperation();
}

static void
gatekeeper_checks(PROCESS_UTILITY_PARAMS)
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
    case T_AlterRoleStmt: // ALTER ROLE
    case T_AlterRoleSetStmt:
    case T_CreateRoleStmt: // CREATE ROLE
    case T_DropRoleStmt:   // DROP ROLE
    case T_GrantRoleStmt:  // GRANT ROLE

        if (creating_extension)
        {
            elog(ERROR, "ROLE modifiers not allowed in extensions");
            return;
        }
        if (is_security_restricted())
        {
            elog(ERROR, "ROLE modifiers not allowed in SECURITY_RESTRICTED_OPERATION");
            return;
        }
        if (is_elevated())
        {
            elog(ERROR, "ROLE modifiers not allowed");
            return;
        }

        break;
    case T_CopyStmt: // COPY

        /* get the actual copy statement so we can check is_program and filename */
        copyStmt = (CopyStmt *)stmt;

        /* check if TO/FROM PROGRAM
         * we deny this regardless of the context we are running in
         */
        if (copyStmt->is_program)
        {
            elog(ERROR, "COPY TO/FROM PROGRAM not allowed");
            return;
        }
        /* otherwise, we don't want copy TO/FROM FILE
         * in an elevated context
         */
        if (copyStmt->filename)
        {
            if (creating_extension)
            {
                elog(ERROR, "COPY TO/FROM FILE not allowed in extensions");
                return;
            }
            if (is_security_restricted())
            {
                elog(ERROR, "COPY TO/FROM FILE not allowed in SECURITY_RESTRICTED_OPERATION");
                return;
            }
            if (is_elevated())
            {
                elog(ERROR, "COPY TO/FROM FILE not allowed");
                return;
            }
        }
        break;
    case T_VariableSetStmt:
        /* SET SESSION_AUTHORIZATION would allow bypassing of our dumb privilege escalation check.
         * even though this should be blocked in extension installation, due to
         *  ERROR:  cannot set parameter "session_authorization" within security-definer function
         * so don't do anything.
         */
        break;
    default:
        break;
    }

    /* execute the actual query */
    if (prev_ProcessUtility)
        prev_ProcessUtility(PROCESS_UTILITY_ARGS);
    else
        standard_ProcessUtility(PROCESS_UTILITY_ARGS);
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