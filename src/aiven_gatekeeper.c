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
#include "catalog/pg_authid.h"
#include "commands/extension.h"
#include "commands/defrem.h"
#include "nodes/value.h"
#include "miscadmin.h"
#include "tcop/utility.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "nodes/nodes.h"

#include "aiven_gatekeeper.h"

PG_MODULE_MAGIC;

void _PG_init(void);
void _PG_fini(void);

static bool is_elevated(void);
static bool is_security_restricted(void);
static void gatekeeper_checks(PROCESS_UTILITY_PARAMS);
static void allow_role_stmt(void);
static void allow_granted_roles(List *addroleto);
static void allow_grant_role(Oid role_oid);
static bool allowed_guc_change_check_hook(bool *newval, void **extra, GucSource source);

/* GUC Variables */
static bool pg_security_agent_enabled = false;

/* Saved hook values in case of unload */
static ProcessUtility_hook_type prev_ProcessUtility = NULL;

static bool
allowed_guc_change_check_hook(bool *newval, void **extra, GucSource source)
{
    /* don't allow setting the config value from an elevated context
     * otherwise a combination of ALTER SYSTEM SET aiven.pg_security_agent TO off;
     * SELECT pg_reload_conf(); could be used in a two step attack to disable
     * the security agent. Only allow setting the security agent if the current session is
     * a superuser session (eg: login as postgres).
     * We should be safe-ish anyway, as ALTER SYSTEM can't be executed from a function. But
     * doesn't hurt to be careful.
     */
    return !(creating_extension || is_security_restricted() || is_elevated());
}
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
     */
    return InSecurityRestrictedOperation();
}

static void
allow_role_stmt(void)
{
    if (creating_extension)
        elog(ERROR, "ROLE modification to SUPERUSER not allowed in extensions");

    if (is_security_restricted())
        elog(ERROR, "ROLE modification to SUPERUSER not allowed in SECURITY_RESTRICTED_OPERATION");

    if (is_elevated())
        elog(ERROR, "ROLE modification to SUPERUSER not allowed");
}

static void
allow_granted_roles(List *addroleto)
{
    ListCell *role_cell;
    RoleSpec *rolemember;
    Oid role_member_oid;

    // check if any of the roles we are trying to add to have superuser
    foreach (role_cell, addroleto)
    {
        rolemember = lfirst(role_cell);
        role_member_oid = get_rolespec_oid(rolemember, false);
        if (superuser_arg(role_member_oid))
            allow_role_stmt();
    }
}
static void
allow_grant_role(Oid role_oid)
{
    /* check we aren't granting superuser or privileged roles
     */
    if (superuser_arg(role_oid) ||
        is_member_of_role(role_oid, ROLE_PG_EXECUTE_SERVER_PROGRAM) ||
        is_member_of_role(role_oid, ROLE_PG_READ_SERVER_FILES) ||
        is_member_of_role(role_oid, ROLE_PG_WRITE_SERVER_FILES))
        allow_role_stmt();
}

static void
gatekeeper_checks(PROCESS_UTILITY_PARAMS)
{
    /* if the agent is disabled, skip all checks */
    if (!pg_security_agent_enabled)
    {
        /* execute the actual query */
        if (prev_ProcessUtility)
            prev_ProcessUtility(PROCESS_UTILITY_ARGS);
        else
            standard_ProcessUtility(PROCESS_UTILITY_ARGS);
    }

    /* get the utilty statment from the planner
     * https://github.com/postgres/postgres/blob/24d2b2680a8d0e01b30ce8a41c4eb3b47aca5031/src/backend/tcop/utility.c#L575
     */
    Node *stmt = pstmt->utilityStmt;
    CopyStmt *copyStmt;
    CreateRoleStmt *createRoleStmt;
    AlterRoleStmt *alterRoleStmt;
    GrantRoleStmt *grantRoleStmt;
    ListCell *option;
    DefElem *defel;
    List *addroleto;
    ListCell *grantRoleCell;
    AccessPriv *priv;
    Oid roleoid;

    /* switch between the types to see if we care about this stmt */
    switch (stmt->type)
    {
    case T_AlterRoleStmt: // ALTER ROLE
    case T_AlterRoleSetStmt:
        alterRoleStmt = (AlterRoleStmt *)stmt;
        // check if we are altering with superuser

        foreach (option, alterRoleStmt->options)
        {
            defel = (DefElem *)lfirst(option);
            // superuser or nosuperuser is supplied (both are treated as defname superuser) and check that the arg is set to true
            if (strcmp(defel->defname, "superuser") == 0 && defGetBoolean(defel))
            {
                allow_role_stmt();
            }
        }
        break;
    case T_CreateRoleStmt: // CREATE ROLE
        createRoleStmt = (CreateRoleStmt *)stmt;

        foreach (option, createRoleStmt->options)
        {
            defel = (DefElem *)lfirst(option);

            // check if we are granting superuser
            if (strcmp(defel->defname, "superuser") == 0 && defGetBoolean(defel))
                allow_role_stmt();

            // check if user is being added to a role that has superuser
            if (strcmp(defel->defname, "addroleto") == 0)
            {
                addroleto = (List *)defel->arg;
                allow_granted_roles(addroleto);
            }
        }
        break;
    case T_DropRoleStmt: // DROP ROLE
        // don't allow dropping role from elevated context
        // this should be a check for dropping reserved roles
        // allow_role_stmt();
        break;
    case T_GrantRoleStmt: // GRANT ROLE
        grantRoleStmt = (GrantRoleStmt *)stmt;

        // check if any of the granted roles have superuser permission
        foreach (grantRoleCell, grantRoleStmt->granted_roles)
        {
            priv = (AccessPriv *)lfirst(grantRoleCell);
            roleoid = get_role_oid(priv->priv_name, false);
            allow_grant_role(roleoid);
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

    // allow toggling of the security agent
    DefineCustomBoolVariable("aiven.pg_security_agent",
                             "Toggle the security agent checks on and off",
                             NULL,
                             &pg_security_agent_enabled,
                             true,               // default to 'on'
                             PGC_SIGHUP,         // only superusers can set, or at postmaster startup
                             GUC_SUPERUSER_ONLY, // only show to superuser
                             allowed_guc_change_check_hook,
                             NULL,
                             NULL);
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