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
#include "catalog/objectaccess.h"
#include "commands/extension.h"
#include "commands/defrem.h"
#include "commands/explain.h"
#include "executor/instrument.h"
#include "nodes/value.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "parser/parse_relation.h"
#include "tcop/utility.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/fmgrtab.h"
#include "utils/lsyscache.h"
#include "utils/resowner.h"
#include "utils/varlena.h"
#include "nodes/nodes.h"
#include "access/sysattr.h"

#include "aiven_gatekeeper.h"

PG_MODULE_MAGIC;

/* session_auth_is_superuser was renamed to current_role_is_superuser */
#if PG17_GTE
#define CURRENT_ROLE_IS_SUPERUSER current_role_is_superuser
#else
#define CURRENT_ROLE_IS_SUPERUSER session_auth_is_superuser
#endif

void _PG_init(void);
void _PG_fini(void);

static bool is_elevated(void);
static bool is_security_restricted(void);
static void gatekeeper_checks(PROCESS_UTILITY_PARAMS);
static void gatekeeper_oa_hook(ObjectAccessType access,
                               Oid classId,
                               Oid objectId,
                               int subId,
                               void *arg);
static char *allow_role_stmt(void);
static void allow_granted_roles(List *addroleto);
static char *allow_grant_or_alter_role(Oid role_oid);
static bool allowed_guc_change_check_hook(bool *newval, void **extra, GucSource source);

/* disallow-list of reserved functions we don't want to give access to
 * as these can be abused in to get local filesystem access or as a step
 * in gaining code execution.
 */
static const char *reserved_func_names[] = {"pg_read_file",
                                            "pg_read_file_off_len",
                                            "pg_read_file_v2",
                                            "pg_read_file_all",
                                            "pg_read_binary_file",
                                            "pg_read_binary_file_all",
                                            "pg_read_binary_file_off_len",
                                            "pg_reload_conf",
                                            "be_lo_import",
                                            "be_lo_export",
                                            "be_lo_import_with_oid"};
static const int NUM_RESERVED_FUNCS = sizeof reserved_func_names / sizeof reserved_func_names[0];
static Oid *reserved_func_oids; // array to track the oids of the above reserved_func_names
static int max_reserved_oid = 0;
static int min_reserved_oid = 9000;

/* reserverd columns in the pg_proc table that aren't permitted to be modified */
static const char *reserved_col_names[] = {"proowner", "proacl", "prolang", "prosecdef"};
static const int NUM_RESERVED_COLS = sizeof reserved_col_names / sizeof reserved_col_names[0];

/* reserved columns in the pg_authid table that aren't permitted to be read */
static const char *reserved_auth_col_names[] = {"rolpassword"};
static const int NUM_RESERVED_AUTH_COLS = sizeof reserved_auth_col_names / sizeof reserved_auth_col_names[0];

/* GUC Variables */
static bool pg_security_agent_enabled = false;
static bool pg_security_agent_strict = false;
static char *allowed_superuser_roles = NULL;

/* Saved hook values in case of unload */
static ProcessUtility_hook_type prev_ProcessUtility = NULL;
static object_access_hook_type next_object_access_hook = NULL;
static ExecutorStart_hook_type prev_ExecutorStart_hook = NULL;

/* bug that breaks some extension functionality due to nested queries inadvertently
    reading, but not using, a reserved column name
*/
static bool BUG_01 = true;

static bool
allowed_guc_change_check_hook(bool *newval, void **extra, GucSource source)
{
    // Allow the change during early startup
    if (!IsUnderPostmaster) {
        return true;
    }

    /* don't allow setting the config value from an elevated context
     * otherwise a combination of ALTER SYSTEM SET aiven.pg_security_agent TO off;
     * SELECT pg_reload_conf(); could be used in a two step attack to disable
     * the security agent. Only allow setting the security agent if the current session is
     * a superuser session (eg: login as postgres).
     * We should be safe-ish anyway, as ALTER SYSTEM can't be executed from a function. But
     * doesn't hurt to be careful.
     */
    return !(pg_security_agent_strict || creating_extension || is_security_restricted() || is_elevated());
}

static bool
allowed_guc_change_allowed_superusers(char **newval, void **extra, GucSource source)
{
    // Allow the change during early startup
    if (!IsUnderPostmaster) {
        return true;
    }

    /* same as with the boolean version */
    return !(pg_security_agent_strict || creating_extension || is_security_restricted() || is_elevated());
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
    if (currentUserId == sessionUserId || CurrentResourceOwner == NULL)
    {
        return false;
    }

    is_superuser = superuser_arg(currentUserId);
    /* elevated to supersuser when the session auth user does not have superuser privileges */
    return is_superuser && !CURRENT_ROLE_IS_SUPERUSER;
}

static bool
is_security_restricted(void)
{
    /* checks if we are in a security_restricted context
     * this occurs during VACUUM, ANALYZE, MATERIAL VIEW etc
     */
    return InSecurityRestrictedOperation();
}

/* check if a target role is in the list of roles that are permitted to have superuser */
static bool
allow_superuser_role(const char *target_role)
{
    List *allowed_superuser_list;
    ListCell *role;

    if (allowed_superuser_roles)
    {
        SplitIdentifierString(pstrdup(allowed_superuser_roles), ',', &allowed_superuser_list);

        foreach (role, allowed_superuser_list)
        {
            char *allowed_role = (char *)lfirst(role);
            if (strcmp(target_role, allowed_role) == 0)
            {
                list_free(allowed_superuser_list);
                return true;
            }
        }
        list_free(allowed_superuser_list);
    }
    return false;
}

static char *
allow_role_stmt(void)
{
    if (pg_security_agent_strict)
        return "ROLE modification to SUPERUSER/privileged role not allowed";

    if (creating_extension)
        return "ROLE modification to SUPERUSER/privileged role not allowed in extensions";

    if (is_security_restricted())
        return "ROLE modification to SUPERUSER/privileged role not allowed in SECURITY_RESTRICTED_OPERATION";

    if (is_elevated())
        return "ROLE modification to SUPERUSER/privileged role not allowed";

    return NULL;
}

static void
allow_granted_roles(List *addroleto)
{
    ListCell *role_cell;
    RoleSpec *rolemember;
    Oid role_member_oid;
    char *result;
    // check if any of the roles we are trying to add to have superuser
    foreach (role_cell, addroleto)
    {
        rolemember = lfirst(role_cell);
        role_member_oid = get_rolespec_oid(rolemember, false);
        result = allow_grant_or_alter_role(role_member_oid);
        if (result != NULL)
        {
            elog(ERROR, "%s", result);
            return;
        }
    }
}

static char *
allow_grant_or_alter_role(Oid role_oid)
{
    /* check if we are trying to alter a reserved (privileged) role, or grant
     * access to superuser or privileged roles
     * we first need to fetch the oid's of the reserved roles.
     * these would be nice to pull from header files, but the required
     * headers are generated using src/backend/catalog/genbki.pl and aren't guaranteed to exist.
     */
    Oid role_pg_execute_server_program;
    Oid role_pg_read_server_files;
    Oid role_pg_write_server_files;

    role_pg_execute_server_program = get_role_oid("pg_execute_server_program", true);
    role_pg_read_server_files = get_role_oid("pg_read_server_files", true);
    role_pg_write_server_files = get_role_oid("pg_write_server_files", true);

    if (superuser_arg(role_oid) ||
        is_member_of_role(role_oid, role_pg_execute_server_program) ||
        is_member_of_role(role_oid, role_pg_read_server_files) ||
        is_member_of_role(role_oid, role_pg_write_server_files))
    {
        return allow_role_stmt();
    }
    return NULL;
}

static void
gatekeeper_checks(PROCESS_UTILITY_PARAMS)
{
    Node *stmt;
    CopyStmt *copyStmt;
    CreateRoleStmt *createRoleStmt;
    AlterRoleStmt *alterRoleStmt;
    GrantRoleStmt *grantRoleStmt;
    CreateFunctionStmt *createFuncStmt;
    CreateExtensionStmt *createExtStmt;
    ListCell *option;
    DefElem *defel;
    List *addroleto;
    ListCell *grantRoleCell;
    AccessPriv *priv;
    Oid roleoid;
    char *funcLang;
    int i;
    bool checkBody;
    char *sqlBody;
    char *result;

    /* if the agent is disabled, skip all checks */
    if (!pg_security_agent_enabled)
    {
        /* execute the actual query */
        if (prev_ProcessUtility)
            prev_ProcessUtility(PROCESS_UTILITY_ARGS);
        else
            standard_ProcessUtility(PROCESS_UTILITY_ARGS);

        /* we are done executing, exit the function */
        return;
    }

    /* get the utilty statment from the planner
     * https://github.com/postgres/postgres/blob/24d2b2680a8d0e01b30ce8a41c4eb3b47aca5031/src/backend/tcop/utility.c#L575
     */
    stmt = pstmt->utilityStmt;
    /* switch between the types to see if we care about this stmt */
    switch (stmt->type)
    {
    case T_AlterRoleStmt: // ALTER ROLE
        alterRoleStmt = (AlterRoleStmt *)stmt;

        // check we aren't altering a reserved role (existing superuser)
        roleoid = get_rolespec_oid(alterRoleStmt->role, true);
        result = allow_grant_or_alter_role(roleoid);
        if (result != NULL)
            elog(ERROR, "%s", result);

        // check if we are altering with superuser
        foreach (option, alterRoleStmt->options)
        {
            defel = (DefElem *)lfirst(option);
            // superuser or nosuperuser is supplied (both are treated as defname superuser) and check that the arg is set to true
            if (strncmp(defel->defname, "superuser", 10) == 0 && defGetBoolean(defel))
            {
                // regardless of context (elevated privilege or not), check if the target role is allowed to be superuser
                if (!allow_superuser_role(alterRoleStmt->role->rolename))
                    elog(ERROR, "Role %s not in permitted superuser list", alterRoleStmt->role->rolename);

                result = allow_role_stmt();
                if (result != NULL)
                    elog(ERROR, "%s", result);
            }
        }
        break;
    case T_CreateRoleStmt: // CREATE ROLE
        createRoleStmt = (CreateRoleStmt *)stmt;

        foreach (option, createRoleStmt->options)
        {
            defel = (DefElem *)lfirst(option);

            // check if we are granting superuser
            if (strncmp(defel->defname, "superuser", 10) == 0 && defGetBoolean(defel))
            {
                // regardless of context (elevated privilege or not), check if the target role is allowed to be superuser
                if (!allow_superuser_role(createRoleStmt->role))
                    elog(ERROR, "Role %s not in permitted superuser list", createRoleStmt->role);

                result = allow_role_stmt();
                if (result != NULL)
                    elog(ERROR, "%s", result);
            }

            // check if user is being added to a role that has superuser or other high privilege
            if (strncmp(defel->defname, "addroleto", 10) == 0)
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
            result = allow_grant_or_alter_role(roleoid);
            if (result != NULL)
                elog(ERROR, "%s", result);
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
            if (pg_security_agent_strict)
            {
                elog(ERROR, "COPY TO/FROM FILE not allowed");
                return;
            }
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
    case T_CreateFunctionStmt:
        createFuncStmt = (CreateFunctionStmt *)stmt;
        checkBody = false; // used for versions prior to 14, where the sql_body is not availble in the CreateFuncStmt struct

        foreach (option, createFuncStmt->options)
        {
            defel = (DefElem *)lfirst(option);

            /* check if of language type internal
             * this is not accessible to untrusted users, so disable if elevated context
             */
            if (strncmp(defel->defname, "language", 9) == 0)
            {
                funcLang = defGetString(defel);
                /* check if restricted language type */
                if (strncmp(funcLang, "plperlu", 8) == 0 ||
                    strncmp(funcLang, "plpythonu", 10) == 0)
                {
                    if (pg_security_agent_strict)
                    {
                        elog(ERROR, "LANGUAGE %s not allowed", funcLang);
                        return;
                    }
                    if (creating_extension)
                    {
                        elog(ERROR, "LANGUAGE %s not allowed in extensions", funcLang);
                        return;
                    }
                    if (is_security_restricted())
                    {
                        elog(ERROR, "LANGUAGE %s not allowed in SECURITY_RESTRICTED_OPERATION", funcLang);
                        return;
                    }
                    if (is_elevated())
                    {
                        elog(ERROR, "LANGUAGE %s not allowed", funcLang);
                        return;
                    }
                }
                else if (strncmp(funcLang, "internal", 9) == 0 && (pg_security_agent_strict || creating_extension || is_elevated() || is_security_restricted()))
                {
                    checkBody = true;
                }
            }
            /* extract the sql body so we can use it to check if restricted internal
             * function is being declared
             */
            if (strncmp(defel->defname, "as", 3) == 0)
            {
                sqlBody = defGetString(defel);
            }
        }
        /* we need to check the sql body, as we are in restricted context and the function is of type internal*/
        if (checkBody == true)
        {
            for (i = 0; i < NUM_RESERVED_FUNCS; i++)
            {
                /* internal names are case sensitive, so strcmp is fine here */
                if (strncmp(reserved_func_names[i], sqlBody, 28) == 0)
                {
                    elog(ERROR, "using builtin function %s is not allowed", sqlBody);
                    return;
                }
            }
        }
        break;
    case T_CreateExtensionStmt:
        /* block file_fdw extension. Case sensitive compare is ok, since the extension name is lower case when read from extname*/
        createExtStmt = (CreateExtensionStmt *)stmt;
        if (strncmp(createExtStmt->extname, "file_fdw", 9) == 0)
        {
            elog(ERROR, "file_fdw extension not allowed");
            return;
        }
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

/* straight copy from fmgr.c
 * this function isn't exported by fmgr.c, so just
 * recreate it here
 */
static const FmgrBuiltin *
fmgr_lookupByName(const char *name)
{
    int i;

    for (i = 0; i < fmgr_nbuiltins; i++)
    {
        // switched to strncmp, 28 is the current max size that can be expected for name, as from reserved_func_names
        if (strncmp(name, fmgr_builtins[i].funcName, 28) == 0)
            return fmgr_builtins + i;
    }
    return NULL;
}

static bool
set_reserved_oids()
{
    /* sets the min and max_reserved_oid variables, allowing for skipping builtins search
     * if an oid is clearly not going to be in the builtins.
     */
    const FmgrBuiltin *builtin;
    int i;

    reserved_func_oids = (Oid *)malloc(NUM_RESERVED_FUNCS * sizeof(Oid));
    if (reserved_func_oids == NULL)
    {
        return false;
    }
    /* loop through the function names we have defined as reserved
     * lookup the oid of the function so that we can use this for future
     * evaluations rather than comparing strings
     * and find the maximum oid
     */
    for (i = 0; i < NUM_RESERVED_FUNCS; i++)
    {
        if ((builtin = fmgr_lookupByName(reserved_func_names[i])) != NULL)
        {
            reserved_func_oids[i] = builtin->foid;
            if (builtin->foid < min_reserved_oid)
            {
                min_reserved_oid = builtin->foid;
            }
            else if (builtin->foid > max_reserved_oid)
            {
                max_reserved_oid = builtin->foid;
            }
        }
    }
    return true;
}

/* hook to check if the function being called is not in the disallowed-list
 * obviously allow list of built-in functions would be prefered, but this list of disallowed is tiny
 * and we want to ensure minimum impact on performance and function.
 */
static void
gatekeeper_oa_hook(ObjectAccessType access,
                   Oid classId,
                   Oid objectId,
                   int subId,
                   void *arg)
{
    const FmgrBuiltin *builtin;
    int i;

    /* only check function if security agent is enabled */
    if (pg_security_agent_enabled)
    {
        switch (access) // we are only interested in the OAT_FUNCTION_EXECUTE ObjectAccessType
        {
        case OAT_FUNCTION_EXECUTE:
            /* check if the objecid is within range of our reserved oids
             * this allows faster evalation, rather than having to loop through
             * arrays for each function call.
             */
            if (objectId >= min_reserved_oid && objectId <= max_reserved_oid)
            {
                for (i = 0; i < NUM_RESERVED_FUNCS; i++)
                {
                    /* lookup the oid to see if it is in our reserved list
                     */
                    if (reserved_func_oids[i] == objectId)
                    {
                        /* check if we are in a privileged context and disallow the function executions */
                        if (pg_security_agent_strict || creating_extension || is_elevated() || is_security_restricted())
                        {
                            /* get the function information so that error message can be more friendly */
                            if ((builtin = fmgr_lookupByName(reserved_func_names[i])) != NULL)
                            {
                                elog(ERROR, "using builtin function %s is not allowed", builtin->funcName);
                                return;
                            }
                        }
                        /* extra check, this is to enforce only superuser can call this function in normal
                         * context. Otherwise PG uses the grant system, which could lead to roles being
                         * granted execute privilege on the funcion and still being able to call it.
                         * This is not too serious, since non-superusers can't read outside reserved paths (for example)
                         * but rather be strict.
                         */
                        if (!superuser())
                        {
                            if ((builtin = fmgr_lookupByName(reserved_func_names[i])) != NULL)
                            {
                                elog(ERROR, "using builtin function %s is not allowed by non-superusers", builtin->funcName);
                                return;
                            }
                        }
                        break;
                    }
                }
            }
            break;
        default:
            break;
        }
    }

    if (next_object_access_hook)
        (*next_object_access_hook)(access, classId, objectId, subId, arg);
}

static void
pg_proc_guard_checks(QueryDesc *queryDesc, int eflags)
{
    /* check if there is an attempt to modify the pg_proc table
     * this should never happen directly in extension installs
     * or elevated context. Superuser is allowed to modify pg_proc, but
     * probably doesn't want to be doing this manually.
     */
    ListCell *resultRelations;
    RangeTblEntry *rt;
    Bitmapset *colset;
    int index;
#if PG16_GTE
    List *permInfos;
    RTEPermissionInfo *permInfo;
#endif
    /* only check function if security agent is enabled */
    if (pg_security_agent_enabled && !BUG_01)
    {
        switch (queryDesc->operation)
        {
        case CMD_SELECT:
#if PG16_GTE
	    permInfos = queryDesc->plannedstmt->permInfos;
#endif
            foreach (resultRelations, queryDesc->plannedstmt->rtable)
            {
                rt = lfirst(resultRelations);
                switch (rt->relid)
                {
                case 1260: // pg_authid
#if PG16_GTE
                    permInfo = getRTEPermissionInfo(permInfos, rt);
                    colset = permInfo->selectedCols;
#else
                    colset = rt->selectedCols;
#endif
                    index = -1;
                    while ((index = bms_next_member(colset, index)) >= 0)
                    {
                        AttrNumber attno = index + FirstLowInvalidHeapAttributeNumber;
                        char *attname;
                        int i;

                        /* get the column name, function definition changed with PG11 */
#if PG11_GTE
                        attname = get_attname(1260, attno, true);
#else
                        attname = get_attname(1260, attno);
#endif
                        /* check if column is reserved */
                        for (i = 0; i < NUM_RESERVED_AUTH_COLS; i++)
                        {
                            if (strncmp(reserved_auth_col_names[i], attname, 10) == 0 && (pg_security_agent_strict || creating_extension || is_elevated() || is_security_restricted()))
                            {
                                elog(ERROR, "Reading pg_authid sensitive columns is not allowed in elevated context");
                                return;
                            }
                        }
                    }
                    break;
                default:
                    break;
                }
            }
            break;
        case CMD_INSERT:
        case CMD_UPDATE:
        case CMD_DELETE:
#if PG16_GTE
	    permInfos = queryDesc->plannedstmt->permInfos;
#endif
            foreach (resultRelations, queryDesc->plannedstmt->rtable)
            {
                rt = lfirst(resultRelations);
                switch (rt->relid)
                {
                case 1260: // pg_authid
                case 1261: // pg_auth_membership
                    if (pg_security_agent_strict || creating_extension || is_elevated() || is_security_restricted())
                    {
                        elog(ERROR, "Modifying pg_authid or pg_auth_members is not allowed in elevated context");
                        return;
                    }
                    break;
                case 1255: // pg_proc
                    /* check columns being modified and prevent creating new internal functions
                     * would prefer to just prevent pg_proc modification, but some extensions in contrib
                     * actually alter pg_proc directly during install/upgrade.
                     * block changes to proowner, prolang, prosecdef, proacl, prosrc
                     */
#if PG16_GTE
                    permInfo = getRTEPermissionInfo(permInfos, rt);
                    if (queryDesc->operation == CMD_INSERT)
                        colset = permInfo->insertedCols;
                    else
                        colset = permInfo->updatedCols;
#else
                    if (queryDesc->operation == CMD_INSERT)
                        colset = rt->insertedCols;
                    else
                        colset = rt->updatedCols;
#endif
                    index = -1;
                    while ((index = bms_next_member(colset, index)) >= 0)
                    {
                        AttrNumber attno = index + FirstLowInvalidHeapAttributeNumber;
                        char *attname;
                        int i;

                        /* get the column name, function definition changed with PG11 */
#if PG11_GTE
                        attname = get_attname(1255, attno, true);
#else
                        attname = get_attname(1255, attno);
#endif
                        /* check if column is reserved */
                        for (i = 0; i < NUM_RESERVED_COLS; i++)
                        {
                            if (strncmp(reserved_col_names[i], attname, 10) == 0 && (pg_security_agent_strict || creating_extension || is_elevated() || is_security_restricted()))
                            {
                                elog(ERROR, "Modifying pg_proc sensitive columns is not allowed in elevated context");
                                return;
                            }
                        }
                    }
                    break;
                default:
                    break;
                }
            }
            break;
        default:
            break;
        }
    }

    if (prev_ExecutorStart_hook)
        prev_ExecutorStart_hook(queryDesc, eflags);
    else
        standard_ExecutorStart(queryDesc, eflags);
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

    // comma-separated list of allowed superuser roles (can be assigned superuser)
    DefineCustomStringVariable("aiven.pg_security_agent_reserved_roles",
                               "Comma-separated list of roles that can be assigned superuser",
                               NULL,
                               &allowed_superuser_roles,
                               "postgres",         // default to postgres
                               PGC_POSTMASTER,     // only at postmaster startup
                               GUC_SUPERUSER_ONLY, // only show to superuser
                               allowed_guc_change_allowed_superusers,
                               NULL,
                               NULL);

    // allow toggling of the security agent
    // this variable definition should always be last, otherwise further defines
    // stop working because the agent has defaulted to strict = on
    DefineCustomBoolVariable("aiven.pg_security_agent_strict",
                             "Toggle the agent into strict mode. Reserved actions are blocked regardless of context",
                             NULL,
                             &pg_security_agent_strict,
                             false,              // default to 'off'
                             PGC_POSTMASTER,     // only at postmaster startup
                             GUC_SUPERUSER_ONLY, // only show to superuser
                             allowed_guc_change_check_hook,
                             NULL,
                             NULL);


    if (set_reserved_oids())
    {
        /* Install Hooks */
        prev_ProcessUtility = ProcessUtility_hook;
        ProcessUtility_hook = gatekeeper_checks;

        next_object_access_hook = object_access_hook;
        object_access_hook = gatekeeper_oa_hook;

        prev_ExecutorStart_hook = ExecutorStart_hook;
        ExecutorStart_hook = pg_proc_guard_checks;
    }
    else
    {
        elog(ERROR, "Failed to initialise aiven gatekeeper.");
    }
}

/*
 * Module unload callback
 */
void _PG_fini(void)
{
    /* free malloc(s) */
    if (reserved_func_oids != NULL)
        free(reserved_func_oids);

    /* Uninstall hooks. */
    ProcessUtility_hook = prev_ProcessUtility;
    object_access_hook = next_object_access_hook;
    ExecutorStart_hook = prev_ExecutorStart_hook;
}
