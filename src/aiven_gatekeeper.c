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
#include "utils/fmgroids.h"
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
static bool is_reserved_func_oid(Oid foid);

/* disallow-list of reserved builtin functions we don't want to give access to
 * as these can be abused in to get local filesystem access or as a step
 * in gaining code execution.
 *
 * builtin function oids are fixed in pg_proc.dat and never change for an
 * existing function, even when its C symbol is renamed (as happened to the
 * pg_read_file family in PG16), so the list is kept as oids via the macros
 * from utils/fmgroids.h. Variants that only exist on some major versions are
 * guarded with #ifdef.
 *
 * Before PG14 the fmgroids.h macros were named after the C symbol (prosrc),
 * from PG14 on they are named after the SQL name and argument types. The oids
 * are the same in both branches.
 */
static const Oid reserved_func_oids[] = {
#if PG14_GTE
    /* pg_read_file */
    F_PG_READ_FILE_TEXT,                       /* 3826 */
    F_PG_READ_FILE_TEXT_INT8_INT8,             /* 2624 */
    F_PG_READ_FILE_TEXT_INT8_INT8_BOOL,        /* 3293 */
#ifdef F_PG_READ_FILE_TEXT_BOOL                /* PG16+ */
    F_PG_READ_FILE_TEXT_BOOL,                  /* 6208 */
#endif
#ifdef F_PG_READ_FILE_OLD                      /* removed in PG17 */
    F_PG_READ_FILE_OLD,                        /* 4100 */
#endif
    /* pg_read_binary_file */
    F_PG_READ_BINARY_FILE_TEXT,                /* 3828 */
    F_PG_READ_BINARY_FILE_TEXT_INT8_INT8,      /* 3827 */
    F_PG_READ_BINARY_FILE_TEXT_INT8_INT8_BOOL, /* 3295 */
#ifdef F_PG_READ_BINARY_FILE_TEXT_BOOL         /* PG16+ */
    F_PG_READ_BINARY_FILE_TEXT_BOOL,           /* 6209 */
#endif
    F_PG_RELOAD_CONF,                          /* 2621 */
    /* lo_import / lo_export */
    F_LO_IMPORT_TEXT,                          /* 764 */
    F_LO_IMPORT_TEXT_OID,                      /* 767 */
    F_LO_EXPORT,                               /* 765 */
#else
    /* pg_read_file */
    F_PG_READ_FILE_ALL,                        /* 3826 */
    F_PG_READ_FILE_OFF_LEN,                    /* 2624 */
    F_PG_READ_FILE_V2,                         /* 3293 */
    F_PG_READ_FILE,                            /* 4100, pg_read_file_old */
    /* pg_read_binary_file */
    F_PG_READ_BINARY_FILE_ALL,                 /* 3828 */
    F_PG_READ_BINARY_FILE_OFF_LEN,             /* 3827 */
    F_PG_READ_BINARY_FILE,                     /* 3295 */
    F_PG_RELOAD_CONF,                          /* 2621 */
    /* lo_import / lo_export */
    F_BE_LO_IMPORT,                            /* 764 */
    F_BE_LO_IMPORT_WITH_OID,                   /* 767 */
    F_BE_LO_EXPORT,                            /* 765 */
#endif
};
static const int NUM_RESERVED_FUNCS = lengthof(reserved_func_oids);
/* range of reserved_func_oids, computed in _PG_init, allows skipping the search for most function calls */
static Oid max_reserved_oid = InvalidOid;
static Oid min_reserved_oid = InvalidOid;

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

    int secContext = 0;
    Oid currentUserId = InvalidOid;
    Oid sessionUserId;
    bool is_superuser;
    
    /* when starting up we can't call GetUserId() because
     * that requires a valid user to be set. Check manually
     * and bail out if that is the case.
     */
    GetUserIdAndSecContext(&currentUserId, &secContext);
    if (!OidIsValid(currentUserId))
        return false;

    sessionUserId = GetSessionUserId();

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
    bool checkBody;
    char *sqlBody = "";
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
        /* we need to check the sql body, as we are in restricted context and the function is of type internal.
         * the body is the C symbol name of a builtin, resolve it to the builtin oid so that we don't have to
         * track the symbol names, which change between major versions
         */
        if (checkBody == true && sqlBody != NULL && is_reserved_func_oid(fmgr_internal_function(sqlBody)))
        {
            elog(ERROR, "using builtin function %s is not allowed", sqlBody);
            return;
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

/* returns true if foid is one of the reserved builtin functions */
static bool
is_reserved_func_oid(Oid foid)
{
    int i;

    /* check if the oid is within range of our reserved oids
     * this allows faster evaluation, rather than having to loop through
     * the array for each function call.
     */
    if (foid < min_reserved_oid || foid > max_reserved_oid)
        return false;

    for (i = 0; i < NUM_RESERVED_FUNCS; i++)
    {
        if (reserved_func_oids[i] == foid)
            return true;
    }
    return false;
}

static void
set_reserved_oid_range(void)
{
    /* sets the min and max_reserved_oid variables from the static oid list */
    int i;

    min_reserved_oid = max_reserved_oid = reserved_func_oids[0];
    for (i = 1; i < NUM_RESERVED_FUNCS; i++)
    {
        if (reserved_func_oids[i] < min_reserved_oid)
            min_reserved_oid = reserved_func_oids[i];
        if (reserved_func_oids[i] > max_reserved_oid)
            max_reserved_oid = reserved_func_oids[i];
    }
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
    /* only check function if security agent is enabled */
    if (pg_security_agent_enabled)
    {
        switch (access) // we are only interested in the OAT_FUNCTION_EXECUTE ObjectAccessType
        {
        case OAT_FUNCTION_EXECUTE:
            if (is_reserved_func_oid(objectId))
            {
                /* check if we are in a privileged context and disallow the function executions */
                if (pg_security_agent_strict || creating_extension || is_elevated() || is_security_restricted())
                {
                    elog(ERROR, "using builtin function %s is not allowed", get_func_name(objectId));
                    return;
                }
                /* extra check, this is to enforce only superuser can call this function in normal
                 * context. Otherwise PG uses the grant system, which could lead to roles being
                 * granted execute privilege on the funcion and still being able to call it.
                 * This is not too serious, since non-superusers can't read outside reserved paths (for example)
                 * but rather be strict.
                 */
                if (!superuser())
                {
                    elog(ERROR, "using builtin function %s is not allowed by non-superusers", get_func_name(objectId));
                    return;
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


    set_reserved_oid_range();

    /* Install Hooks */
    prev_ProcessUtility = ProcessUtility_hook;
    ProcessUtility_hook = gatekeeper_checks;

    next_object_access_hook = object_access_hook;
    object_access_hook = gatekeeper_oa_hook;

    prev_ExecutorStart_hook = ExecutorStart_hook;
    ExecutorStart_hook = pg_proc_guard_checks;
}

/*
 * Module unload callback
 */
void _PG_fini(void)
{
    /* Uninstall hooks. */
    ProcessUtility_hook = prev_ProcessUtility;
    object_access_hook = next_object_access_hook;
    ExecutorStart_hook = prev_ExecutorStart_hook;
}
