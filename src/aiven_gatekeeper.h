#include <postgres.h>

#include <nodes/params.h>
#include <tcop/dest.h>
#include <tcop/utility.h>
#include <utils/queryenvironment.h>

/* The structure, definitions and idea of these defines was taken from
 * https://github.com/supabase/supautils/blob/f39ba4bd8eb25dbad270fc801ab850a5e72fa0f8/src/utils.h
 * This solution seems much better, cleaner and readable than
 * my attempt at using #ifdef directly in aiven_gatekeeper.c
 */ 
#define PG13_GTE (PG_VERSION_NUM >= 130000)
#define PG14_GTE (PG_VERSION_NUM >= 140000)

/* The process_utility_hook function changed in PG13 and again in PG14
 * versions from introduction (PG9) through PG12 have the same 7 argument structure
 */
#if PG14_GTE
#define PROCESS_UTILITY_PARAMS                                                 \
    PlannedStmt *pstmt, const char *queryString, bool readOnlyTree,            \
    ProcessUtilityContext context, ParamListInfo params,                   \
    QueryEnvironment *queryEnv, DestReceiver *dest, QueryCompletion *qc
#define PROCESS_UTILITY_ARGS                                                   \
    pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc

#elif PG13_GTE

#define PROCESS_UTILITY_PARAMS                                                 \
    PlannedStmt *pstmt, const char *queryString,                               \
    ProcessUtilityContext context, ParamListInfo params,                   \
    QueryEnvironment *queryEnv, DestReceiver *dest, QueryCompletion *qc
#define PROCESS_UTILITY_ARGS                                                   \
    pstmt, queryString, context, params, queryEnv, dest, qc

#else

#define PROCESS_UTILITY_PARAMS                                                 \
    PlannedStmt *pstmt, const char *queryString,                               \
    ProcessUtilityContext context, ParamListInfo params,                   \
    QueryEnvironment *queryEnv, DestReceiver *dest, char *completionTag

#define PROCESS_UTILITY_ARGS                                                   \
    pstmt, queryString, context, params, queryEnv, dest, completionTag

#endif


static bool is_elevated(void);
static bool is_security_restricted(void);
static void gatekeeper_checks(PROCESS_UTILITY_PARAMS);
static void allow_role_stmt(void);
static void allow_granted_roles(List *addroleto);
static void allow_grant_role(Oid role_oid);
static bool allowed_guc_change_check_hook(bool *newval, void **extra, GucSource source);