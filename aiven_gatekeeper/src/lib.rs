use pgrx::prelude::*;
use pgrx::GucRegistry;
use pgrx::GucFlags;
use pgrx::GucSetting;
use pgrx::GucContext;

pgrx::pg_module_magic!();

static mut PREV_PROCESS_UTILITY_HOOK: pg_sys::ProcessUtility_hook_type = None;
static mut PREV_EXECUTOR_START_HOOK: pg_sys::ExecutorStart_hook_type = None;
static  GUC_IS_STRICT: GucSetting<bool> = GucSetting::<bool>::new(false);

#[pg_extern]
fn is_enabled() -> bool {
    return true;
}

fn is_security_restricted() -> bool {
    return unsafe {pg_sys::InSecurityRestrictedOperation()};
}

fn is_elevated() -> bool {
    /* if current user != session and the current user is
     * a superuser, but the original session_user is not,
     * we can say that we are in an elevated context.
     */
    unsafe {
      let current_user_id: pg_sys::Oid = pg_sys::GetUserId();
      let session_user_id: pg_sys::Oid = pg_sys::GetSessionUserId();
      
      /* short circuit if the current and session user are the same
      * saves on a slightly more expensive role fetch
      */
      if current_user_id == session_user_id || pg_sys::CurrentResourceOwner.is_null() {
          return false;
      }

      /* elevated to supersuser when the session auth user does not have superuser privileges */
      return pg_sys::superuser_arg(current_user_id) && !pg_sys::session_auth_is_superuser;
    }
}

fn copy_stmt_checks(stmt: *mut pg_sys::Node) {
    let copy_stmt: PgBox<pg_sys::CopyStmt> = unsafe {PgBox::from_pg(stmt as *mut pg_sys::CopyStmt)};
    // always deny access to code execution
    if copy_stmt.is_program {
        pg_sys::error!("COPY TO/FROM PROGRAM not allowed");
    }

    // otherwise, check if we are trying to read from file and are in a context that allows file system access
    if !copy_stmt.filename.is_null() {
        // strict
        if GUC_IS_STRICT.get() {
          pg_sys::error!("COPY TO/FROM FILE not allowed");
        }
        // creating extension
        if is_security_restricted() {
            pg_sys::error!("COPY TO/FROM FILE not allowed in extensions");
        }
        // security restricted
        if is_security_restricted(){
            pg_sys::error!("COPY TO/FROM FILE not allowed in SECURITY_RESTRICTED_OPERATION");
        }
        // elevated
        if is_elevated(){
          pg_sys::error!("COPY TO/FROM FILE not allowed");
        }
    }
}

fn create_extension_checks(stmt: *mut pg_sys::Node) {
  // get extension statement and name of extension
  let create_ext_stmt: PgBox<pg_sys::CreateExtensionStmt>;
  let extname: String;
  unsafe {
    create_ext_stmt = PgBox::from_pg(stmt as *mut pg_sys::CreateExtensionStmt);
      extname= std::ffi::CStr::from_ptr(create_ext_stmt.extname).to_string_lossy().into_owned();
  }
  // check if disallowed extension
  if extname == "file_fdw" { // error and abort the current transaction if disallowed extension
      pg_sys::error!("{} extension not allowed", extname);
  }
}

#[pg_guard]
extern "C" fn executor_start_hook(query_desc: *mut pg_sys::QueryDesc, eflags: i32) {
  info!("ExecutorStart");
  unsafe {
    if let Some(prev_hook) = PREV_EXECUTOR_START_HOOK {
      prev_hook(query_desc, eflags);
    } else {
      pg_sys::standard_ExecutorStart(query_desc, eflags);
    }
  }
}

#[allow(clippy::too_many_arguments)]
#[pg_guard]
extern "C" fn process_utility_hook(
  pstmt: *mut pg_sys::PlannedStmt,
  query_string: *const std::os::raw::c_char,
  read_only_tree: bool,
  context: pg_sys::ProcessUtilityContext,
  params: pg_sys::ParamListInfo,
  query_env: *mut pg_sys::QueryEnvironment,
  dest: *mut pg_sys::DestReceiver,
  qc: *mut pg_sys::QueryCompletion,
) {

  let stmt: *mut pg_sys::Node = unsafe {(*pstmt).utilityStmt };
  let stmt_type: pg_sys::NodeTag = unsafe { (*stmt).type_ };

  match stmt_type{
    pg_sys::NodeTag::T_AlterRoleStmt=>info!("ALTER ROLE STATEMENT"),
    pg_sys::NodeTag::T_CreateRoleStmt=>info!("CREATE ROLE STATEMENT"),
    pg_sys::NodeTag::T_DropRoleStmt=>info!("DROP ROLE STATEMENT"),
    pg_sys::NodeTag::T_GrantRoleStmt=>info!("GRANT ROLE STATEMENT"),
    pg_sys::NodeTag::T_CopyStmt=>copy_stmt_checks(stmt),
    pg_sys::NodeTag::T_VariableSetStmt=>(), // currently we don't do any checks on VariableSet
    pg_sys::NodeTag::T_CreateFunctionStmt=>info!("CREATE FUNCTION STATEMENT"),
    pg_sys::NodeTag::T_CreateExtensionStmt=>create_extension_checks(stmt),
    _=> (),
  }

  unsafe {
    if let Some(prev_hook) = PREV_PROCESS_UTILITY_HOOK {
      prev_hook(
        pstmt,
        query_string,
        read_only_tree,
        context,
        params,
        query_env,
        dest,
        qc,
      );
    } else {
      pg_sys::standard_ProcessUtility(
        pstmt,
        query_string,
        read_only_tree,
        context,
        params,
        query_env,
        dest,
        qc,
      );
    }
  }
}

#[pg_guard]
pub extern "C" fn _PG_init() {
  unsafe {
    // if !pg_sys::process_shared_preload_libraries_in_progress {
    //   error!("aiven_pg_gatekeeper is not in shared_preload_libraries");
    // }
    
    GucRegistry::define_bool_guc(
        "aiven.pg_security_agent_strict",
        "Toggle the agent into strict mode. Reserved actions are blocked regardless of context",
        "Toggle the agent into strict mode. Reserved actions are blocked regardless of context",
        &GUC_IS_STRICT,
        GucContext::Userset,//GucContext::Postmaster,
        GucFlags::SUPERUSER_ONLY,
    );

    PREV_EXECUTOR_START_HOOK = pg_sys::ExecutorStart_hook;
    pg_sys::ExecutorStart_hook = Some(executor_start_hook);

    PREV_PROCESS_UTILITY_HOOK = pg_sys::ProcessUtility_hook;
    pg_sys::ProcessUtility_hook = Some(process_utility_hook);
  }
}

#[pg_guard]
pub extern "C" fn _PG_fini() {
  unsafe {
    pg_sys::ExecutorStart_hook = PREV_EXECUTOR_START_HOOK;
    pg_sys::ProcessUtility_hook = PREV_PROCESS_UTILITY_HOOK;
  }
}

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use pgrx::prelude::*;

    #[pg_test]
    fn test_hello_aiven_gatekeeper() {
        assert_eq!("Hello, aiven_gatekeeper", crate::hello_aiven_gatekeeper());
    }

}

/// This module is required by `cargo pgrx test` invocations.
/// It must be visible at the root of your extension crate.
#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {
        // perform one-off initialization when the pg_test framework starts
    }

    pub fn postgresql_conf_options() -> Vec<&'static str> {
        // return any postgresql.conf settings that are required for your tests
        vec![]
    }
}
