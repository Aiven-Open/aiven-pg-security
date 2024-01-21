use pgrx::pg_sys;

use crate::is_security_restricted;

pub fn is_local_user_id_change() -> bool {
    unsafe{
        return pg_sys::InLocalUserIdChange();
    }
}

pub fn is_restricted_role_or_grant(role_oid: pg_sys::Oid) -> bool {
    /* check if we are trying to alter a reserved (privileged) role, or grant
     * access to superuser or privileged roles
     * we first need to fetch the oid's of the reserved roles.
     * these would be nice to pull from header files, but the required
     * headers are generated using src/backend/catalog/genbki.pl and aren't guaranteed to exist.
     */
    const PG_EXECUTE_SERVER_PROGRAM_NAME: &[u8] = b"pg_execute_server_program\0";
    const PG_READ_SERVER_FILES_NAME: &[u8] = b"pg_read_server_files\0";
    const PG_WRITE_SERVER_FILES_NAME: &[u8] = b"pg_write_server_files\0";

    unsafe {
        if pg_sys::superuser_arg(role_oid) {
            return true;
        }
        let role_pg_execute_server_program: pg_sys::Oid = pg_sys::get_role_oid(PG_EXECUTE_SERVER_PROGRAM_NAME.as_ptr().cast(), true);
        let role_pg_read_server_files: pg_sys::Oid = pg_sys::get_role_oid(PG_READ_SERVER_FILES_NAME.as_ptr().cast(), true);
        let role_pg_write_server_files: pg_sys::Oid = pg_sys::get_role_oid(PG_WRITE_SERVER_FILES_NAME.as_ptr().cast(), true);
        if pg_sys::is_member_of_role(role_oid, role_pg_execute_server_program) ||
           pg_sys::is_member_of_role(role_oid, role_pg_read_server_files) ||
           pg_sys::is_member_of_role(role_oid, role_pg_write_server_files) {
                return true;
        }
    }
    return false;
}

pub fn is_elevated() -> bool {
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

pub fn is_role_modify_allowed(in_strict_mode: bool) -> Result<bool, &'static str> {
    if in_strict_mode || is_elevated() {
        return Err("ROLE modification to SUPERUSER/privileged role not allowed");
    }

    if is_security_restricted() {
        return Err("ROLE modification to SUPERUSER/privileged role not allowed in SECURITY_RESTRICTED_OPERATION");
    }

    if is_local_user_id_change() {
        return Err("ROLE modification to SUPERUSER/privileged role not allowed in extensions");
    }
    return Ok(true);
}

pub fn is_allowed_superuser_role(role_name: &str, reserved_roles: &str) -> bool {
    let roles: std::str::Split<'_, &str> = reserved_roles.split(",");
    for role in roles {
        if role == role_name {
            return true;
        }
    }
    return false;
}
