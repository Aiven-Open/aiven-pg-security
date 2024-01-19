
use pgrx::pg_sys;

use crate::{roles::{is_elevated, is_local_user_id_change}, is_security_restricted};

const RESERVED_FUNCTION_NAMES: [&str; 11] = ["pg_read_file",
                                            "pg_read_file_off_len",
                                            "pg_read_file_v2",
                                            "pg_read_file_all",
                                            "pg_read_binary_file",
                                            "pg_read_binary_file_all",
                                            "pg_read_binary_file_off_len",
                                            "pg_reload_conf",
                                            "be_lo_import",
                                            "be_lo_export",
                                            "be_lo_import_with_oid"];
static mut RESERVED_FUNCTION_OIDS: Vec<pg_sys::Oid> = vec![];
static mut MIN_RESERVED_OID: u32 = 9000;
static mut MAX_RESERVED_OID: u32 = 0;

pub fn is_function_language_allowed(lang_name: &str,in_strict_mode: bool ) -> bool  {

    if in_strict_mode || is_elevated() {
        pg_sys::error!("LANGUAGE {} not allowed", lang_name);
    }

    if is_security_restricted() {
        pg_sys::error!("LANGUAGE {} not allowed", lang_name);
    }

    if is_local_user_id_change() {
        pg_sys::error!("LANGUAGE {} not allowed", lang_name);
    }

    return true;
}

pub fn is_reserved_internal_function(func_name: &str) -> bool {
    for r_func in RESERVED_FUNCTION_NAMES {
        if r_func == func_name {
            return true;
        }
    }
    return false;
}

pub fn is_reserved_internal_function_oid(func_oid: pg_sys::Oid) -> bool {
    pg_sys::info!("OAT EXECUTE {}", func_oid);
    unsafe {
        if func_oid.as_u32() > MIN_RESERVED_OID && func_oid.as_u32() < MAX_RESERVED_OID {
            pg_sys::info!("OAT EXECUTE {}", func_oid);
            for r_oid in RESERVED_FUNCTION_OIDS.iter() {
                if *r_oid == func_oid {
                    return true;
                }
            }
        }
    }
    return false;
}

// resolve reserved internal function oids
pub fn resolve_internal_func_oids() {
    pg_sys::info!("RESOLVE");
    // map the reserved function names to oids
    for r_func in RESERVED_FUNCTION_NAMES {
        let oid:pg_sys::Oid = unsafe {
            pg_sys::fmgr_internal_function(r_func.as_ptr().cast())
        };
        unsafe {
            RESERVED_FUNCTION_OIDS.push(oid);
            if oid.as_u32() < MIN_RESERVED_OID {
                MIN_RESERVED_OID = oid.as_u32();
            } else if oid.as_u32() > MAX_RESERVED_OID {
                MAX_RESERVED_OID = oid.as_u32();
            }
        }
    }
}
