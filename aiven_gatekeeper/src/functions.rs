
use pgrx::pg_sys;
use std::ffi::CString;
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

pub fn is_reserved_internal_function_oid(func_oid: pg_sys::Oid, min_reserved_oid: u32, max_reserved_oid: u32, reserved_function_oids: &Vec<pg_sys::Oid>) -> bool {
    if func_oid.as_u32() > min_reserved_oid && func_oid.as_u32() < max_reserved_oid {
        for r_oid in reserved_function_oids.iter() {
            if *r_oid == func_oid {
                return true;
            }
        }
    }
    return false;
}

// resolve reserved internal function oids and return min, max oids
pub fn resolve_internal_func_oids(reserved_function_oids: &mut Vec<pg_sys::Oid>) -> (u32, u32) {
    let mut min_reserved_oid: u32 = 9000;
    let mut max_reserved_oid: u32 = 0;

    // map the reserved function names to oids
    for r_func in RESERVED_FUNCTION_NAMES {
        let c_str = CString::new(r_func).unwrap();
        let oid:pg_sys::Oid = unsafe {
            pg_sys::fmgr_internal_function(c_str.as_ptr() as *const i8)
        };
        reserved_function_oids.push(oid);
        if oid.as_u32() < min_reserved_oid {
            min_reserved_oid = oid.as_u32();
        }
        if oid.as_u32() > max_reserved_oid {
            max_reserved_oid = oid.as_u32();
        }
    }
    return (min_reserved_oid, max_reserved_oid);
}
