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
            pg_sys::error!("using builtin function {} is not allowed", func_name);
        }
    }
    return false;
}
