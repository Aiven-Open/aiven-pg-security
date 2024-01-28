
pub fn to_cstr(ptr: *const i8) -> Result<&'static str, std::str::Utf8Error> {
    return unsafe { std::ffi::CStr::from_ptr(ptr).to_str() };
}