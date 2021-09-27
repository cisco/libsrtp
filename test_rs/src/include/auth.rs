use super::types::*;

pub(super) type srtp_auth_type_id_t = c_int;

// type srtp_auth_type_pointer = *const srtp_auth_type_t;
type srtp_auth_pointer_t = *mut srtp_auth_t;
type srtp_auth_alloc_func = Option<
    unsafe extern "C" fn(
        ap: *mut srtp_auth_pointer_t,
        key_len: c_int,
        out_len: c_int,
    ) -> srtp_err_status_t,
>;
type srtp_auth_init_func = Option<
    unsafe extern "C" fn(state: *mut c_void, key: *const u8, key_len: c_int) -> srtp_err_status_t,
>;
type srtp_auth_dealloc_func =
    Option<unsafe extern "C" fn(ap: srtp_auth_pointer_t) -> srtp_err_status_t>;
type srtp_auth_compute_func = Option<
    unsafe extern "C" fn(
        state: *mut c_void,
        buffer: *const u8,
        octets_to_auth: c_int,
        tag_len: c_int,
        tag: *mut u8,
    ) -> srtp_err_status_t,
>;
type srtp_auth_update_func = Option<
    unsafe extern "C" fn(
        state: *mut c_void,
        buffer: *const u8,
        octets_to_auth: c_int,
    ) -> srtp_err_status_t,
>;
type srtp_auth_start_func = Option<unsafe extern "C" fn(state: *mut c_void) -> srtp_err_status_t>;

extern "C" {
    // fn srtp_auth_get_key_length(a: *const srtp_auth_t) -> c_int;
    // fn srtp_auth_get_tag_length(a: *const srtp_auth_t) -> c_int;
    // fn srtp_auth_get_prefix_length(a: *const srtp_auth_t) -> c_int;
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct srtp_auth_test_case_t {
    key_length_octets: c_int,
    key: *const u8,
    data_length_octets: c_int,
    data: *const u8,
    tag_length_octets: c_int,
    tag: *const u8,
    next_test_case: *const srtp_auth_test_case_t,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub(super) struct srtp_auth_type_t {
    alloc: srtp_auth_alloc_func,
    dealloc: srtp_auth_dealloc_func,
    init: srtp_auth_init_func,
    compute: srtp_auth_compute_func,
    update: srtp_auth_update_func,
    start: srtp_auth_start_func,
    description: *const c_char,
    test_data: *const srtp_auth_test_case_t,
    id: srtp_auth_type_id_t,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct srtp_auth_t {
    type_: *const srtp_auth_type_t,
    state: *mut c_void,
    out_len: c_int,
    key_len: c_int,
    prefix_len: c_int,
}

extern "C" {
    //     fn srtp_auth_type_self_test(at: *const srtp_auth_type_t) -> srtp_err_status_t;
    //     fn srtp_auth_type_test(
    //         at: *const srtp_auth_type_t,
    //         test_data: *const srtp_auth_test_case_t,
    //     ) -> srtp_err_status_t;
    //     fn srtp_replace_auth_type(
    //         ct: *const srtp_auth_type_t,
    //         id: srtp_auth_type_id_t,
    //     ) -> srtp_err_status_t;
}
