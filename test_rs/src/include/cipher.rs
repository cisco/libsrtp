use super::types::*;

pub(super) type srtp_cipher_type_id_t = c_int;

// const srtp_cipher_direction_t_srtp_direction_encrypt: srtp_cipher_direction_t = 0;
// const srtp_cipher_direction_t_srtp_direction_decrypt: srtp_cipher_direction_t = 1;
// const srtp_cipher_direction_t_srtp_direction_any: srtp_cipher_direction_t = 2;
type srtp_cipher_direction_t = c_uint;

type srtp_cipher_pointer_t = *mut srtp_cipher_t;
type srtp_cipher_alloc_func_t = Option<
    unsafe extern "C" fn(
        cp: *mut srtp_cipher_pointer_t,
        key_len: c_int,
        tag_len: c_int,
    ) -> srtp_err_status_t,
>;
type srtp_cipher_init_func_t =
    Option<unsafe extern "C" fn(state: *mut c_void, key: *const u8) -> srtp_err_status_t>;
type srtp_cipher_dealloc_func_t =
    Option<unsafe extern "C" fn(cp: srtp_cipher_pointer_t) -> srtp_err_status_t>;
type srtp_cipher_set_aad_func_t = Option<
    unsafe extern "C" fn(state: *mut c_void, aad: *const u8, aad_len: u32) -> srtp_err_status_t,
>;
type srtp_cipher_encrypt_func_t = Option<
    unsafe extern "C" fn(
        state: *mut c_void,
        buffer: *mut u8,
        octets_to_encrypt: *mut c_uint,
    ) -> srtp_err_status_t,
>;
// type srtp_cipher_decrypt_func_t = Option<
//     unsafe extern "C" fn(
//         state: *mut c_void,
//         buffer: *mut u8,
//         octets_to_decrypt: *mut c_uint,
//     ) -> srtp_err_status_t,
// >;
type srtp_cipher_set_iv_func_t = Option<
    unsafe extern "C" fn(
        state: *mut c_void,
        iv: *mut u8,
        direction: srtp_cipher_direction_t,
    ) -> srtp_err_status_t,
>;
type srtp_cipher_get_tag_func_t = Option<
    unsafe extern "C" fn(state: *mut c_void, tag: *mut u8, len: *mut u32) -> srtp_err_status_t,
>;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct srtp_cipher_test_case_t {
    key_length_octets: c_int,
    key: *const u8,
    idx: *mut u8,
    plaintext_length_octets: c_uint,
    plaintext: *const u8,
    ciphertext_length_octets: c_uint,
    ciphertext: *const u8,
    aad_length_octets: c_int,
    aad: *const u8,
    tag_length_octets: c_int,
    next_test_case: *const srtp_cipher_test_case_t,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub(super) struct srtp_cipher_type_t {
    alloc: srtp_cipher_alloc_func_t,
    dealloc: srtp_cipher_dealloc_func_t,
    init: srtp_cipher_init_func_t,
    set_aad: srtp_cipher_set_aad_func_t,
    encrypt: srtp_cipher_encrypt_func_t,
    decrypt: srtp_cipher_encrypt_func_t,
    set_iv: srtp_cipher_set_iv_func_t,
    get_tag: srtp_cipher_get_tag_func_t,
    description: *const c_char,
    test_data: *const srtp_cipher_test_case_t,
    id: srtp_cipher_type_id_t,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct srtp_cipher_t {
    type_: *const srtp_cipher_type_t,
    state: *mut c_void,
    key_len: c_int,
    algorithm: c_int,
}

extern "C" {
    // fn srtp_cipher_get_key_length(c: *const srtp_cipher_t) -> c_int;
    // fn srtp_cipher_type_self_test(ct: *const srtp_cipher_type_t) -> srtp_err_status_t;
    // fn srtp_cipher_type_test(
    //     ct: *const srtp_cipher_type_t,
    //     test_data: *const srtp_cipher_test_case_t,
    // ) -> srtp_err_status_t;
    // fn srtp_cipher_bits_per_second(
    //     c: *mut srtp_cipher_t,
    //     octets_in_buffer: c_int,
    //     num_trials: c_int,
    // ) -> u64;
    // fn srtp_cipher_type_alloc(
    //     ct: *const srtp_cipher_type_t,
    //     c: *mut *mut srtp_cipher_t,
    //     key_len: c_int,
    //     tlen: c_int,
    // ) -> srtp_err_status_t;
    // fn srtp_cipher_dealloc(c: *mut srtp_cipher_t) -> srtp_err_status_t;
    // fn srtp_cipher_init(c: *mut srtp_cipher_t, key: *const u8) -> srtp_err_status_t;
    // fn srtp_cipher_set_iv(
    //     c: *mut srtp_cipher_t,
    //     iv: *mut u8,
    //     direction: c_int,
    // ) -> srtp_err_status_t;
    // fn srtp_cipher_output(
    //     c: *mut srtp_cipher_t,
    //     buffer: *mut u8,
    //     num_octets_to_output: *mut u32,
    // ) -> srtp_err_status_t;
    // fn srtp_cipher_encrypt(
    //     c: *mut srtp_cipher_t,
    //     buffer: *mut u8,
    //     num_octets_to_output: *mut u32,
    // ) -> srtp_err_status_t;
    // fn srtp_cipher_decrypt(
    //     c: *mut srtp_cipher_t,
    //     buffer: *mut u8,
    //     num_octets_to_output: *mut u32,
    // ) -> srtp_err_status_t;
    // fn srtp_cipher_get_tag(
    //     c: *mut srtp_cipher_t,
    //     buffer: *mut u8,
    //     tag_len: *mut u32,
    // ) -> srtp_err_status_t;
    // fn srtp_cipher_set_aad(
    //     c: *mut srtp_cipher_t,
    //     aad: *const u8,
    //     aad_len: u32,
    // ) -> srtp_err_status_t;
    // fn srtp_replace_cipher_type(
    //     ct: *const srtp_cipher_type_t,
    //     id: srtp_cipher_type_id_t,
    // ) -> srtp_err_status_t;
}
