#![cfg(feature = "native-crypto")]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

pub use super::datatypes::v128_t;
pub use super::types::*;

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct srtp_aes_expanded_key_t {
    pub round: [v128_t; 15],
    pub num_rounds: c_int,
}

extern "C" {
    pub fn srtp_aes_expand_encryption_key(
        key: *const u8,
        key_len: c_int,
        expanded_key: *mut srtp_aes_expanded_key_t,
    ) -> srtp_err_status_t;
    // pub fn srtp_aes_expand_decryption_key(
    //     key: *const u8,
    //     key_len: c_int,
    //     expanded_key: *mut srtp_aes_expanded_key_t,
    // ) -> srtp_err_status_t;
    pub fn srtp_aes_encrypt(plaintext: *mut v128_t, exp_key: *const srtp_aes_expanded_key_t);
    // pub fn srtp_aes_decrypt(plaintext: *mut v128_t, exp_key: *const srtp_aes_expanded_key_t);
}
