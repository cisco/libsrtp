pub use super::types::*;

#[repr(C)]
#[derive(Copy, Clone)]
pub union v128_t {
    pub v8: [u8; 16],
    pub v16: [u16; 8],
    pub v32: [u32; 4],
    pub v64: [u64; 2],
}

impl Default for v128_t {
    fn default() -> Self {
        Self { v8: [0; 16] }
    }
}

impl From<Vec<u8>> for v128_t {
    fn from(vec: Vec<u8>) -> Self {
        let mut v128 = Self::default();
        unsafe { v128.v8.copy_from_slice(&vec) };
        v128
    }
}

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
