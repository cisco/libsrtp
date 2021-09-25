#![cfg(feature = "native-crypto")]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use std::convert::TryInto;

use super::datatypes::v128_t;
use super::types::*;

#[repr(C)]
#[derive(Default, Copy, Clone)]
struct srtp_aes_expanded_key_t {
    round: [v128_t; 15],
    num_rounds: c_int,
}

extern "C" {
    fn srtp_aes_expand_encryption_key(
        key: *const u8,
        key_len: c_int,
        expanded_key: *mut srtp_aes_expanded_key_t,
    ) -> srtp_err_status_t;
    // pub fn srtp_aes_expand_decryption_key(
    //     key: *const u8,
    //     key_len: c_int,
    //     expanded_key: *mut srtp_aes_expanded_key_t,
    // ) -> srtp_err_status_t;
    fn srtp_aes_encrypt(plaintext: *mut v128_t, exp_key: *const srtp_aes_expanded_key_t);
    // pub fn srtp_aes_decrypt(plaintext: *mut v128_t, exp_key: *const srtp_aes_expanded_key_t);
}

pub struct AesKey {
    expanded_key: srtp_aes_expanded_key_t,
}

impl AesKey {
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        let mut aes_key = AesKey {
            expanded_key: srtp_aes_expanded_key_t::default(),
        };

        let key_ptr = key.as_ptr();
        let key_len: i32 = key.len().try_into().unwrap();
        unsafe {
            srtp_aes_expand_encryption_key(key_ptr, key_len, &mut aes_key.expanded_key)
                .as_result()
                .map(|_| aes_key)
        }
    }

    pub fn encrypt(&self, block: &mut [u8]) -> Result<(), Error> {
        if block.len() != std::mem::size_of::<v128_t>() {
            return Err(Error::BadParam);
        }

        let block_ptr = block.as_ptr() as *mut v128_t;
        unsafe { srtp_aes_encrypt(block_ptr, &self.expanded_key) };
        Ok(())
    }
}
