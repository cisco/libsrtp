pub use super::types::*;

pub(super) type srtp_cipher_type_id_t = c_int;

const srtp_direction_encrypt: srtp_cipher_direction_t = 0;
// const srtp_direction_decrypt: srtp_cipher_direction_t = 1;
// const srtp_direction_any: srtp_cipher_direction_t = 2;
type srtp_cipher_direction_t = c_int;

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
    fn srtp_cipher_type_self_test(ct: *const srtp_cipher_type_t) -> srtp_err_status_t;
    // fn srtp_cipher_type_test(
    //     ct: *const srtp_cipher_type_t,
    //     test_data: *const srtp_cipher_test_case_t,
    // ) -> srtp_err_status_t;
    fn srtp_cipher_bits_per_second(
        c: *mut srtp_cipher_t,
        octets_in_buffer: c_int,
        num_trials: c_int,
    ) -> u64;
    fn srtp_cipher_type_alloc(
        ct: *const srtp_cipher_type_t,
        c: *mut *mut srtp_cipher_t,
        key_len: c_int,
        tlen: c_int,
    ) -> srtp_err_status_t;
    fn srtp_cipher_dealloc(c: *mut srtp_cipher_t) -> srtp_err_status_t;
    fn srtp_cipher_init(c: *mut srtp_cipher_t, key: *const u8) -> srtp_err_status_t;
    fn srtp_cipher_set_iv(
        c: *mut srtp_cipher_t,
        iv: *mut u8,
        direction: c_int,
    ) -> srtp_err_status_t;
    // fn srtp_cipher_output(
    //     c: *mut srtp_cipher_t,
    //     buffer: *mut u8,
    //     num_octets_to_output: *mut u32,
    // ) -> srtp_err_status_t;
    fn srtp_cipher_encrypt(
        c: *mut srtp_cipher_t,
        buffer: *mut u8,
        num_octets_to_output: *mut u32,
    ) -> srtp_err_status_t;
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

extern "C" {
    static srtp_null_cipher: srtp_cipher_type_t;
    static srtp_aes_icm_128: srtp_cipher_type_t;
    static srtp_aes_icm_256: srtp_cipher_type_t;

    #[cfg(not(feature = "native-crypto"))]
    static srtp_aes_gcm_128: srtp_cipher_type_t;

    #[cfg(not(feature = "native-crypto"))]
    static srtp_aes_gcm_256: srtp_cipher_type_t;
}

use std::ffi::CStr;
use std::marker::Sync;

pub mod constants {
    pub const SALT_LEN: usize = 14;
    pub const AEAD_SALT_LEN: usize = 12;
    pub const AES_128_KEY_LEN: usize = 16;
    pub const AES_192_KEY_LEN: usize = 24;
    pub const AES_256_KEY_LEN: usize = 32;

    pub const AES_ICM_128_KEY_LEN_WSALT: usize = AES_128_KEY_LEN + SALT_LEN;
    pub const AES_ICM_192_KEY_LEN_WSALT: usize = AES_192_KEY_LEN + SALT_LEN;
    pub const AES_ICM_256_KEY_LEN_WSALT: usize = AES_256_KEY_LEN + SALT_LEN;
    pub const AES_GCM_128_KEY_LEN_WSALT: usize = AES_128_KEY_LEN + AEAD_SALT_LEN;
    pub const AES_GCM_256_KEY_LEN_WSALT: usize = AES_256_KEY_LEN + AEAD_SALT_LEN;
}

#[derive(Copy, Clone, Debug)]
pub enum CipherTypeId {
    Null,
    AesIcm128,
    // AesIcm192,
    AesIcm256,
    AesGcm128(usize),
    AesGcm256(usize),
}

impl CipherTypeId {
    pub fn key_size(&self) -> usize {
        match self {
            CipherTypeId::Null => 0,
            CipherTypeId::AesIcm128 => constants::AES_ICM_128_KEY_LEN_WSALT,
            // CipherTypeId::AesIcm192 => constants::AES_ICM_192_KEY_LEN_WSALT,
            CipherTypeId::AesIcm256 => constants::AES_ICM_256_KEY_LEN_WSALT,
            CipherTypeId::AesGcm128(_) => constants::AES_GCM_128_KEY_LEN_WSALT,
            CipherTypeId::AesGcm256(_) => constants::AES_GCM_256_KEY_LEN_WSALT,
        }
    }

    pub fn tag_size(&self) -> usize {
        match self {
            CipherTypeId::Null
            | CipherTypeId::AesIcm128
            // | CipherTypeId::AesIcm192
            | CipherTypeId::AesIcm256 => 0,
            CipherTypeId::AesGcm128(tag_size) => *tag_size,
            CipherTypeId::AesGcm256(tag_size) => *tag_size,
        }
    }
}

impl Into<srtp_cipher_type_id_t> for CipherTypeId {
    fn into(self) -> srtp_cipher_type_id_t {
        match self {
            CipherTypeId::Null => 0,
            CipherTypeId::AesIcm128 => 1,
            // CipherTypeId::AesIcm192 => 4,
            CipherTypeId::AesIcm256 => 5,
            CipherTypeId::AesGcm128(_) => 6,
            CipherTypeId::AesGcm256(_) => 7,
        }
    }
}

pub struct CipherType {
    ct: &'static srtp_cipher_type_t,
}

impl CipherType {
    pub fn create(&self, key: &[u8], tag_len: usize) -> Result<Cipher, Error> {
        let mut cipher = Cipher {
            c: std::ptr::null_mut(),
        };
        let key_len = key.len() as c_int;
        let tag_len = tag_len as c_int;
        unsafe { srtp_cipher_type_alloc(self.ct, &mut cipher.c, key_len, tag_len).as_result()? };
        unsafe {
            srtp_cipher_init(cipher.c, key.as_ptr())
                .as_result()
                .map(|_| cipher)
        }
    }

    pub fn self_test(&self) -> Result<(), Error> {
        unsafe { srtp_cipher_type_self_test(self.ct).as_result() }
    }

    pub fn description(&self) -> &str {
        unsafe { CStr::from_ptr(self.ct.description).to_str().unwrap() }
    }
}

unsafe impl Sync for CipherType {}

pub struct Cipher {
    c: *mut srtp_cipher_t,
}

impl Cipher {
    pub fn set_iv(&self, iv: &[u8]) -> Result<(), Error> {
        let iv_ptr = iv.as_ptr() as *mut u8;
        unsafe { srtp_cipher_set_iv(self.c, iv_ptr, srtp_direction_encrypt).as_result() }
    }

    pub fn encrypt(&self, pt: &mut [u8], pt_len: &mut u32) -> Result<(), Error> {
        unsafe { srtp_cipher_encrypt(self.c, pt.as_mut_ptr(), pt_len).as_result() }
    }

    pub fn bits_per_second(&self, msg_size: usize, num_trials: usize) -> u64 {
        let msg_size = msg_size as c_int;
        let num_trials = num_trials as c_int;
        unsafe { srtp_cipher_bits_per_second(self.c, msg_size, num_trials) }
    }

    pub fn description(&self) -> &str {
        let cipher = unsafe { self.c.as_ref().unwrap() };
        let cipher_type = unsafe { cipher.type_.as_ref().unwrap() };
        unsafe { CStr::from_ptr(cipher_type.description).to_str().unwrap() }
    }

    pub fn key_len(&self) -> usize {
        unsafe { self.c.as_ref().unwrap().key_len as usize }
    }
}

impl Drop for Cipher {
    fn drop(&mut self) {
        if !self.c.is_null() {
            unsafe { srtp_cipher_dealloc(self.c).as_result().unwrap() };
        }
    }
}

pub static NULL_CIPHER: CipherType = CipherType {
    ct: unsafe { &srtp_null_cipher },
};

pub static AES_ICM_128: CipherType = CipherType {
    ct: unsafe { &srtp_aes_icm_128 },
};

pub static AES_ICM_256: CipherType = CipherType {
    ct: unsafe { &srtp_aes_icm_256 },
};

#[cfg(not(feature = "native-crypto"))]
pub static AES_GCM_128: CipherType = CipherType {
    ct: unsafe { &srtp_aes_gcm_128 },
};

#[cfg(not(feature = "native-crypto"))]
pub static AES_GCM_256: CipherType = CipherType {
    ct: unsafe { &srtp_aes_gcm_256 },
};
