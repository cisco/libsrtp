use super::auth::*;
use super::cipher::*;
use super::types::*;

// const srtp_crypto_kernel_state_insecure: srtp_crypto_kernel_state_t = 0;
// const srtp_crypto_kernel_state_secure: srtp_crypto_kernel_state_t = 1;
type srtp_crypto_kernel_state_t = c_uint;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct srtp_kernel_cipher_type {
    id: srtp_cipher_type_id_t,
    cipher_type: *const srtp_cipher_type_t,
    next: *mut srtp_kernel_cipher_type,
}
type srtp_kernel_cipher_type_t = srtp_kernel_cipher_type;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct srtp_kernel_auth_type {
    id: srtp_auth_type_id_t,
    auth_type: *const srtp_auth_type_t,
    next: *mut srtp_kernel_auth_type,
}
type srtp_kernel_auth_type_t = srtp_kernel_auth_type;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct srtp_kernel_debug_module {
    mod_: *mut srtp_debug_module_t,
    next: *mut srtp_kernel_debug_module,
}
type srtp_kernel_debug_module_t = srtp_kernel_debug_module;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct srtp_crypto_kernel_t {
    state: srtp_crypto_kernel_state_t,
    cipher_type_list: *mut srtp_kernel_cipher_type_t,
    auth_type_list: *mut srtp_kernel_auth_type_t,
    debug_module_list: *mut srtp_kernel_debug_module_t,
}

extern "C" {
    fn srtp_crypto_kernel_init() -> srtp_err_status_t;
    fn srtp_crypto_kernel_shutdown() -> srtp_err_status_t;
    fn srtp_crypto_kernel_status() -> srtp_err_status_t;
    // fn srtp_crypto_kernel_list_debug_modules() -> srtp_err_status_t;
    // fn srtp_crypto_kernel_load_cipher_type(
    //     ct: *const srtp_cipher_type_t,
    //     id: srtp_cipher_type_id_t,
    // ) -> srtp_err_status_t;
    // fn srtp_crypto_kernel_load_auth_type(
    //     ct: *const srtp_auth_type_t,
    //     id: srtp_auth_type_id_t,
    // ) -> srtp_err_status_t;
    // fn srtp_crypto_kernel_load_debug_module(new_dm: *mut srtp_debug_module_t) -> srtp_err_status_t;
    // fn srtp_crypto_kernel_alloc_cipher(
    //     id: srtp_cipher_type_id_t,
    //     cp: *mut srtp_cipher_pointer_t,
    //     key_len: c_int,
    //     tag_len: c_int,
    // ) -> srtp_err_status_t;
    // fn srtp_crypto_kernel_alloc_auth(
    //     id: srtp_auth_type_id_t,
    //     ap: *mut srtp_auth_pointer_t,
    //     key_len: c_int,
    //     tag_len: c_int,
    // ) -> srtp_err_status_t;
    fn srtp_crypto_kernel_set_debug_module(mod_name: *const c_char, v: c_int) -> srtp_err_status_t;
}

use std::sync::atomic::AtomicU64;

static mut KERNEL_REFCOUNT: AtomicU64 = AtomicU64::new(0);

pub struct CryptoKernel;

impl CryptoKernel {
    pub fn new() -> Result<Self, Error> {
        let ctr = unsafe { KERNEL_REFCOUNT.get_mut() };
        *ctr += 1;
        if *ctr == 1 {
            unsafe { srtp_crypto_kernel_init().as_result()? };
        }
        Ok(Self)
    }

    pub fn status(&self) -> Result<(), Error> {
        unsafe { srtp_crypto_kernel_status().as_result() }
    }

    pub fn set_debug_module(&self, name: &str, active: bool) -> Result<(), Error> {
        let name_ptr = name.as_ptr() as *mut c_char;
        let val = if active { 1 } else { 0 };
        unsafe { srtp_crypto_kernel_set_debug_module(name_ptr, val).as_result() }
    }
}

impl Drop for CryptoKernel {
    fn drop(&mut self) {
        let ctr = unsafe { KERNEL_REFCOUNT.get_mut() };
        *ctr -= 1;
        if *ctr == 0 {
            unsafe { srtp_crypto_kernel_shutdown().as_result().unwrap() };
        }
    }
}
