#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

pub mod types {
    pub use std::os::raw::{c_char, c_int, c_uint, c_ulong, c_void};
    // pub type size_t = c_ulong;

    pub const srtp_err_status_ok: srtp_err_status_t = 0;
    pub const srtp_err_status_fail: srtp_err_status_t = 1;
    // pub const srtp_err_status_bad_param: srtp_err_status_t = 2;
    // pub const srtp_err_status_alloc_fail: srtp_err_status_t = 3;
    // pub const srtp_err_status_dealloc_fail: srtp_err_status_t = 4;
    // pub const srtp_err_status_init_fail: srtp_err_status_t = 5;
    // pub const srtp_err_status_terminus: srtp_err_status_t = 6;
    // pub const srtp_err_status_auth_fail: srtp_err_status_t = 7;
    // pub const srtp_err_status_cipher_fail: srtp_err_status_t = 8;
    pub const srtp_err_status_replay_fail: srtp_err_status_t = 9;
    pub const srtp_err_status_replay_old: srtp_err_status_t = 10;
    pub const srtp_err_status_algo_fail: srtp_err_status_t = 11;
    // pub const srtp_err_status_no_such_op: srtp_err_status_t = 12;
    // pub const srtp_err_status_no_ctx: srtp_err_status_t = 13;
    // pub const srtp_err_status_cant_check: srtp_err_status_t = 14;
    pub const srtp_err_status_key_expired: srtp_err_status_t = 15;
    // pub const srtp_err_status_socket_err: srtp_err_status_t = 16;
    // pub const srtp_err_status_signal_err: srtp_err_status_t = 17;
    // pub const srtp_err_status_nonce_bad: srtp_err_status_t = 18;
    // pub const srtp_err_status_read_fail: srtp_err_status_t = 19;
    // pub const srtp_err_status_write_fail: srtp_err_status_t = 20;
    // pub const srtp_err_status_parse_err: srtp_err_status_t = 21;
    // pub const srtp_err_status_encode_err: srtp_err_status_t = 22;
    // pub const srtp_err_status_semaphore_err: srtp_err_status_t = 23;
    // pub const srtp_err_status_pfkey_err: srtp_err_status_t = 24;
    // pub const srtp_err_status_bad_mki: srtp_err_status_t = 25;
    // pub const srtp_err_status_pkt_idx_old: srtp_err_status_t = 26;
    // pub const srtp_err_status_pkt_idx_adv: srtp_err_status_t = 27;

    pub type srtp_err_status_t = c_uint;

    pub trait Error {
        fn is_ok(&self) -> bool;
        fn is_err(&self) -> bool;
        fn as_result(&self) -> Result<(), srtp_err_status_t>;
    }

    impl Error for srtp_err_status_t {
        fn is_ok(&self) -> bool {
            self.as_result().is_ok()
        }

        fn is_err(&self) -> bool {
            self.as_result().is_err()
        }

        fn as_result(&self) -> Result<(), srtp_err_status_t> {
            match *self {
                srtp_err_status_ok => Ok(()),
                err => Err(err),
            }
        }
    }
}

// Submodules
mod datatypes;
pub mod rdb;
pub mod rdbx;

#[cfg(feature = "native-crypto")]
pub mod aes;

#[cfg(feature = "native-crypto")]
pub mod sha1;
