#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

// The general approach of this module is as follows:
//
// 1. The primary content of the header is generated by `bindgen` from the relevant C headers.
//    The generated content is cleaned up, e.g., by removing struct tests and consolidating extern
//    blocks.  Code not used by tests is commented out to silence dead code warnings, but left in
//    place to highlight the fact that it is unused.
//
// 2. The C interface is not exposed as `pub` by this module.  Instead, we provide a thin Rust
//    wrapper around the C functions that provides three nice things:
//    * Isolates `unsafe` calls so that test code can be written in safe rust
//    * Uses RAII to ensure that objects are cleaned up
//    * Exposes a clean Rust interface that is plausible for a pure Rust implementation
//
// This is effectively what a typical C-wrapping crate such as `openssl` would do, with a -sys
// crate exposing the low-level API.
//
// The latter property ensures that the tests are memory-safe as long as the underlying library is.
// It also means that as we convert C components to Rust, we will be able to compare all three
// configurations:
//      1. C called via FFI
//      2. Rust called via FFI
//      3. Rust called natively
//
// The difference between (1) and (2) is the difference that C callers will see.  The difference
// between (2) and (3) indicates how much of that is due to the FFI interface, vs. the core of the
// Rust implementation.

pub mod types {
    pub(super) use std::os::raw::{c_char, c_int, c_uint, c_ulong, c_void};

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub(super) struct srtp_debug_module_t {
        pub on: ::std::os::raw::c_int,
        pub name: *const ::std::os::raw::c_char,
    }

    // Errors that do not appear in the SRTP code base are commented out.
    pub(super) type srtp_err_status_t = c_uint;
    pub(super) const srtp_err_status_ok: srtp_err_status_t = 0;
    pub(super) const srtp_err_status_fail: srtp_err_status_t = 1;
    pub(super) const srtp_err_status_bad_param: srtp_err_status_t = 2;
    pub(super) const srtp_err_status_alloc_fail: srtp_err_status_t = 3;
    pub(super) const srtp_err_status_dealloc_fail: srtp_err_status_t = 4;
    pub(super) const srtp_err_status_init_fail: srtp_err_status_t = 5;
    pub(super) const srtp_err_status_terminus: srtp_err_status_t = 6;
    pub(super) const srtp_err_status_auth_fail: srtp_err_status_t = 7;
    pub(super) const srtp_err_status_cipher_fail: srtp_err_status_t = 8;
    pub(super) const srtp_err_status_replay_fail: srtp_err_status_t = 9;
    pub(super) const srtp_err_status_replay_old: srtp_err_status_t = 10;
    pub(super) const srtp_err_status_algo_fail: srtp_err_status_t = 11;
    pub(super) const srtp_err_status_no_such_op: srtp_err_status_t = 12;
    pub(super) const srtp_err_status_no_ctx: srtp_err_status_t = 13;
    pub(super) const srtp_err_status_cant_check: srtp_err_status_t = 14;
    pub(super) const srtp_err_status_key_expired: srtp_err_status_t = 15;
    pub(super) const srtp_err_status_socket_err: srtp_err_status_t = 16;
    pub(super) const srtp_err_status_signal_err: srtp_err_status_t = 17;
    pub(super) const srtp_err_status_nonce_bad: srtp_err_status_t = 18;
    pub(super) const srtp_err_status_read_fail: srtp_err_status_t = 19;
    pub(super) const srtp_err_status_write_fail: srtp_err_status_t = 20;
    pub(super) const srtp_err_status_parse_err: srtp_err_status_t = 21;
    pub(super) const srtp_err_status_encode_err: srtp_err_status_t = 22;
    pub(super) const srtp_err_status_semaphore_err: srtp_err_status_t = 23;
    pub(super) const srtp_err_status_pfkey_err: srtp_err_status_t = 24;
    pub(super) const srtp_err_status_bad_mki: srtp_err_status_t = 25;
    pub(super) const srtp_err_status_pkt_idx_old: srtp_err_status_t = 26;
    pub(super) const srtp_err_status_pkt_idx_adv: srtp_err_status_t = 27;

    #[repr(u32)]
    #[derive(Debug)]
    pub enum Error {
        Fail,
        BadParam,
        AllocFail,
        DeallocFail,
        InitFail,
        Terminus,
        AuthFail,
        CipherFail,
        ReplayFail,
        ReplayOld,
        AlgoFail,
        NoSuchOp,
        NoCtx,
        CantCheck,
        KeyExpired,
        SocketErr,
        SignalErr,
        NonceBad,
        ReadFail,
        WriteFail,
        ParseErr,
        EncodeErr,
        SemaphoreErr,
        PfkeyErr,
        BadMki,
        PktIdxOld,
        PktIdxAdv,
    }

    impl From<srtp_err_status_t> for Error {
        // Note: Panics if err is srtp_err_status_ok, since this should be represented by an Ok()
        // result.  See SrtpError::as_result()
        fn from(err: srtp_err_status_t) -> Error {
            match err {
                srtp_err_status_fail => Error::Fail,
                srtp_err_status_bad_param => Error::BadParam,
                srtp_err_status_alloc_fail => Error::AllocFail,
                srtp_err_status_dealloc_fail => Error::DeallocFail,
                srtp_err_status_init_fail => Error::InitFail,
                srtp_err_status_terminus => Error::Terminus,
                srtp_err_status_auth_fail => Error::AuthFail,
                srtp_err_status_cipher_fail => Error::CipherFail,
                srtp_err_status_replay_fail => Error::ReplayFail,
                srtp_err_status_replay_old => Error::ReplayOld,
                srtp_err_status_algo_fail => Error::AlgoFail,
                srtp_err_status_no_such_op => Error::NoSuchOp,
                srtp_err_status_no_ctx => Error::NoCtx,
                srtp_err_status_cant_check => Error::CantCheck,
                srtp_err_status_key_expired => Error::KeyExpired,
                srtp_err_status_socket_err => Error::SocketErr,
                srtp_err_status_signal_err => Error::SignalErr,
                srtp_err_status_nonce_bad => Error::NonceBad,
                srtp_err_status_read_fail => Error::ReadFail,
                srtp_err_status_write_fail => Error::WriteFail,
                srtp_err_status_parse_err => Error::ParseErr,
                srtp_err_status_encode_err => Error::EncodeErr,
                srtp_err_status_semaphore_err => Error::SemaphoreErr,
                srtp_err_status_pfkey_err => Error::PfkeyErr,
                srtp_err_status_bad_mki => Error::BadMki,
                srtp_err_status_pkt_idx_old => Error::PktIdxOld,
                srtp_err_status_pkt_idx_adv => Error::PktIdxAdv,
                _ => panic!("Invalid error code"),
            }
        }
    }

    pub trait SrtpError {
        fn as_result(&self) -> Result<(), Error>;

        fn is_ok(&self) -> bool {
            self.as_result().is_ok()
        }

        fn is_err(&self) -> bool {
            self.as_result().is_err()
        }
    }

    impl SrtpError for srtp_err_status_t {
        fn as_result(&self) -> Result<(), Error> {
            match *self {
                srtp_err_status_ok => Ok(()),
                err => Err(err.into()),
            }
        }
    }
}

// Submodules
mod auth;
mod cipher;
mod datatypes;
pub(crate) mod kernel;
pub(crate) mod rdb;
pub(crate) mod rdbx;

#[cfg(feature = "native-crypto")]
pub(crate) mod aes;

#[cfg(feature = "native-crypto")]
pub(crate) mod sha1;
