#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use super::datatypes::v128_t;
pub use super::types::*;

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct srtp_rdb_t {
    pub window_start: u32,
    pub bitmask: v128_t,
}

extern "C" {
    pub fn srtp_rdb_init(rdb: *mut srtp_rdb_t) -> srtp_err_status_t;
    pub fn srtp_rdb_check(rdb: *const srtp_rdb_t, rdb_index: u32) -> srtp_err_status_t;
    pub fn srtp_rdb_add_index(rdb: *mut srtp_rdb_t, rdb_index: u32) -> srtp_err_status_t;
    pub fn srtp_rdb_increment(rdb: *mut srtp_rdb_t) -> srtp_err_status_t;
    pub fn srtp_rdb_get_value(rdb: *const srtp_rdb_t) -> u32;
}
