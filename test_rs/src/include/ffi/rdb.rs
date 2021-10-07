#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use super::datatypes::v128_t;
pub use super::types::*;

#[repr(C)]
#[derive(Default, Copy, Clone)]
struct srtp_rdb_t {
    pub window_start: u32,
    pub bitmask: v128_t,
}

extern "C" {
    fn srtp_rdb_init(rdb: *mut srtp_rdb_t) -> srtp_err_status_t;
    fn srtp_rdb_check(rdb: *const srtp_rdb_t, rdb_index: u32) -> srtp_err_status_t;
    fn srtp_rdb_add_index(rdb: *mut srtp_rdb_t, rdb_index: u32) -> srtp_err_status_t;
    fn srtp_rdb_increment(rdb: *mut srtp_rdb_t) -> srtp_err_status_t;
    fn srtp_rdb_get_value(rdb: *const srtp_rdb_t) -> u32;
}

pub struct ReplayDB {
    rdb: srtp_rdb_t,
}

impl ReplayDB {
    pub fn new() -> Result<Self, Error> {
        let mut rdb = Self {
            rdb: srtp_rdb_t::default(),
        };
        unsafe { srtp_rdb_init(&mut rdb.rdb).as_result().map(|_| rdb) }
    }

    pub fn check(&self, rdb_index: u32) -> Result<(), Error> {
        unsafe { srtp_rdb_check(&self.rdb, rdb_index).as_result() }
    }

    pub fn add(&mut self, rdb_index: u32) -> Result<(), Error> {
        unsafe { srtp_rdb_add_index(&mut self.rdb, rdb_index).as_result() }
    }

    pub fn increment(&mut self) -> Result<(), Error> {
        unsafe { srtp_rdb_increment(&mut self.rdb).as_result() }
    }

    pub fn value(&self) -> u32 {
        unsafe { srtp_rdb_get_value(&self.rdb) }
    }

    pub fn set_value(&mut self, window_start: u32) {
        self.rdb.window_start = window_start;
    }
}
