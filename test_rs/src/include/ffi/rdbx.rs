#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

pub use super::types::*;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bitvector_t {
    pub length: u32,
    pub word: *mut u32,
}

impl Default for bitvector_t {
    fn default() -> Self {
        Self {
            length: 0,
            word: std::ptr::null_mut(),
        }
    }
}

// extern "C" {
//     pub fn bitvector_alloc(v: *mut bitvector_t, length: c_ulong) -> c_int;
//     pub fn bitvector_dealloc(v: *mut bitvector_t);
//     pub fn bitvector_set_to_zero(x: *mut bitvector_t);
//     pub fn bitvector_left_shift(x: *mut bitvector_t, index: c_int);
// }

pub type srtp_sequence_number_t = u16;
// pub type srtp_rollover_counter_t = u32;
pub type srtp_xtd_seq_num_t = u64;

#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
pub struct srtp_rdbx_t {
    pub index: srtp_xtd_seq_num_t,
    pub bitmask: bitvector_t,
}

extern "C" {
    pub fn srtp_rdbx_init(rdbx: *mut srtp_rdbx_t, ws: c_ulong) -> srtp_err_status_t;
    pub fn srtp_rdbx_dealloc(rdbx: *mut srtp_rdbx_t) -> srtp_err_status_t;
    // pub fn srtp_rdbx_estimate_index(
    //     rdbx: *const srtp_rdbx_t,
    //     guess: *mut srtp_xtd_seq_num_t,
    //     s: srtp_sequence_number_t,
    // ) -> i32;
    pub fn srtp_rdbx_check(rdbx: *const srtp_rdbx_t, difference: c_int) -> srtp_err_status_t;
    pub fn srtp_rdbx_add_index(rdbx: *mut srtp_rdbx_t, delta: c_int) -> srtp_err_status_t;
    // pub fn srtp_rdbx_set_roc(rdbx: *mut srtp_rdbx_t, roc: u32) -> srtp_err_status_t;
    // pub fn srtp_rdbx_get_packet_index(rdbx: *const srtp_rdbx_t) -> srtp_xtd_seq_num_t;
    // pub fn srtp_rdbx_get_window_size(rdbx: *const srtp_rdbx_t) -> c_ulong;
    // pub fn srtp_rdbx_get_roc(rdbx: *const srtp_rdbx_t) -> u32;
    // pub fn srtp_rdbx_set_roc_seq(rdbx: *mut srtp_rdbx_t, roc: u32, seq: u16) -> srtp_err_status_t;

    pub fn srtp_index_init(pi: *mut srtp_xtd_seq_num_t);
    pub fn srtp_index_advance(pi: *mut srtp_xtd_seq_num_t, s: srtp_sequence_number_t);
    pub fn srtp_index_guess(
        local: *const srtp_xtd_seq_num_t,
        guess: *mut srtp_xtd_seq_num_t,
        s: srtp_sequence_number_t,
    ) -> i32;
}

pub type SequenceNumber = srtp_sequence_number_t;
pub type ExtendedSequenceNumber = srtp_xtd_seq_num_t;

pub trait ExtendedSequenceNumberMethods {
    fn new() -> Self;
    fn advance(&mut self, s: SequenceNumber);
    fn guess(&self, s: SequenceNumber) -> (ExtendedSequenceNumber, i32);
}

impl ExtendedSequenceNumberMethods for ExtendedSequenceNumber {
    fn new() -> Self {
        let mut pi = ExtendedSequenceNumber::default();
        unsafe { srtp_index_init(&mut pi) };
        pi
    }

    fn advance(&mut self, s: SequenceNumber) {
        unsafe { srtp_index_advance(self, s) };
    }

    fn guess(&self, s: SequenceNumber) -> (ExtendedSequenceNumber, i32) {
        let mut guess = ExtendedSequenceNumber::default();
        let delta = unsafe { srtp_index_guess(self, &mut guess, s) };
        (guess, delta)
    }
}

pub struct ExtendedReplayDB {
    rdbx: srtp_rdbx_t,
}

impl ExtendedReplayDB {
    pub fn new(ws: usize) -> Result<Self, Error> {
        let ws = ws as c_ulong;
        let mut rdbx = Self {
            rdbx: srtp_rdbx_t::default(),
        };
        unsafe { srtp_rdbx_init(&mut rdbx.rdbx, ws).as_result().map(|_| rdbx) }
    }

    pub fn check(&self, difference: i32) -> Result<(), Error> {
        let difference = difference as c_int;
        unsafe { srtp_rdbx_check(&self.rdbx, difference).as_result() }
    }

    pub fn add(&mut self, delta: i32) -> Result<(), Error> {
        unsafe { srtp_rdbx_add_index(&mut self.rdbx, delta).as_result() }
    }

    pub fn index(&self) -> ExtendedSequenceNumber {
        self.rdbx.index
    }
}

impl Drop for ExtendedReplayDB {
    fn drop(&mut self) {
        unsafe { srtp_rdbx_dealloc(&mut self.rdbx) };
    }
}
