#![cfg(feature = "native-crypto")]

pub use super::types::*;
use std::convert::TryInto;

#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
struct srtp_sha1_ctx_t {
    H: [u32; 5],
    M: [u32; 16],
    octets_in_buffer: c_int,
    num_bits_in_msg: u32,
}

extern "C" {
    fn srtp_sha1_init(ctx: *mut srtp_sha1_ctx_t);
    fn srtp_sha1_update(ctx: *mut srtp_sha1_ctx_t, M: *const u8, octets_in_msg: c_int);
    fn srtp_sha1_final(ctx: *mut srtp_sha1_ctx_t, output: *mut u32);
}

pub struct Sha1 {
    ctx: srtp_sha1_ctx_t,
}

impl Sha1 {
    pub fn new() -> Self {
        let mut sha1 = Self {
            ctx: srtp_sha1_ctx_t::default(),
        };
        unsafe { srtp_sha1_init(&mut sha1.ctx) };
        sha1
    }

    pub fn update(&mut self, data: &[u8]) {
        let data_ptr = data.as_ptr();
        let data_len: c_int = data.len().try_into().unwrap();
        unsafe { srtp_sha1_update(&mut self.ctx, data_ptr, data_len) };
    }

    pub fn finalize(&mut self, hash: &mut [u8; 20]) {
        let hash_ptr = hash.as_mut_ptr() as *mut u32;
        unsafe { srtp_sha1_final(&mut self.ctx, hash_ptr) };
    }
}
