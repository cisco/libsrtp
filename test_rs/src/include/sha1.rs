pub use super::types::*;

#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
pub struct srtp_sha1_ctx_t {
    pub H: [u32; 5],
    pub M: [u32; 16],
    pub octets_in_buffer: c_int,
    pub num_bits_in_msg: u32,
}

extern "C" {
    pub fn srtp_sha1_init(ctx: *mut srtp_sha1_ctx_t);
    pub fn srtp_sha1_update(ctx: *mut srtp_sha1_ctx_t, M: *const u8, octets_in_msg: c_int);
    pub fn srtp_sha1_final(ctx: *mut srtp_sha1_ctx_t, output: *mut u32);
}
