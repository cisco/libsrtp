#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

#[repr(C)]
#[derive(Copy, Clone)]
pub union v128_t {
    pub v8: [u8; 16],
    pub v16: [u16; 8],
    pub v32: [u32; 4],
    pub v64: [u64; 2],
}

impl Default for v128_t {
    fn default() -> Self {
        Self { v8: [0; 16] }
    }
}

impl From<Vec<u8>> for v128_t {
    fn from(vec: Vec<u8>) -> Self {
        let mut v128 = Self::default();
        unsafe { v128.v8.copy_from_slice(&vec) };
        v128
    }
}
