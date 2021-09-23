#![cfg(feature = "native-crypto")]

use crate::include::aes::*;
use clap::Clap;
use hex::FromHexError;
use std::convert::TryInto;
use std::marker::PhantomData;
use std::os::raw::c_int;
use std::str::FromStr;

const AES_KEY_SIZES: [usize; 2] = [16, 32];
const AES_BLOCK_SIZE: usize = 16;

trait SizeValidator {
    fn valid(size: usize) -> bool;
    fn decode(s: &str) -> Result<Vec<u8>, FromHexError> {
        hex::decode(s).and_then(|data| {
            if !Self::valid(data.len()) {
                Err(FromHexError::InvalidStringLength)
            } else {
                Ok(data)
            }
        })
    }
}

struct AesKey;
impl SizeValidator for AesKey {
    fn valid(size: usize) -> bool {
        AES_KEY_SIZES.contains(&size)
    }
}

struct AesBlock;
impl SizeValidator for AesBlock {
    fn valid(size: usize) -> bool {
        size == AES_BLOCK_SIZE
    }
}

struct SizeConstrainedHex<SV> {
    data: Vec<u8>,
    phantom_data: PhantomData<SV>,
}

impl<SV> FromStr for SizeConstrainedHex<SV>
where
    SV: SizeValidator,
{
    type Err = FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            data: SV::decode(s)?,
            phantom_data: PhantomData,
        })
    }
}

#[derive(Clap)]
struct Config {
    #[clap(short)]
    verbose: bool,

    key: SizeConstrainedHex<AesKey>,

    plaintext: SizeConstrainedHex<AesBlock>,
    ciphertext: Option<SizeConstrainedHex<AesBlock>>,
}

#[no_mangle]
pub extern "C" fn aes_calc_main() -> c_int {
    let config = Config::parse();

    if config.verbose {
        println!("plaintext:\t{}", hex::encode(&config.plaintext.data));
    }

    let mut exp_key = srtp_aes_expanded_key_t::default();
    let key_ptr = config.key.data.as_ptr();
    let key_len: i32 = config.key.data.len().try_into().unwrap();
    if unsafe { srtp_aes_expand_encryption_key(key_ptr, key_len, &mut exp_key).is_err() } {
        println!("error: AES key expansion failed.");
        return 1;
    }

    let mut ciphertext: v128_t = config.plaintext.data.into();
    unsafe { srtp_aes_encrypt(&mut ciphertext, &exp_key) };

    if config.verbose {
        println!("key:\t\t{}", hex::encode(&config.key.data));
        println!("ciphertext:\t{}", hex::encode(unsafe { &ciphertext.v8 }));
    }

    match config.ciphertext.as_ref() {
        Some(expected) => unsafe {
            let expected_v128: v128_t = expected.data.clone().into();
            if ciphertext.v8 != expected_v128.v8 {
                1
            } else {
                0
            }
        },
        _ => 0,
    }
}
