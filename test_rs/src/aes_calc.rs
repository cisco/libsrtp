#![cfg(feature = "native-crypto")]

use crate::include::aes::*;
use clap::Clap;
use hex::FromHexError;
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

struct AesKeySize;
impl SizeValidator for AesKeySize {
    fn valid(size: usize) -> bool {
        AES_KEY_SIZES.contains(&size)
    }
}

struct AesBlockSize;
impl SizeValidator for AesBlockSize {
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

    key: SizeConstrainedHex<AesKeySize>,

    plaintext: SizeConstrainedHex<AesBlockSize>,
    ciphertext: Option<SizeConstrainedHex<AesBlockSize>>,
}

#[no_mangle]
pub extern "C" fn aes_calc_main() -> c_int {
    let config = Config::parse();

    if config.verbose {
        println!("plaintext:\t{}", hex::encode(&config.plaintext.data));
    }

    let key = match AesKey::new(&config.key.data) {
        Ok(x) => x,
        Err(_) => {
            println!("error: AES key expansion failed.");
            return 1;
        }
    };

    let mut ciphertext = config.plaintext.data.clone();
    key.encrypt(&mut ciphertext).unwrap();

    if config.verbose {
        println!("key:\t\t{}", hex::encode(&config.key.data));
        println!("ciphertext:\t{}", hex::encode(&ciphertext));
    }

    match config.ciphertext.as_ref() {
        Some(expected) if expected.data != ciphertext => 1,
        _ => 0,
    }
}
