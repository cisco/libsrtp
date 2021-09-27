use crate::include::cipher::*;
use clap::Clap;
use hex::encode as hex_encode;
use hex_literal::hex;
use rand::{distributions::Standard, seq::SliceRandom, thread_rng, Rng};
use std::os::raw::c_int;
use std::time::Instant;

#[derive(Clap)]
struct Config {
    #[clap(short)]
    validation: bool,

    #[clap(short)]
    timing: bool,

    #[clap(short)]
    array_timing: bool,
}

macro_rules! check {
    ($val:expr) => {
        match $val {
            Ok(x) => x,
            Err(err) => {
                println!("error (code {:?})", err);
                return 1;
            }
        }
    };
}

#[no_mangle]
pub extern "C" fn cipher_driver_main() -> c_int {
    println!("cipher test driver");
    println!("David A. McGrew");
    println!("Cisco Systems, Inc.");

    let test_key = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");

    let config = Config::parse();

    // array timing (cache thrash) test
    if config.array_timing {
        check!(test_array_throughput_all(&NULL_CIPHER, 0));
        check!(test_array_throughput_all(
            &AES_ICM_128,
            constants::AES_ICM_128_KEY_LEN_WSALT
        ));
        check!(test_array_throughput_all(
            &AES_ICM_256,
            constants::AES_ICM_256_KEY_LEN_WSALT
        ));
        // TODO ifdef GCM...
    }

    if config.validation {
        check!(cipher_self_test(&NULL_CIPHER));
        check!(cipher_self_test(&AES_ICM_128));
        check!(cipher_self_test(&AES_ICM_256));
        // TODO ifdef GCM...
    }

    // do timing and/or buffer_test on srtp_null_cipher
    let cipher = check!(NULL_CIPHER.new(&[], 0));
    if config.timing {
        test_throughput(&cipher);
    }
    if config.validation {
        check!(test_buffering(&cipher));
    }

    // run the throughput test on the aes_icm cipher (128-bit key)
    let key = &test_key[..constants::AES_ICM_128_KEY_LEN_WSALT];
    let cipher = check!(NULL_CIPHER.new(key, 0));
    if config.timing {
        test_throughput(&cipher);
    }
    if config.validation {
        check!(test_buffering(&cipher));
    }

    // repeat the tests with 256-bit keys
    let key = &test_key[..constants::AES_ICM_256_KEY_LEN_WSALT];
    let cipher = check!(NULL_CIPHER.new(key, 0));
    if config.timing {
        test_throughput(&cipher);
    }
    if config.validation {
        check!(test_buffering(&cipher));
    }

    // TODO ifdef GCM...
    // run the throughput test on the aes_gcm_128 cipher
    // run the throughput test on the aes_gcm_256 cipher

    0
}

fn cipher_self_test(ct: &CipherType) -> Result<(), Error> {
    println!("running cipher self-test for {}...", ct.description());
    match ct.self_test() {
        Ok(x) => {
            println!("passed");
            Ok(x)
        }
        Err(err) => {
            println!("failed with error code {:?}", err);
            Err(err)
        }
    }
}

fn test_buffering(c: &Cipher) -> Result<(), Error> {
    const NUM_TRIALS: usize = 1000;
    const BUFFER_LEN: usize = 1024;
    const IV: [u8; 16] = hex!("00000000000000000000000000001234");
    let mut buffer0 = [0; BUFFER_LEN];
    let mut buffer1 = [0; BUFFER_LEN];
    let mut buflen: u32 = BUFFER_LEN as u32;
    let mut rng = thread_rng();

    println!("testing output buffering for cipher {}...", c.description());
    for i in 0..NUM_TRIALS {
        buffer0.fill(0);
        buffer1.fill(0);

        // Generate the reference value all at once
        c.set_iv(&IV)?;
        c.encrypt(&mut buffer0, &mut buflen)?;

        // Re-initialize and loop over short lengths
        c.set_iv(&IV)?;
        let mut start: usize = 0;
        while start < BUFFER_LEN {
            let remaining = BUFFER_LEN - start;
            let mut len = (1 + rng.gen_range(0..remaining)) as u32;
            let end = start + (len as usize);
            c.encrypt(&mut buffer1[start..end], &mut len)?;
            start = end;
        }

        for j in 0..BUFFER_LEN {
            if buffer0[j] != buffer1[j] {
                println!("test case {} failed at byte {}", i, j);
                println!("computed: {}", hex_encode(&buffer1));
                println!("expected: {}", hex_encode(&buffer0));
                return Err(Error::AlgoFail);
            }
        }
    }
    Ok(())
}

fn test_throughput(c: &Cipher) {
    const MIN_ENC_LEN: usize = 32;
    const MAX_ENC_LEN: usize = 2048;
    const NUM_TRIALS: usize = 1_000_000;

    println!(
        "timing {} throughput, key length {}:",
        c.description(),
        c.key_len()
    );
    let mut msg_size: usize = MIN_ENC_LEN;
    while msg_size <= MAX_ENC_LEN {
        let rate = c.bits_per_second(msg_size, NUM_TRIALS) as f64;
        println!(
            "msg len: {}\tgigabits per second: {}",
            msg_size,
            rate / 1.0e9
        );
        msg_size *= 2;
    }
}

/*
 * cipher_array_bits_per_second(c, l, t) computes (an estimate of) the
 * number of bits that a cipher implementation can encrypt in a second
 * when distinct keys are used to encrypt distinct messages
 *
 * c is a cipher (which MUST be allocated an initialized already), l
 * is the length in octets of the test data to be encrypted, and t is
 * the number of trials
 *
 * if an error is encountered, the value 0 is returned
 */
fn cipher_array_bits_per_second(
    cipher_array: &[Cipher],
    msg_size: usize,
    num_trials: usize,
) -> Result<f64, Error> {
    let mut rng = thread_rng();
    let mut enc_buf = vec![0u8; msg_size + 17];
    let mut nonce = [0u8; 16];

    let start = Instant::now();
    for i in 0..(num_trials as u32) {
        let mut octets_to_encrypt = msg_size as u32;
        nonce[12..].copy_from_slice(&i.to_be_bytes());

        let cipher = cipher_array.choose(&mut rng).unwrap();
        cipher.set_iv(&nonce)?;
        cipher.encrypt(&mut enc_buf, &mut octets_to_encrypt)?;
    }
    let elapsed = start.elapsed();

    let bits = (8 * msg_size * num_trials) as f64;
    Ok(bits / elapsed.as_secs_f64())
}

fn test_array_throughput(ct: &CipherType, key_len: usize, num_cipher: usize) -> Result<(), Error> {
    const MIN_ENC_LEN: usize = 16;
    const MAX_ENC_LEN: usize = 2048;
    const NUM_TRIALS: usize = 1_000_000;

    let mut cipher_array = Vec::new();
    for _ in 0..num_cipher {
        let key: Vec<u8> = thread_rng().sample_iter(&Standard).take(key_len).collect();
        let cipher = ct.new(&key, 16)?;
        cipher_array.push(cipher);
    }

    println!(
        "timing {} throughput with key length {}, array size {}:",
        ct.description(),
        cipher_array[0].key_len(),
        num_cipher
    );
    let mut msg_size = MIN_ENC_LEN;
    while msg_size <= MAX_ENC_LEN {
        let rate = cipher_array_bits_per_second(&cipher_array, msg_size, NUM_TRIALS)?;
        println!(
            "msg len: {}\tgigabits per second: {}",
            msg_size,
            rate / 1.0e9
        );
        msg_size *= 4;
    }

    Ok(())
}

fn test_array_throughput_all(ct: &CipherType, key_len: usize) -> Result<(), Error> {
    let num_ciphers_arr = {
        const MAX_NUM_CIPHERS: usize = 1 << 16;
        let mut v = vec![];
        let mut n = 1;
        while n < MAX_NUM_CIPHERS {
            v.push(n);
            n = n << 3;
        }
        v
    };

    for num_cipher in num_ciphers_arr {
        test_array_throughput(ct, key_len, num_cipher)?;
    }

    Ok(())
}
