use crate::include::srtp::*;
use clap::Clap;
use hex_literal::hex;
use packed_struct::PackedStruct;
use std::os::raw::c_int;
use std::time::Instant;

#[derive(Clap)]
struct Config {
    #[clap(short = 't', about = "run timing test")]
    timing: bool,

    #[clap(short = 'r', about = "run rejection timing test")]
    rejection_timing: bool,

    #[clap(short = 'c', about = "run codec timing test")]
    codec_timing: bool,

    #[clap(short = 'v', about = "run validation tests")]
    validation: bool,

    #[clap(short = 'o', about = "output logging to stdout")]
    log_to_stdout: bool,

    #[clap(short = 'l', about = "list debug modules")]
    list_debug_modules: bool,

    #[clap(
        short = 'd',
        about = "turn on debugging for module <debug>",
        multiple_occurrences = true
    )]
    debug_modules: Vec<String>,
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

macro_rules! check_pass_fail {
    ($val:expr) => {
        match $val {
            Ok(x) => {
                println!("passed");
                x
            }
            Err(err) => {
                println!("failed (code {:?})", err);
                return 1;
            }
        }
    };
}

#[no_mangle]
pub extern "C" fn srtp_driver_main() -> c_int {
    // TODO load srtp_driver debug module

    // process input arguments
    let config = Config::parse();

    if !config.validation
        && !config.rejection_timing
        && !config.codec_timing
        && !config.validation
        && !config.list_debug_modules
    {
        // TODO usage()
        return 1;
    }

    if config.log_to_stdout {
        // TODO install log handler
    }

    if config.list_debug_modules {
        // TODO list debug modules
        return 0;
    }

    if config.validation {
        for policy in POLICY_ARRAY {
            let policy = &[policy.clone()];

            println!("testing srtp_protect and srtp_unprotect");
            check_pass_fail!(srtp_test(policy, None, None));

            println!("testing srtp_protect and srtp_unprotect with encrypted extensions headers");
            check_pass_fail!(srtp_test(policy, Some(1), None));

            println!("testing srtp_protect_rtcp and srtp_unprotect_rtcp");
            check_pass_fail!(srtcp_test(policy, None));

            println!("testing srtp_protect and srtp_unprotect with MKI index set to 0");
            check_pass_fail!(srtp_test(policy, None, Some(0)));

            println!("testing srtp_protect and srtp_unprotect with MKI index set to 1");
            check_pass_fail!(srtp_test(policy, None, Some(1)));

            println!("testing srtp_protect_rtcp and srtp_unprotect_rtcp with MKI index set to 0");
            check_pass_fail!(srtcp_test(policy, Some(0)));

            println!("testing srtp_protect_rtcp and srtp_unprotect_rtcp with MKI index set to 1");
            check_pass_fail!(srtcp_test(policy, Some(1)));
        }

        // loop over invalid policy array, testing that an SRTP context cannot
        // be created with the policy
        for policy in INVALID_POLICY_ARRAY {
            println!("testing srtp_create fails with invalid policy");
            match Context::new(&[policy.clone()]) {
                Err(_) => {
                    println!("passed");
                }
                Ok(_) => {
                    println!("failed");
                    return 1;
                }
            }
        }

        // create a big policy list and run tests on it
        let big_policy = create_big_policy();

        println!("testing srtp_protect and srtp_unprotect with big policy");
        check_pass_fail!(srtp_test(&big_policy, None, None));

        println!("testing srtp_protect and srtp_unprotect with big policy and encrypted extensions headers");
        check_pass_fail!(srtp_test(&big_policy, Some(1), None));

        // run test on wildcard policy
        println!("testing srtp_protect and srtp_unprotect on wildcard ssrc policy");
        check_pass_fail!(srtp_test(&[WILDCARD_POLICY.clone()], None, None));

        println!("testing srtp_protect and srtp_unprotect on wildcard ssrc policy and encrypted extensions headers");
        check_pass_fail!(srtp_test(&[WILDCARD_POLICY.clone()], Some(1), None));

        // run validation test against the reference packets
        for tc in VALIDATION_TEST_CASES {
            println!("testing srtp_protect and srtp_unprotect {}", tc.name);
            check_pass_fail!(tc.check());
        }

        println!("testing srtp_remove_stream()");
        check_pass_fail!(test_remove_stream());

        println!("testing srtp_update()");
        check_pass_fail!(test_update());

        println!("testing srtp_get_protect_trailer_length()");
        println!("testing srtp_get_protect_rtcp_trailer_length()");
        check_pass_fail!(test_max_trailer_size());

        println!("testing srtp_test_get_roc()");
        check_pass_fail!(test_get_roc());

        println!("testing srtp_test_set_receiver_roc()");
        check_pass_fail!(test_set_receiver_roc());

        println!("testing srtp_test_set_receiver_roc_then_rollover()");
        check_pass_fail!(test_set_receiver_roc_then_rollover());

        println!("testing srtp_test_set_sender_roc()");
        check_pass_fail!(test_set_sender_roc());
    }

    if config.timing {
        for p in POLICY_ARRAY {
            check!(do_timing(p));
        }
    }

    if config.rejection_timing {
        for p in POLICY_ARRAY {
            check!(do_rejection_timing(p));
        }
    }

    if config.codec_timing {
        let policy = Policy {
            ssrc: Ssrc::Specific(0xdecafbad),
            rtp: CryptoPolicy::RTP_DEFAULT,
            rtcp: CryptoPolicy::RTCP_DEFAULT,
            keys: TEST_KEYS_128_ICM,
            window_size: 128,
            allow_repeat_tx: false,
            extension_headers_to_encrypt: &[],
        };

        let (_, mips_value) = mips_estimate(1_000_000_000);
        println!("mips estimate: {:e}", mips_value);

        println!("testing srtp processing time for voice codecs:");
        println!("codec\t\tlength (octets)\t\tsrtp instructions/second");

        const CODEC_CASES: [(&str, usize, f64); 8] = [
            ("G.711", 80, 0.01),
            ("G.711", 160, 0.02),
            ("G.726-32", 40, 0.01),
            ("G.726-32", 80, 0.02),
            ("G.729", 10, 0.01),
            ("G.729", 20, 0.02),
            ("Wideband", 320, 0.01),
            ("Wideband", 640, 0.02),
        ];
        for (name, bytes, adjustment) in &CODEC_CASES {
            let bps = check!(srtp_bits_per_second(*bytes, &policy));
            let ops = mips_value * 8.0 * (*bytes as f64) / bps / adjustment;
            println!("{}\t{}\t\t\t{:e}", name, bytes, ops);
        }
    }

    0
}

const TEST_MKI_ID_1: &'static [u8] = &hex!("e1f97a0d");
const TEST_MKI_ID_2: &'static [u8] = &hex!("f3a14671");

// XXX(RLB) Because our Rust interface to master keys uses separate key and salt, we have to be a
// little more verbose than the corresponding C code.  Where the C code uses one byte string, we
// have to manually slice it differently for 128-bit or 256-bit keys, and for ICM vs. GCM salts.
//
// * 16-byte key | 14-byte ICM salt | (16 bytes ignored)
// * 16-byte key | 12-byte GCM salt | (18 bytes ignored)
// * 32-byte key | 14-byte ICM salt
// * 32-byte key | 12-byte GCM salt | (2 bytes ignored)
//
// Test key 1:
// e1f97a0d3e018be0d64fa32c06de4139 0ec675ad498afeebb6960b3aabe6 c173c317f2dabe357793b6960b3aabe6
// e1f97a0d3e018be0d64fa32c06de4139 0ec675ad498afeebb6960b3a abe6c173c317f2dabe357793b6960b3aabe6
// e1f97a0d3e018be0d64fa32c06de41390ec675ad498afeebb6960b3aabe6c173 c317f2dabe357793b6960b3aabe6
// e1f97a0d3e018be0d64fa32c06de41390ec675ad498afeebb6960b3aabe6c173 c317f2dabe357793b6960b3a abe6
//
// Test key 2:
// f0f04914b513f2763a1b1fa130f10e29 98f6f6e43e4309d1e622a0e332b9 f1b6c317f2dabe357793b6960b3aabe6
// f0f04914b513f2763a1b1fa130f10e29 98f6f6e43e4309d1e622a0e3 32b9f1b6c317f2dabe357793b6960b3aabe6
// f0f04914b513f2763a1b1fa130f10e2998f6f6e43e4309d1e622a0e332b9f1b6 c317f2dabe357793b6960b3aabe6
// f0f04914b513f2763a1b1fa130f10e2998f6f6e43e4309d1e622a0e332b9f1b6 c317f2dabe357793b6960b3a abe6
//
// Unfortunately, Rust doesn't allow slicing in statics, so we have to repeat ourselves instead of
// having one buffer and taking slices of it for the variants.
const KEY_128_1: &'static [u8] = &hex!("e1f97a0d3e018be0d64fa32c06de4139");
const SALT_128_ICM_1: &'static [u8] = &hex!("0ec675ad498afeebb6960b3aabe6");
const SALT_128_GCM_1: &'static [u8] = &hex!("0ec675ad498afeebb6960b3a");
const KEY_256_1: &'static [u8] = &hex!("e1f97a0d3e018be0d64fa32c06de4139"
                                        "0ec675ad498afeebb6960b3aabe6c173");

const KEY_128_2: &'static [u8] = &hex!("f0f04914b513f2763a1b1fa130f10e29");
const SALT_128_ICM_2: &'static [u8] = &hex!("98f6f6e43e4309d1e622a0e332b9");
const SALT_128_GCM_2: &'static [u8] = &hex!("98f6f6e43e4309d1e622a0e3");
const KEY_256_2: &'static [u8] = &hex!("f0f04914b513f2763a1b1fa130f10e29"
                                        "98f6f6e43e4309d1e622a0e332b9f1b6");

const SALT_256_ICM: &'static [u8] = &hex!("c317f2dabe357793b6960b3aabe6");
const SALT_256_GCM: &'static [u8] = &hex!("c317f2dabe357793b6960b3a");

// XXX(RLB): This seems redundant, but the C code defines it, so we do the same to match.
const TEST_KEY_GCM: MasterKey = MasterKey {
    key: &hex!("000102030405060708090a0b0c0d0e0f"),
    salt: &hex!("a0a1a2a3a4a5a6a7a8a9aaab"),
    id: TEST_MKI_ID_1,
};

const TEST_KEYS_128_ICM: &[MasterKey] = &[
    MasterKey {
        key: KEY_128_1,
        salt: SALT_128_ICM_1,
        id: TEST_MKI_ID_1,
    },
    MasterKey {
        key: KEY_128_2,
        salt: SALT_128_ICM_2,
        id: TEST_MKI_ID_2,
    },
];

const TEST_KEYS_256_ICM: &[MasterKey] = &[
    MasterKey {
        key: KEY_256_1,
        salt: SALT_256_ICM,
        id: TEST_MKI_ID_1,
    },
    MasterKey {
        key: KEY_256_2,
        salt: SALT_256_ICM,
        id: TEST_MKI_ID_2,
    },
];

const TEST_KEYS_128_GCM: &[MasterKey] = &[
    MasterKey {
        key: KEY_128_1,
        salt: SALT_128_GCM_1,
        id: TEST_MKI_ID_1,
    },
    MasterKey {
        key: KEY_128_2,
        salt: SALT_128_GCM_2,
        id: TEST_MKI_ID_2,
    },
];

const TEST_KEYS_256_GCM: &[MasterKey] = &[
    MasterKey {
        key: KEY_256_1,
        salt: SALT_256_GCM,
        id: TEST_MKI_ID_1,
    },
    MasterKey {
        key: KEY_256_2,
        salt: SALT_256_GCM,
        id: TEST_MKI_ID_2,
    },
];

const POLICY_ARRAY: &[Policy] = &[
    // default_policy
    Policy {
        ssrc: Ssrc::AnyOutbound,
        rtp: CryptoPolicy::RTP_DEFAULT,
        rtcp: CryptoPolicy::RTCP_DEFAULT,
        keys: &TEST_KEYS_128_ICM,
        window_size: 128,
        allow_repeat_tx: false,
        extension_headers_to_encrypt: &[],
    },
    // aes_only_policy
    Policy {
        ssrc: Ssrc::AnyOutbound,
        rtp: CryptoPolicy::AES_ICM_128_NULL_AUTH,
        rtcp: CryptoPolicy::AES_ICM_128_NULL_AUTH,
        keys: TEST_KEYS_128_ICM,
        window_size: 128,
        allow_repeat_tx: false,
        extension_headers_to_encrypt: &[],
    },
    // hmac_only_policy
    Policy {
        ssrc: Ssrc::AnyOutbound,
        rtp: CryptoPolicy::NULL_CIPHER_HMAC_SHA1_80,
        rtcp: CryptoPolicy::NULL_CIPHER_HMAC_SHA1_80,
        keys: TEST_KEYS_128_ICM,
        window_size: 128,
        allow_repeat_tx: false,
        extension_headers_to_encrypt: &[],
    },
    // aes_256_hmac_policy
    Policy {
        ssrc: Ssrc::AnyOutbound,
        rtp: CryptoPolicy::AES_ICM_256_HMAC_SHA1_80,
        rtcp: CryptoPolicy::AES_ICM_256_HMAC_SHA1_80,
        keys: TEST_KEYS_256_ICM,
        window_size: 128,
        allow_repeat_tx: false,
        extension_headers_to_encrypt: &[],
    },
    // null_policy
    Policy {
        ssrc: Ssrc::AnyOutbound,
        rtp: CryptoPolicy::NULL_CIPHER_NULL_AUTH,
        rtcp: CryptoPolicy::NULL_CIPHER_NULL_AUTH,
        keys: TEST_KEYS_128_ICM,
        window_size: 128,
        allow_repeat_tx: false,
        extension_headers_to_encrypt: &[],
    },
    // aes_128_gcm_8_policy
    #[cfg(not(feature = "native-crypto"))]
    Policy {
        ssrc: Ssrc::AnyOutbound,
        rtp: CryptoPolicy::AES_GCM_128_8_AUTH,
        rtcp: CryptoPolicy::AES_GCM_128_8_AUTH,
        keys: TEST_KEYS_128_GCM,
        window_size: 128,
        allow_repeat_tx: false,
        extension_headers_to_encrypt: &[],
    },
    // aes_128_gcm_8_cauth_policy
    #[cfg(not(feature = "native-crypto"))]
    Policy {
        ssrc: Ssrc::AnyOutbound,
        rtp: CryptoPolicy::AES_GCM_128_8_AUTH,
        rtcp: CryptoPolicy::AES_GCM_128_8_AUTH_ONLY,
        keys: TEST_KEYS_128_GCM,
        window_size: 128,
        allow_repeat_tx: false,
        extension_headers_to_encrypt: &[],
    },
    // aes_256_gcm_8_policy
    #[cfg(not(feature = "native-crypto"))]
    Policy {
        ssrc: Ssrc::AnyOutbound,
        rtp: CryptoPolicy::AES_GCM_256_8_AUTH,
        rtcp: CryptoPolicy::AES_GCM_256_8_AUTH,
        keys: TEST_KEYS_256_GCM,
        window_size: 128,
        allow_repeat_tx: false,
        extension_headers_to_encrypt: &[],
    },
    // aes_256_gcm_8_cauth_policy
    #[cfg(not(feature = "native-crypto"))]
    Policy {
        ssrc: Ssrc::AnyOutbound,
        rtp: CryptoPolicy::AES_GCM_256_8_AUTH,
        rtcp: CryptoPolicy::AES_GCM_256_8_AUTH_ONLY,
        keys: TEST_KEYS_256_GCM,
        window_size: 128,
        allow_repeat_tx: false,
        extension_headers_to_encrypt: &[],
    },
];

const INVALID_POLICY_ARRAY: &[Policy] = &[
    // XXX(RLB) In the C version, this array tests that a policy that requests EKT is rejected.  In
    // the policy struct we are using here, we have removed the ability to request EKT, so it's
    // impossible to express such an invalid policy.
];

fn create_big_policy() -> Vec<Policy<'static>> {
    let mut policy = POLICY_ARRAY.to_vec();

    let mut ssrc: u32 = 0;
    for p in &mut policy {
        p.ssrc = Ssrc::Specific(ssrc);
        ssrc += 1;
    }

    policy
}

const WILDCARD_POLICY: Policy = Policy {
    ssrc: Ssrc::AnyOutbound,
    rtp: CryptoPolicy::RTP_DEFAULT,
    rtcp: CryptoPolicy::RTCP_DEFAULT,
    keys: TEST_KEYS_128_ICM,
    window_size: 128,
    allow_repeat_tx: false,
    extension_headers_to_encrypt: &[],
};

// note: the output of this function is formatted so that it
// can be used in gnuplot.  '#' indicates a comment, and "\r\n"
// terminates a record
fn do_timing(policy: &Policy) -> Result<(), Error> {
    print!("# testing srtp throughput:\r\n");
    print!("# mesg length (octets)\tthroughput (megabits per second)\r\n");

    for log_len in 4..12 {
        let len = 1 << log_len;
        let bps = srtp_bits_per_second(len, policy)?;
        print!("{}\t\t\t{}\r\n", len, bps / 1.0e6);
    }

    print!("\r\n\r\n");
    Ok(())
}

fn do_rejection_timing(policy: &Policy) -> Result<(), Error> {
    print!("# testing srtp rejection throughput:\r\n");
    print!("# mesg length (octets)\trejections per second\r\n");

    for log_len in 4..12 {
        let len = 1 << log_len;
        let rps = srtp_rejections_per_second(len, policy)?;
        print!("{}\t\t\t{}\r\n", len, rps);
    }

    print!("\r\n\r\n");
    Ok(())
}

// srtp_create_test_packet(len, ssrc) returns a pointer to a
// (malloced) example RTP packet whose data field has the length given
// by pkt_octet_len and the SSRC value ssrc.  The total length of the
// packet is twelve octets longer, since the header is at the
// beginning.  There is room at the end of the packet for a trailer,
// and the four octets following the packet are filled with 0xff
// values to enable testing for overwrites.
//
// note that the location of the test packet can (and should) be
// deallocated with the free() call once it is no longer needed.
fn create_test_packet(
    msg_octets: usize,
    ssrc: u32,
    seq: Option<u16>,
    ext_hdr: bool,
) -> (Vec<u8>, usize) {
    let header = RtpHeader {
        v: 2,
        p: 0,
        x: 0,
        cc: 0,
        m: 0,
        pt: 0xf,
        seq: seq.or(Some(0x1234_u16)).unwrap(),
        ts: 0xdecafbad,
        ssrc: ssrc,
    };
    let ext = hex!(
        "bede" // one-byte header
        "0002" // size
        "11"   // id 1, length 1 (i.e., 2 bytes)
        "cafe" // payload
        "00"   // padding
        "20"   // id 2, length 0 (i.e., 1 byte)
        "ba"   // payload
        "0000" // padding
    );

    let mut pkt = vec![];
    pkt.extend_from_slice(&header.pack().unwrap());
    if ext_hdr {
        pkt.extend_from_slice(&ext);
    }

    pkt.extend_from_slice(&vec![0xab; msg_octets]);
    let pt_size = pkt.len();

    pkt.extend_from_slice(&vec![0xff; MAX_TRAILER_SIZE + 4]);

    (pkt, pt_size)
}

fn srtp_bits_per_second(msg_octets: usize, policy: &Policy) -> Result<f64, Error> {
    const NUM_TRIALS: usize = 100_000;

    // allocate and initialize an srtp session
    let mut ctx = Context::new(&[policy.clone()])?;

    // if the ssrc is unspecified, use a predetermined one
    let ssrc = match policy.ssrc {
        Ssrc::Specific(ssrc) => ssrc,
        _ => 0xdeadbeef,
    };

    // create a test packet
    let (mut msg, pt_len) = create_test_packet(msg_octets, ssrc, None, false);

    let start = Instant::now();
    for _i in 0..NUM_TRIALS {
        // srtp protect message
        ctx.protect(&mut msg, pt_len)?;

        // increment message sequence number
        let seq = u16::from_be_bytes([msg[2], msg[3]]) + 1;
        msg[2..4].copy_from_slice(&seq.to_be_bytes());
    }
    let elapsed = start.elapsed();

    let bits = ((NUM_TRIALS * msg_octets) as f64) * 8.0;
    Ok(bits / elapsed.as_secs_f64())
}

fn srtp_rejections_per_second(msg_octets: usize, policy: &Policy) -> Result<f64, Error> {
    const NUM_TRIALS: usize = 100_000;

    // allocate and initialize an srtp session
    let mut ctx = Context::new(&[policy.clone()])?;

    // if the ssrc is unspecified, use a predetermined one
    let ssrc = match policy.ssrc {
        Ssrc::Specific(ssrc) => ssrc,
        _ => 0xdeadbeef,
    };

    // create a test packet
    let (mut msg, pt_len) = create_test_packet(msg_octets, ssrc, None, false);
    ctx.protect(&mut msg, pt_len)?;

    let start = Instant::now();
    for _i in 0..NUM_TRIALS {
        ctx.unprotect(&mut msg)?;
    }
    let elapsed = start.elapsed();

    let bits = ((NUM_TRIALS * msg_octets) as f64) * 8.0;
    Ok(bits / elapsed.as_secs_f64())
}

// mips_estimate() is a simple function to estimate the number of
// instructions per second that the host can perform.  note that this
// function can be grossly wrong; you may want to have a manual sanity
// check of its output!
//
// The usize return value is there to convince the compiler to not just
// optimize away the function
fn mips_estimate(num_trials: usize) -> (usize, f64) {
    let mut sum: usize = 0;
    let start = Instant::now();
    for i in 0..num_trials {
        sum += i;
    }
    let elapsed = start.elapsed();

    (sum, (num_trials as f64) / elapsed.as_secs_f64())
}

fn srtp_test(
    policy: &[Policy],
    extension_header: Option<u8>,
    mki_index: Option<usize>,
) -> Result<(), Error> {
    let mut send_policy: Vec<Policy> = Vec::with_capacity(policy.len());
    send_policy.extend_from_slice(policy);

    let mut receive_policy: Vec<Policy> = Vec::with_capacity(policy.len());
    receive_policy.extend_from_slice(policy);

    let enc_ext_hdr = extension_header.is_some();
    let mut ext_hdr: Vec<u8> = Vec::new();
    if let Some(hdr) = extension_header {
        ext_hdr.push(hdr);
    }

    for mut p in &mut send_policy {
        p.extension_headers_to_encrypt = &ext_hdr;
    }

    for mut p in &mut receive_policy {
        p.extension_headers_to_encrypt = &ext_hdr;

        if let Ssrc::AnyOutbound = p.ssrc {
            p.ssrc = Ssrc::AnyInbound;
        }
    }

    let mut send = Context::new(&send_policy)?;
    let mut recv = Context::new(&receive_policy)?;

    // initialize data buffer, using the ssrc in the policy unless that value is a wildcard, in
    // which case we'll just use an arbitrary one
    let ssrc = match policy[0].ssrc {
        Ssrc::Specific(ssrc) => ssrc,
        _ => 0xdecafbad,
    };

    const MSG_LEN_OCTETS: usize = 28;

    let (mut pkt_buffer, pt_size) = create_test_packet(MSG_LEN_OCTETS, ssrc, None, enc_ext_hdr);
    let pkt_pt_ref = pkt_buffer[..pt_size].to_vec();

    let ct_size = match mki_index {
        None => send.protect(&mut pkt_buffer, pt_size)?,
        Some(mki_index) => send.protect_mki(&mut pkt_buffer, pt_size, mki_index)?,
    };

    // check for overrun of the srtp_protect() function
    //
    // The packet is followed by a value of 0xfffff; if the value of the
    // data following the packet is different, then we know that the
    // protect function is overwriting the end of the packet.
    if ct_size > pt_size + send.max_trailer_size(mki_index)? {
        return Err(Error::AlgoFail);
    }

    if !pkt_buffer[ct_size..].iter().all(|&b| b == 0xff) {
        return Err(Error::AlgoFail);
    }

    // if the policy includes confidentiality, check that ciphertext is
    // different than plaintext
    //
    // Note that this check will give false negatives, with some small
    // probability, especially if the packets are short.  For that
    // reason, we skip this check if the plaintext is less than four
    // octets long.
    if policy[0].rtp.conf() {
        if &pkt_buffer[RTP_HEADER_SIZE..pt_size] == &pkt_pt_ref[RTP_HEADER_SIZE..pt_size] {
            return Err(Error::AlgoFail);
        }
    }

    // verify that the unprotected packet matches the original one
    let pt_size_dec = match mki_index {
        None => recv.unprotect(&mut pkt_buffer[..ct_size])?,
        Some(_) => recv.unprotect_mki(&mut pkt_buffer[..ct_size])?,
    };

    if &pkt_buffer[..pt_size_dec] != &pkt_pt_ref {
        return Err(Error::AlgoFail);
    }

    // unprotect a second time - should fail with a replay error
    // XXX(RLB) Note that:
    // * We are calling unprotect() on a plaintext packet (!)  This should be OK because the crypto
    //   is never invoked; unprotect should after a replay failure
    // * In the C version, this check is conditional on the security policy performing
    //   authentication.  Here it is unconditional, because the replay check is independent from
    //   authentication.
    let result = match mki_index {
        None => recv.unprotect(&mut pkt_buffer[..ct_size]),
        Some(_) => recv.unprotect_mki(&mut pkt_buffer[..ct_size]),
    };
    match result {
        Err(Error::ReplayFail) => {}
        Err(err) => return Err(err),
        Ok(_) => return Err(Error::Fail),
    }

    // if the policy includes authentication, then test for false positives
    if policy[0].rtp.auth() {
        // increment the sequence number
        pkt_buffer[3] += 1;

        // apply protection
        let ct_size = match mki_index {
            None => send.protect(&mut pkt_buffer, pt_size)?,
            Some(mki_index) => send.protect_mki(&mut pkt_buffer, pt_size, mki_index)?,
        };

        // flip bits in the packet
        let data_offset = if extension_header.is_none() { 12 } else { 24 };
        pkt_buffer[data_offset] ^= 0xff;

        // unprotect and check for authentication failure
        let result = match mki_index {
            None => recv.unprotect(&mut pkt_buffer[..ct_size]),
            Some(_) => recv.unprotect_mki(&mut pkt_buffer[..ct_size]),
        };
        match result {
            Err(Error::AuthFail) => {}
            Err(err) => return Err(err),
            Ok(_) => return Err(Error::Fail),
        }
    }

    Ok(())
}

fn srtcp_test(policy: &[Policy], mki_index: Option<usize>) -> Result<(), Error> {
    let mut send_policy: Vec<Policy> = Vec::with_capacity(policy.len());
    send_policy.extend_from_slice(policy);

    let mut receive_policy: Vec<Policy> = Vec::with_capacity(policy.len());
    receive_policy.extend_from_slice(policy);

    for mut p in &mut receive_policy {
        if let Ssrc::AnyOutbound = p.ssrc {
            p.ssrc = Ssrc::AnyInbound;
        }
    }

    let mut send = Context::new(&send_policy)?;
    let mut recv = Context::new(&receive_policy)?;

    // initialize data buffer, using the ssrc in the policy unless that value is a wildcard, in
    // which case we'll just use an arbitrary one
    let ssrc = match policy[0].ssrc {
        Ssrc::Specific(ssrc) => ssrc,
        _ => 0xdecafbad,
    };

    const MSG_LEN_OCTETS: usize = 28;
    const RTP_HEADER_SIZE: usize = 12;

    let (mut pkt_buffer, pt_size) = create_test_packet(MSG_LEN_OCTETS, ssrc, None, false);
    let pkt_pt_ref = pkt_buffer[..pt_size].to_vec();

    let ct_size = match mki_index {
        None => send.protect_rtcp(&mut pkt_buffer, pt_size)?,
        Some(mki_index) => send.protect_rtcp_mki(&mut pkt_buffer, pt_size, mki_index)?,
    };

    // check for overrun of the srtcp_protect() function
    //
    // The packet is followed by a value of 0xfffff; if the value of the
    // data following the packet is different, then we know that the
    // protect function is overwriting the end of the packet.
    if ct_size > pt_size + send.max_trailer_size_rtcp(mki_index)? {
        return Err(Error::AlgoFail);
    }

    if !pkt_buffer[ct_size..].iter().all(|&b| b == 0xff) {
        return Err(Error::AlgoFail);
    }

    // if the policy includes confidentiality, check that ciphertext is
    // different than plaintext
    //
    // Note that this check will give false negatives, with some small
    // probability, especially if the packets are short.  For that
    // reason, we skip this check if the plaintext is less than four
    // octets long.
    if policy[0].rtcp.conf() {
        if &pkt_buffer[RTP_HEADER_SIZE..pt_size] == &pkt_pt_ref[RTP_HEADER_SIZE..pt_size] {
            return Err(Error::AlgoFail);
        }
    }

    // verify that the unprotected packet matches the original one
    let pt_size_dec = match mki_index {
        None => recv.unprotect_rtcp(&mut pkt_buffer[..ct_size])?,
        Some(_) => recv.unprotect_rtcp_mki(&mut pkt_buffer[..ct_size])?,
    };

    if &pkt_buffer[..pt_size_dec] != &pkt_pt_ref {
        return Err(Error::AlgoFail);
    }

    // unprotect a second time - should fail with a replay error
    // XXX(RLB) Note that:
    // * We are calling unprotect() on a plaintext packet (!)  This should be OK because the crypto
    //   is never invoked; unprotect should after a replay failure
    // * In the C version, this check is conditional on the security policy performing
    //   authentication.  Here it is unconditional, because the replay check is independent from
    //   authentication.
    let result = match mki_index {
        None => recv.unprotect_rtcp(&mut pkt_buffer[..ct_size]),
        Some(_) => recv.unprotect_rtcp_mki(&mut pkt_buffer[..ct_size]),
    };
    match result {
        Err(Error::ReplayFail) => {}
        Err(err) => return Err(err),
        Ok(_) => return Err(Error::Fail),
    }

    // if the policy includes authentication, then test for false positives
    if policy[0].rtcp.auth() {
        // increment the sequence number
        pkt_buffer[3] += 1;

        // apply protection
        let ct_size = match mki_index {
            None => send.protect_rtcp(&mut pkt_buffer, pt_size)?,
            Some(mki_index) => send.protect_rtcp_mki(&mut pkt_buffer, pt_size, mki_index)?,
        };

        // flip bits in the packet
        let data_offset = 12;
        pkt_buffer[data_offset] ^= 0xff;

        // unprotect and check for authentication failure
        let result = match mki_index {
            None => recv.unprotect_rtcp(&mut pkt_buffer[..ct_size]),
            Some(_) => recv.unprotect_rtcp_mki(&mut pkt_buffer[..ct_size]),
        };
        match result {
            Err(Error::AuthFail) => {}
            Err(err) => return Err(err),
            Ok(_) => return Err(Error::Fail),
        }
    }

    Ok(())
}

struct ValidationTestCase {
    name: &'static str,
    srtp_plaintext: &'static [u8],
    srtp_ciphertext: &'static [u8],
    srtcp_plaintext: Option<&'static [u8]>,
    srtcp_ciphertext: Option<&'static [u8]>,
    policy: &'static [Policy<'static>],
}

impl ValidationTestCase {
    fn check(&self) -> Result<(), Error> {
        let mut send = Context::new(self.policy)?;
        let mut recv = Context::new(self.policy)?;

        // protect plaintext, then compare with ciphertext
        let mut srtp_buffer = vec![0u8; self.srtp_ciphertext.len()];
        srtp_buffer[..self.srtp_plaintext.len()].copy_from_slice(self.srtp_plaintext);

        let srtp_ct_len = send.protect(&mut srtp_buffer, self.srtp_plaintext.len())?;
        if &srtp_buffer[..srtp_ct_len] != self.srtp_ciphertext {
            println!(
                "{} ct {:x?} != {:x?}",
                self.name,
                &srtp_buffer[..srtp_ct_len],
                self.srtp_ciphertext,
            );
            return Err(Error::Fail);
        }

        // unprotect ciphertext, then compare with plaintext
        let srtp_pt_len = recv.unprotect(&mut srtp_buffer[..srtp_ct_len])?;
        if &srtp_buffer[..srtp_pt_len] != self.srtp_plaintext {
            println!(
                "{} pt {:x?} != {:x?}",
                self.name,
                &srtp_buffer[..srtp_pt_len],
                self.srtp_plaintext,
            );
            return Err(Error::Fail);
        }

        if let (Some(plaintext), Some(ciphertext)) = (self.srtcp_plaintext, self.srtcp_ciphertext) {
            // protect plaintext rtcp, then compare with srtcp ciphertext
            let mut srtcp_buffer = vec![0u8; ciphertext.len()];
            srtcp_buffer[..plaintext.len()].copy_from_slice(plaintext);

            let srtcp_ct_len = send.protect_rtcp(&mut srtcp_buffer, plaintext.len())?;
            if &srtcp_buffer[..srtcp_ct_len] != ciphertext {
                println!(
                    "{} c ct {:x?} != {:x?}",
                    self.name,
                    &srtcp_buffer[..srtcp_ct_len],
                    ciphertext,
                );
                return Err(Error::Fail);
            }

            // unprotect srtcp ciphertext, then compare with rtcp plaintext
            let srtcp_pt_len = recv.unprotect_rtcp(&mut srtcp_buffer[..srtcp_ct_len])?;
            if &srtcp_buffer[..srtcp_pt_len] != plaintext {
                println!(
                    "{} c pt {:x?} != {:x?}",
                    self.name,
                    &srtcp_buffer[..srtcp_pt_len],
                    plaintext,
                );
                return Err(Error::Fail);
            }
        }

        Ok(())
    }
}

const VALIDATION_TEST_CASES: &[ValidationTestCase] = &[
    // srtp_validate
    ValidationTestCase {
        name: "against reference packet",
        srtp_plaintext: &hex!("800f1234decafbadcafebabe"
                              "abababababababababababababababab"),
        srtp_ciphertext: &hex!("800f1234decafbadcafebabe"
                               "4e55dc4ce79978d88ca4d215949d2402b78d6acc99ea179b8dbb"),
        srtcp_plaintext: Some(&hex!("81c8000bcafebabe"
                                    "abababababababababababababababab")),
        srtcp_ciphertext: Some(&hex!("81c8000bcafebabe"
                                     "7128035be487b9bdbef89041f977a5a880000001993e08cd54d6c1230798")),
        policy: &[Policy {
            ssrc: Ssrc::Specific(0xcafebabe),
            rtp: CryptoPolicy::RTP_DEFAULT,
            rtcp: CryptoPolicy::RTCP_DEFAULT,
            keys: TEST_KEYS_128_ICM,
            window_size: 128,
            allow_repeat_tx: false,
            extension_headers_to_encrypt: &[],
        }],
    },
    // srtp_validate_null
    ValidationTestCase {
        name: "against reference packet using null cipher and HMAC",
        srtp_plaintext: &hex!("800f1234decafbadcafebabe"
                              "abababababababababababababababab"),
        srtp_ciphertext: &hex!("800f1234decafbadcafebabe"
                               "abababababababababababababababababa136270b679134ce9b"),
        srtcp_plaintext: Some(&hex!("81c8000bcafebabe"
                               "abababababababababababababababab")),
        srtcp_ciphertext: Some(&hex!("81c8000bcafebabe"
                                "abababababababababababababababab00000001fe88c7fdfd37ebce615d")),
        policy: &[Policy {
            ssrc: Ssrc::Specific(0xcafebabe),
            rtp: CryptoPolicy::NULL_CIPHER_HMAC_SHA1_80,
            rtcp: CryptoPolicy::NULL_CIPHER_HMAC_SHA1_80,
            keys: TEST_KEYS_128_ICM,
            window_size: 128,
            allow_repeat_tx: false,
            extension_headers_to_encrypt: &[],
        }],
    },
    // srtp_validate_gcm
    #[cfg(not(feature = "native-crypto"))]
    ValidationTestCase {
        name: "against reference packet using GCM",
        srtp_plaintext: &hex!("800f1234decafbadcafebabe"
                              "abababababababababababababababab"),
        srtp_ciphertext: &hex!("800f1234decafbadcafebabe"
                               "c5002ede04cfdd2eb91159e0880aa06ed2976826f796b201df3131a127e8a392"),
        srtcp_plaintext: Some(&hex!("81c8000bcafebabe"
                                    "abababababababababababababababab")),
        srtcp_ciphertext: Some(&hex!("81c8000bcafebabe"
                                     "c98b8b5df0392a55852b6c21ac8e7025c52c6fbea2b3b446ea31123ba88ce61e80000001")),
        policy: &[Policy {
            ssrc: Ssrc::Specific(0xcafebabe),
            rtp: CryptoPolicy::AES_GCM_128,
            rtcp: CryptoPolicy::AES_GCM_128,
            keys: &[TEST_KEY_GCM],
            window_size: 128,
            allow_repeat_tx: false,
            extension_headers_to_encrypt: &[],
        }],
    },
    // srtp_validate_encrypted_extensions_headers
    ValidationTestCase {
        name: "against reference packet with encrypted extensions headers",
        srtp_plaintext: &hex!("900f1234decafbadcafebabe"
                              "bede000617414273a475262748220000c8308e4655996386b395fb00"
                              "abababababababababababababababab"),
        srtp_ciphertext: &hex!("900f1234decafbadcafebabe"
                               "BEDE000617588A9270F4E15E1C220000C8309546A994F0BC54789700"
                               "4e55dc4ce79978d88ca4d215949d24025a46b3ca35c535a891c7"),
        srtcp_plaintext: None,
        srtcp_ciphertext: None,
        policy: &[Policy {
            ssrc: Ssrc::Specific(0xcafebabe),
            rtp: CryptoPolicy::RTP_DEFAULT,
            rtcp: CryptoPolicy::RTCP_DEFAULT,
            keys: TEST_KEYS_128_ICM,
            window_size: 128,
            allow_repeat_tx: false,
            extension_headers_to_encrypt: &[1, 3, 4],
        }],
    },
    // srtp_validate_encrypted_extensions_headers_gcm
    #[cfg(not(feature = "native-crypto"))]
    ValidationTestCase {
        name: "reference packet with encrypted extension headers (GCM)",
        srtp_plaintext: &hex!("900f1234decafbadcafebabe"
                              "bede000617414273a475262748220000c8308e4655996386b395fb00"
                              "abababababababababababababababab"),
        srtp_ciphertext: &hex!("900f1234decafbadcafebabe"
                               "bede00061712e0205bfa949b1c220000c830bb46732778d9929aab00"
                               "0eca0cf95ee955b26cd3d288b49f6ca9f4b1b759719eb5bc"),
        srtcp_plaintext: None,
        srtcp_ciphertext: None,
        policy: &[Policy {
            ssrc: Ssrc::Specific(0xcafebabe),
            rtp: CryptoPolicy::AES_GCM_128_8_AUTH,
            rtcp: CryptoPolicy::AES_GCM_128_8_AUTH,
            keys: &[MasterKey {
                key: &hex!("e1f97a0d3e018be0d64fa32c06de4139"),
                salt: &hex!("0ec675ad498afeebb6960b3aabe6"),
                id: &[],
            }],
            window_size: 128,
            allow_repeat_tx: false,
            extension_headers_to_encrypt: &[1, 3, 4],
        }],
    },
    // srtp_validate_aes_256
    ValidationTestCase {
        name: "against reference packet (AES-256)",
        srtp_plaintext: &hex!("800f1234decafbadcafebabe"
                              "abababababababababababababababab"),
        srtp_ciphertext: &hex!("800f1234decafbadcafebabe"
                               "f1d9de17ff251ff1aa007774b0b4b40da08d9d9a5b3a55d8873b"),
        srtcp_plaintext: None,
        srtcp_ciphertext: None,
        policy: &[Policy {
            ssrc: Ssrc::Specific(0xcafebabe),
            rtp: CryptoPolicy::AES_ICM_256_HMAC_SHA1_80,
            rtcp: CryptoPolicy::AES_ICM_256_HMAC_SHA1_80,
            keys: &[MasterKey {
                key: &hex!("f0f04914b513f2763a1b1fa130f10e2998f6f6e43e4309d1e622a0e332b9f1b6"),
                salt: &hex!("3b04803de51ee7c96423ab5b78d2"),
                id: &[],
            }],
            window_size: 128,
            allow_repeat_tx: false,
            extension_headers_to_encrypt: &[1, 3, 4],
        }],
    },
    // srtp_test_empty_payload
    ValidationTestCase {
        name: "packet with empty payload",
        srtp_plaintext: &hex!("800f1234decafbadcafebabe"),
        srtp_ciphertext: &hex!("800f1234decafbadcafebabe773c2e1cd91d590d16e5"),
        srtcp_plaintext: None,
        srtcp_ciphertext: None,
        policy: &[Policy {
            ssrc: Ssrc::Specific(0xcafebabe),
            rtp: CryptoPolicy::RTP_DEFAULT,
            rtcp: CryptoPolicy::RTCP_DEFAULT,
            keys: TEST_KEYS_128_ICM,
            window_size: 128,
            allow_repeat_tx: false,
            extension_headers_to_encrypt: &[],
        }],
    },
    // srtp_test_empty_payload_gcm
    #[cfg(not(feature = "native-crypto"))]
    ValidationTestCase {
        name: "packet with empty payload",
        srtp_plaintext: &hex!("800f1234decafbadcafebabe"),
        srtp_ciphertext: &hex!("800f1234decafbadcafebabef8b471a9e44e229c"),
        srtcp_plaintext: None,
        srtcp_ciphertext: None,
        policy: &[Policy {
            ssrc: Ssrc::Specific(0xcafebabe),
            rtp: CryptoPolicy::AES_GCM_128_8_AUTH,
            rtcp: CryptoPolicy::AES_GCM_128_8_AUTH,
            keys: TEST_KEYS_128_GCM,
            window_size: 128,
            allow_repeat_tx: false,
            extension_headers_to_encrypt: &[],
        }],
    },
];

fn test_remove_stream() -> Result<(), Error> {
    let policy = create_big_policy();
    let mut session = Context::new(&policy)?;

    // check for false positives by trying to remove a stream that's not in the session
    match session.remove_stream(0xaaaaaaaa) {
        Err(Error::NoCtx) => {}
        _ => return Err(Error::Fail),
    }

    // check for false negatives by removing stream 0x1, then searching for streams 0x0 and 0x2
    session.remove_stream(0x00000001)?;
    if !session.has_stream(0x00000000) || !session.has_stream(0x00000002) {
        return Err(Error::Fail);
    }

    // Now test adding and removing a single stream
    let ssrc: u32 = 0xcafebabe;
    let policy = Policy {
        ssrc: Ssrc::Specific(ssrc),
        rtp: CryptoPolicy::RTP_DEFAULT,
        rtcp: CryptoPolicy::RTCP_DEFAULT,
        keys: TEST_KEYS_128_ICM,
        window_size: 128,
        allow_repeat_tx: false,
        extension_headers_to_encrypt: &[],
    };

    let mut session = Context::new(&[])?;
    session.add_stream(&policy)?;
    session.remove_stream(ssrc)?;
    Ok(())
}

fn test_update() -> Result<(), Error> {
    let mut policy = Policy {
        ssrc: Ssrc::AnyOutbound,
        rtp: CryptoPolicy::RTP_DEFAULT,
        rtcp: CryptoPolicy::RTCP_DEFAULT,
        keys: TEST_KEYS_128_ICM,
        window_size: 128,
        allow_repeat_tx: false,
        extension_headers_to_encrypt: &[],
    };

    // create a send and recive ctx with defualt profile and test_key
    let mut send = Context::new(&[policy.clone()])?;

    policy.ssrc = Ssrc::AnyInbound;
    let mut recv = Context::new(&[policy.clone()])?;

    // protect and unprotect two msg's that will cause the ROC to be equal to 1
    let msg_len_octets: usize = 32;
    let ssrc: u32 = 0x12121212;

    for seq in [0xffff_u16, 0x0001_u16] {
        let (mut msg, pt_size) = create_test_packet(msg_len_octets, ssrc, Some(seq), false);
        let ct_size = send.protect(&mut msg, pt_size)?;
        recv.unprotect(&mut msg[..ct_size])?;
    }

    // update send ctx with same test_key t verify update works
    policy.ssrc = Ssrc::AnyOutbound;
    send.update(&[policy.clone()])?;

    let (mut msg, pt_size) = create_test_packet(msg_len_octets, ssrc, Some(0x0002), false);
    let ct_size = send.protect(&mut msg, pt_size)?;
    recv.unprotect(&mut msg[..ct_size])?;

    // update send ctx to use test_alt_key
    let test_alt_keys = &[MasterKey {
        key: &hex!("e5196f015ef19be1d747a72707d74733"),
        salt: &hex!("01c2354d596af7849698ebaaacf6"),
        id: &[],
    }];

    policy.keys = test_alt_keys;
    send.update(&[policy.clone()])?;

    // create and protect msg with new key and ROC still equal to 1
    let (mut msg, pt_size) = create_test_packet(msg_len_octets, ssrc, Some(0x0003), false);
    let ct_size = send.protect(&mut msg, pt_size)?;

    // verify that recive ctx will fail to unprotect as it still uses test_key
    match recv.unprotect(&mut msg[..ct_size]) {
        Err(Error::AuthFail) => {}
        _ => return Err(Error::Fail),
    };

    // create a new recvieve ctx with test_alt_key but since it is new it will
    // have ROC equal to 1 and therefore should fail to unprotected
    policy.ssrc = Ssrc::AnyInbound;
    policy.keys = test_alt_keys;
    let mut recv_roc_0 = Context::new(&[policy.clone()])?;
    match recv_roc_0.unprotect(&mut msg[..ct_size]) {
        Err(Error::AuthFail) => {}
        _ => return Err(Error::Fail),
    }

    // update recive ctx to use test_alt_key
    recv.update(&[policy.clone()])?;

    // verify that can still unprotect, therfore key is updated and ROC value is preserved
    recv.unprotect(&mut msg[..ct_size]).map(|_| ())?;

    Ok(())
}

fn test_max_trailer_size() -> Result<(), Error> {
    // Default policy
    let ctx = Context::new(&[Policy {
        ssrc: Ssrc::AnyOutbound,
        rtp: CryptoPolicy::RTP_DEFAULT,
        rtcp: CryptoPolicy::RTCP_DEFAULT,
        keys: TEST_KEYS_128_ICM,
        window_size: 128,
        allow_repeat_tx: false,
        extension_headers_to_encrypt: &[],
    }])?;

    let trailer_sizes = (
        ctx.max_trailer_size(None)?,
        ctx.max_trailer_size_rtcp(None)?,
        ctx.max_trailer_size(Some(1))?,
        ctx.max_trailer_size_rtcp(Some(1))?,
    );
    if trailer_sizes != (10, 14, 14, 18) {
        return Err(Error::Fail);
    }

    // GCM policy
    let ctx = Context::new(&[Policy {
        ssrc: Ssrc::AnyOutbound,
        rtp: CryptoPolicy::AES_GCM_128,
        rtcp: CryptoPolicy::AES_GCM_128,
        keys: TEST_KEYS_128_GCM,
        window_size: 128,
        allow_repeat_tx: false,
        extension_headers_to_encrypt: &[],
    }])?;

    let trailer_sizes = (
        ctx.max_trailer_size(None)?,
        ctx.max_trailer_size_rtcp(None)?,
        ctx.max_trailer_size(Some(1))?,
        ctx.max_trailer_size_rtcp(Some(1))?,
    );
    if trailer_sizes != (16, 20, 20, 24) {
        return Err(Error::Fail);
    }

    Ok(())
}

fn test_get_roc() -> Result<(), Error> {
    const MSG_LEN_OCTETS: usize = 32;
    const SSRC: u32 = 0xcafebabe;

    // Create a sender session
    let mut session = Context::new(&[Policy {
        ssrc: Ssrc::Specific(SSRC),
        rtp: CryptoPolicy::RTP_DEFAULT,
        rtcp: CryptoPolicy::RTCP_DEFAULT,
        keys: TEST_KEYS_128_ICM,
        window_size: 128,
        allow_repeat_tx: false,
        extension_headers_to_encrypt: &[],
    }])?;

    // Set start sequence so we roll over
    let cases: [(u16, u32); 2] = [(0xffff, 0x00000000), (0x0000, 0x00000001)];
    for (seq, roc) in cases {
        let (mut msg, pt_len) = create_test_packet(MSG_LEN_OCTETS, SSRC, Some(seq), false);
        session.protect(&mut msg, pt_len)?;

        let session_roc = session.get_stream_roc(SSRC)?;
        if session_roc != roc {
            return Err(Error::Fail);
        }
    }

    Ok(())
}

fn test_set_receiver_roc_inner(packets: usize, roc_to_set: u32) -> Result<(), Error> {
    const SSRC: u32 = 0xcafebabe;
    const MSG_LEN_OCTETS: usize = 32;

    #[cfg(feature = "native-crypto")]
    let (rtp, rtcp, keys) = (
        CryptoPolicy::RTP_DEFAULT,
        CryptoPolicy::RTCP_DEFAULT,
        TEST_KEYS_128_ICM,
    );

    #[cfg(not(feature = "native-crypto"))]
    let (rtp, rtcp, keys) = (
        CryptoPolicy::AES_GCM_128,
        CryptoPolicy::AES_GCM_128,
        TEST_KEYS_128_GCM,
    );

    let policy = &[Policy {
        ssrc: Ssrc::Specific(SSRC),
        rtp: rtp,
        rtcp: rtcp,
        keys: keys,
        window_size: 128,
        allow_repeat_tx: false,
        extension_headers_to_encrypt: &[],
    }];

    // Create sender and receiver
    let mut send = Context::new(policy)?;
    let mut recv = Context::new(policy)?;

    // Create and protect packets
    let mut seq: u16 = 0;
    for _ in 0..packets {
        let (mut msg, pt_size) = create_test_packet(MSG_LEN_OCTETS, SSRC, Some(seq), false);
        send.protect(&mut msg, pt_size)?;
        seq = seq.wrapping_add(1);
    }

    // Create the first packet to decrypt and test for ROC change
    let (mut pkt_1, pt_size_1) = create_test_packet(MSG_LEN_OCTETS, SSRC, Some(seq), false);
    let ct_size_1 = send.protect(&mut pkt_1, pt_size_1)?;
    seq = seq.wrapping_add(1);

    // Create the second packet to decrypt and test for ROC change
    let (mut pkt_2, pt_size_2) = create_test_packet(MSG_LEN_OCTETS, SSRC, Some(seq), false);
    let ct_size_2 = send.protect(&mut pkt_2, pt_size_2)?;

    // Set the ROC to the wanted value
    recv.set_stream_roc(SSRC, roc_to_set)?;

    // Unprotect the first packet
    recv.unprotect(&mut pkt_1[..ct_size_1])?;

    // Unprotect the second packet
    recv.unprotect(&mut pkt_2[..ct_size_2])?;

    Ok(())
}

fn test_set_receiver_roc() -> Result<(), Error> {
    // XXX(RLB) This code faithfully replicates the C test, but this could be improved quite a bit.
    // The (0, 0) case doesn't actualy do anything, and it's not necessary to actually encrypt
    // 2^16+1 packets to trigger roll-over.

    // First test does not rollover
    test_set_receiver_roc_inner(0, 0)?;
    test_set_receiver_roc_inner(1, 0)?;
    test_set_receiver_roc_inner(2, 0)?;
    test_set_receiver_roc_inner(1 + 60000, 0)?;

    // Second test should rollover
    test_set_receiver_roc_inner(0xfffe, 0)?;
    test_set_receiver_roc_inner(0xffff, 0)?;

    // Now the rollover counter should be 1
    test_set_receiver_roc_inner(0x10000, 1)?;
    test_set_receiver_roc_inner(0x10000 + 60000, 1)?;

    Ok(())
}

fn test_set_receiver_roc_then_rollover() -> Result<(), Error> {
    const SSRC: u32 = 0xcafebabe;
    const MSG_LEN_OCTETS: usize = 32;

    #[cfg(feature = "native-crypto")]
    let (rtp, rtcp, keys) = (
        CryptoPolicy::RTP_DEFAULT,
        CryptoPolicy::RTCP_DEFAULT,
        TEST_KEYS_128_ICM,
    );

    #[cfg(not(feature = "native-crypto"))]
    let (rtp, rtcp, keys) = (
        CryptoPolicy::AES_GCM_128,
        CryptoPolicy::AES_GCM_128,
        TEST_KEYS_128_GCM,
    );

    let policy = &[Policy {
        ssrc: Ssrc::Specific(SSRC),
        rtp: rtp,
        rtcp: rtcp,
        keys: keys,
        window_size: 128,
        allow_repeat_tx: false,
        extension_headers_to_encrypt: &[],
    }];

    // Create sender and receiver
    let mut send = Context::new(policy)?;
    let mut recv = Context::new(policy)?;

    // Create and protect packets to get to seq 65536 and roc == 1
    let mut seq: u16 = 0xffff;
    for _ in 0..65535 {
        let (mut msg, pt_size) = create_test_packet(MSG_LEN_OCTETS, SSRC, Some(seq), false);
        send.protect(&mut msg, pt_size)?;
        seq = seq.wrapping_add(1);
    }

    if send.get_stream_roc(SSRC)? != 1 {
        return Err(Error::Fail);
    }

    // Create the first packet to decrypt and test for ROC change
    let (mut pkt_1, pt_size_1) = create_test_packet(MSG_LEN_OCTETS, SSRC, Some(0xffff), false);
    let ct_size_1 = send.protect(&mut pkt_1, pt_size_1)?;

    // Create the second packet to decrypt and test for ROC change
    let (mut pkt_2, pt_size_2) = create_test_packet(MSG_LEN_OCTETS, SSRC, Some(0x0000), false);
    let ct_size_2 = send.protect(&mut pkt_2, pt_size_2)?;

    if send.get_stream_roc(SSRC)? != 2 {
        return Err(Error::Fail);
    }

    // Set the ROC to the wanted value
    recv.set_stream_roc(SSRC, 1)?;

    // Unprotect the first packet
    recv.unprotect(&mut pkt_1[..ct_size_1])?;

    // Unprotect the second packet
    recv.unprotect(&mut pkt_2[..ct_size_2])?;

    // Verify that the receiver rolled over
    if recv.get_stream_roc(SSRC)? != 2 {
        return Err(Error::Fail);
    }

    Ok(())
}

fn test_set_sender_roc_inner(seq: u16, roc_to_set: u32) -> Result<(), Error> {
    const SSRC: u32 = 0xcafebabe;
    const MSG_LEN_OCTETS: usize = 32;

    #[cfg(feature = "native-crypto")]
    let (rtp, rtcp, keys) = (
        CryptoPolicy::RTP_DEFAULT,
        CryptoPolicy::RTCP_DEFAULT,
        TEST_KEYS_128_ICM,
    );

    #[cfg(not(feature = "native-crypto"))]
    let (rtp, rtcp, keys) = (
        CryptoPolicy::AES_GCM_128,
        CryptoPolicy::AES_GCM_128,
        TEST_KEYS_128_GCM,
    );

    let policy = &[Policy {
        ssrc: Ssrc::Specific(SSRC),
        rtp: rtp,
        rtcp: rtcp,
        keys: keys,
        window_size: 128,
        allow_repeat_tx: false,
        extension_headers_to_encrypt: &[],
    }];

    // Create sender and receiver
    let mut send = Context::new(policy)?;
    let mut recv = Context::new(policy)?;

    // Set the ROC before encrypting the first packet
    send.set_stream_roc(SSRC, roc_to_set)?;

    // Create the packet to decrypt
    let (mut msg, pt_size) = create_test_packet(MSG_LEN_OCTETS, SSRC, Some(seq), false);
    let ct_size = send.protect(&mut msg, pt_size)?;

    // Set the ROC to the wanted value
    recv.set_stream_roc(SSRC, roc_to_set)?;
    recv.unprotect(&mut msg[..ct_size])?;
    Ok(())
}

fn test_set_sender_roc() -> Result<(), Error> {
    // XXX(RLB) This code faithfully replicates the C test, but I suspect it is incorrect.  For
    // example, the case (42310, 65535) is tested twice, once with the ROC in hex and once in
    // decimal.  Perhaps the intent was to set the SEQ in one of these?
    test_set_sender_roc_inner(43210, 0)?;
    test_set_sender_roc_inner(43210, 65535)?;
    test_set_sender_roc_inner(43210, 0xffff)?;
    test_set_sender_roc_inner(43210, 0xffff00)?;
    test_set_sender_roc_inner(43210, 0xfffffff0)?;
    Ok(())
}
