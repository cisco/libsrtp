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

        // run validation test against the reference packets - note that this test only covers the
        // default policy
        println!("testing srtp_protect and srtp_unprotect against reference packet");
        check_pass_fail!(srtp_validate());

        println!("testing srtp_protect and srtp_unprotect against reference packet using null cipher and HMAC");
        check_pass_fail!(srtp_validate_null());

        println!("testing srtp_protect and srtp_unprotect against reference packet with encrypted extensions headers");
        check_pass_fail!(srtp_validate_encrypted_extensions_headers());

        println!("testing srtp_protect and srtp_unprotect against reference packet (AES-256)");
        check_pass_fail!(srtp_validate_aes_256());

        println!("testing srtp_protect and srtp_unprotect against packet with empty payload");
        check_pass_fail!(srtp_test_empty_payload());

        #[cfg(not(feature = "native-crypto"))]
        {
            println!("testing srtp_protect and srtp_unprotect against reference packet using GCM");
            check_pass_fail!(srtp_validate_gcm());

            println!("testing srtp_protect and srtp_unprotect against reference packet with encrypted extension headers (GCM)");
            check_pass_fail!(srtp_validate_encrypted_extensions_headers_gcm());

            println!(
                "testing srtp_protect and srtp_unprotect against packet with empty payload (GCM)"
            );
            check_pass_fail!(srtp_test_empty_payload_gcm());
        }

        println!("testing srtp_remove_stream()");
        check_pass_fail!(srtp_test_remove_stream());

        println!("testing srtp_update()");
        check_pass_fail!(srtp_test_update());

        println!("testing srtp_get_protect_trailer_length()");
        check_pass_fail!(srtp_test_protect_trailer_length());

        println!("testing srtp_get_protect_rtcp_trailer_length()");
        check_pass_fail!(srtp_test_protect_rtcp_trailer_length());

        println!("testing srtp_test_get_roc()");
        check_pass_fail!(srtp_test_get_roc());

        println!("testing srtp_test_set_receiver_roc()");
        check_pass_fail!(srtp_test_set_receiver_roc());

        println!("testing srtp_test_set_receiver_roc_then_rollover()");
        check_pass_fail!(srtp_test_set_receiver_roc_then_rollover());

        println!("testing srtp_test_set_sender_roc()");
        check_pass_fail!(srtp_test_set_sender_roc());
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

static TEST_MKI_ID_1: &'static [u8] = &hex!("e1f97a0d");
static TEST_MKI_ID_2: &'static [u8] = &hex!("f3a14671");

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
static KEY_128_1: &'static [u8] = &hex!("e1f97a0d3e018be0d64fa32c06de4139");
static SALT_128_ICM_1: &'static [u8] = &hex!("0ec675ad498afeebb6960b3aabe6");
static SALT_128_GCM_1: &'static [u8] = &hex!("0ec675ad498afeebb6960b3a");
static KEY_256_1: &'static [u8] = &hex!("e1f97a0d3e018be0d64fa32c06de4139"
                                        "0ec675ad498afeebb6960b3aabe6c173");

static KEY_128_2: &'static [u8] = &hex!("f0f04914b513f2763a1b1fa130f10e29");
static SALT_128_ICM_2: &'static [u8] = &hex!("98f6f6e43e4309d1e622a0e332b9");
static SALT_128_GCM_2: &'static [u8] = &hex!("98f6f6e43e4309d1e622a0e3");
static KEY_256_2: &'static [u8] = &hex!("f0f04914b513f2763a1b1fa130f10e29"
                                        "98f6f6e43e4309d1e622a0e332b9f1b6");

static SALT_256_ICM: &'static [u8] = &hex!("c317f2dabe357793b6960b3aabe6");
static SALT_256_GCM: &'static [u8] = &hex!("c317f2dabe357793b6960b3a");

// XXX(RLB): This seems redundant, but the C code defines it, so we do the same to match.
static TEST_GCM_MASTER_KEY: MasterKey = MasterKey {
    key: &hex!("000102030405060708090a0b0c0d0e0f"),
    salt: &hex!("a0a1a2a3a4a5a6a7a8a9aaab"),
    id: TEST_MKI_ID_1,
};

static TEST_KEYS_128_ICM: &[MasterKey] = &[
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

static TEST_KEYS_256_ICM: &[MasterKey] = &[
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

static TEST_KEYS_128_GCM: &[MasterKey] = &[
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

static TEST_KEYS_256_GCM: &[MasterKey] = &[
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

static POLICY_ARRAY: &[Policy] = &[
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

static INVALID_POLICY_ARRAY: &[Policy] = &[
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

static WILDCARD_POLICY: Policy = Policy {
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
fn create_test_packet(msg_octets: usize, ssrc: u32, ext_hdr: bool) -> (Vec<u8>, usize) {
    let header = RtpHeader {
        v: 2,
        p: 0,
        x: 0,
        cc: 0,
        m: 0,
        pt: 0xf,
        seq: 0x1234,
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

    pkt.extend_from_slice(&vec![0xff; MAX_TRAILER_LEN + 4]);

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
    let (mut msg, pt_len) = create_test_packet(msg_octets, ssrc, false);

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
    let (mut msg, pt_len) = create_test_packet(msg_octets, ssrc, false);
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

    let mut srtp_sender = Context::new(&send_policy)?;
    let mut srtp_receiver = Context::new(&receive_policy)?;

    // TODO print policy

    // initialize data buffer, using the ssrc in the policy unless that value is a wildcard, in
    // which case we'll just use an arbitrary one
    let ssrc = match policy[0].ssrc {
        Ssrc::Specific(ssrc) => ssrc,
        _ => 0xdecafbad,
    };

    const MSG_LEN_OCTETS: usize = 28;
    const RTP_HEADER_SIZE: usize = 12;

    let (mut pkt_buffer, pt_size) = create_test_packet(MSG_LEN_OCTETS, ssrc, enc_ext_hdr);
    let pkt_pt_ref = pkt_buffer[..pt_size].to_vec();

    // TODO print test packet before protection

    let ct_size = match mki_index {
        None => srtp_sender.protect(&mut pkt_buffer, pt_size)?,
        Some(mki_index) => srtp_sender.protect_mki(&mut pkt_buffer, pt_size, mki_index)?,
    };

    // TODO print test packet after protection

    // check for overrun of the srtp_protect() function
    //
    // The packet is followed by a value of 0xfffff; if the value of the
    // data following the packet is different, then we know that the
    // protect function is overwriting the end of the packet.
    //
    // TODO check that ct_size is as intended, according to the defined trailer size
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
        None => srtp_receiver.unprotect(&mut pkt_buffer[..ct_size])?,
        Some(_) => srtp_receiver.unprotect_mki(&mut pkt_buffer[..ct_size])?,
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
        None => srtp_receiver.unprotect(&mut pkt_buffer[..ct_size]),
        Some(_) => srtp_receiver.unprotect_mki(&mut pkt_buffer[..ct_size]),
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
            None => srtp_sender.protect(&mut pkt_buffer, pt_size)?,
            Some(mki_index) => srtp_sender.protect_mki(&mut pkt_buffer, pt_size, mki_index)?,
        };

        // flip bits in the packet
        let data_offset = if extension_header.is_none() { 12 } else { 24 };
        pkt_buffer[data_offset] ^= 0xff;

        // unprotect and check for authentication failure
        let result = match mki_index {
            None => srtp_receiver.unprotect(&mut pkt_buffer[..ct_size]),
            Some(_) => srtp_receiver.unprotect_mki(&mut pkt_buffer[..ct_size]),
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

    let mut srtcp_sender = Context::new(&send_policy)?;
    let mut srtcp_receiver = Context::new(&receive_policy)?;

    // TODO print policy

    // initialize data buffer, using the ssrc in the policy unless that value is a wildcard, in
    // which case we'll just use an arbitrary one
    let ssrc = match policy[0].ssrc {
        Ssrc::Specific(ssrc) => ssrc,
        _ => 0xdecafbad,
    };

    const MSG_LEN_OCTETS: usize = 28;
    const RTP_HEADER_SIZE: usize = 12;

    let (mut pkt_buffer, pt_size) = create_test_packet(MSG_LEN_OCTETS, ssrc, false);
    let pkt_pt_ref = pkt_buffer[..pt_size].to_vec();

    // TODO print test packet before protection

    let ct_size = match mki_index {
        None => srtcp_sender.protect_rtcp(&mut pkt_buffer, pt_size)?,
        Some(mki_index) => srtcp_sender.protect_rtcp_mki(&mut pkt_buffer, pt_size, mki_index)?,
    };

    // TODO print test packet after protection

    // check for overrun of the srtcp_protect() function
    //
    // The packet is followed by a value of 0xfffff; if the value of the
    // data following the packet is different, then we know that the
    // protect function is overwriting the end of the packet.
    //
    // TODO match this against srtcp_get_protect_rtcp_trailer_length
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
        None => srtcp_receiver.unprotect_rtcp(&mut pkt_buffer[..ct_size])?,
        Some(_) => srtcp_receiver.unprotect_rtcp_mki(&mut pkt_buffer[..ct_size])?,
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
        None => srtcp_receiver.unprotect_rtcp(&mut pkt_buffer[..ct_size]),
        Some(_) => srtcp_receiver.unprotect_rtcp_mki(&mut pkt_buffer[..ct_size]),
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
            None => srtcp_sender.protect_rtcp(&mut pkt_buffer, pt_size)?,
            Some(mki_index) => {
                srtcp_sender.protect_rtcp_mki(&mut pkt_buffer, pt_size, mki_index)?
            }
        };

        // flip bits in the packet
        let data_offset = 12;
        pkt_buffer[data_offset] ^= 0xff;

        // unprotect and check for authentication failure
        let result = match mki_index {
            None => srtcp_receiver.unprotect_rtcp(&mut pkt_buffer[..ct_size]),
            Some(_) => srtcp_receiver.unprotect_rtcp_mki(&mut pkt_buffer[..ct_size]),
        };
        match result {
            Err(Error::AuthFail) => {}
            Err(err) => return Err(err),
            Ok(_) => return Err(Error::Fail),
        }
    }

    Ok(())
}

fn srtp_validate() -> Result<(), Error> {
    const SRTP_PLAINTEXT: &'static [u8] = &hex!(
        "800f1234decafbad"
        "cafebabeabababab"
        "abababababababab"
        "abababab");
    const SRTP_CIPHERTEXT: &'static [u8] = &hex!(
        "800f1234decafbad"
        "cafebabe4e55dc4c"
        "e79978d88ca4d215"
        "949d2402b78d6acc"
        "99ea179b8dbb");
    const SRTCP_PLAINTEXT: &'static [u8] = &hex!(
        "81c8000bcafebabe"
        "abababababababab"
        "abababababababab");
    const SRTCP_CIPHERTEXT: &'static [u8] = &hex!(
        "81c8000bcafebabe"
        "7128035be487b9bd"
        "bef89041f977a5a8"
        "80000001993e08cd"
        "54d6c1230798");

    // create a session with a single stream using the default srtp
    // policy and with the SSRC value 0xcafebabe
    let policy = &[Policy {
        ssrc: Ssrc::Specific(0xcafebabe),
        rtp: CryptoPolicy::RTP_DEFAULT,
        rtcp: CryptoPolicy::RTCP_DEFAULT,
        keys: TEST_KEYS_128_ICM,
        window_size: 128,
        allow_repeat_tx: false,
        extension_headers_to_encrypt: &[],
    }];

    let mut send = Context::new(policy)?;
    let mut recv = Context::new(policy)?;

    // protect plaintext, then compare with ciphertext
    let mut srtp_buffer = vec![0u8; SRTP_CIPHERTEXT.len()];
    srtp_buffer[..SRTP_PLAINTEXT.len()].copy_from_slice(SRTP_PLAINTEXT);

    let srtp_ct_len = send.protect(&mut srtp_buffer, SRTP_PLAINTEXT.len())?;
    if &srtp_buffer[..srtp_ct_len] != SRTP_CIPHERTEXT {
        return Err(Error::Fail);
    }

    // protect plaintext rtcp, then compare with srtcp ciphertext
    let mut srtcp_buffer = vec![0u8; SRTCP_CIPHERTEXT.len()];
    srtcp_buffer[..SRTCP_PLAINTEXT.len()].copy_from_slice(SRTCP_PLAINTEXT);

    let srtcp_ct_len = send.protect_rtcp(&mut srtcp_buffer, SRTCP_PLAINTEXT.len())?;
    if &srtcp_buffer[..srtcp_ct_len] != SRTCP_CIPHERTEXT {
        return Err(Error::Fail);
    }

    // unprotect ciphertext, then compare with plaintext
    let srtp_pt_len = recv.unprotect(&mut srtp_buffer[..srtp_ct_len])?;
    if &srtp_buffer[..srtp_pt_len] != SRTP_PLAINTEXT {
        return Err(Error::Fail);
    }

    // unprotect srtcp ciphertext, then compare with rtcp plaintext
    let srtcp_pt_len = recv.unprotect_rtcp(&mut srtcp_buffer[..srtcp_ct_len])?;
    if &srtcp_buffer[..srtcp_pt_len] != SRTCP_PLAINTEXT {
        return Err(Error::Fail);
    }

    Ok(())
}

fn srtp_validate_null() -> Result<(), Error> {
    Ok(()) // TODO
}

fn srtp_validate_encrypted_extensions_headers() -> Result<(), Error> {
    Ok(()) // TODO
}

fn srtp_validate_aes_256() -> Result<(), Error> {
    Ok(()) // TODO
}

fn srtp_test_empty_payload() -> Result<(), Error> {
    Ok(()) // TODO
}

#[cfg(not(feature = "native-crypto"))]
fn srtp_validate_gcm() -> Result<(), Error> {
    Ok(()) // TODO
}

#[cfg(not(feature = "native-crypto"))]
fn srtp_validate_encrypted_extensions_headers_gcm() -> Result<(), Error> {
    Ok(()) // TODO
}

#[cfg(not(feature = "native-crypto"))]
fn srtp_test_empty_payload_gcm() -> Result<(), Error> {
    Ok(()) // TODO
}

fn srtp_test_remove_stream() -> Result<(), Error> {
    Ok(()) // TODO
}

fn srtp_test_update() -> Result<(), Error> {
    Ok(()) // TODO
}

fn srtp_test_protect_trailer_length() -> Result<(), Error> {
    Ok(()) // TODO
}

fn srtp_test_protect_rtcp_trailer_length() -> Result<(), Error> {
    Ok(()) // TODO
}

fn srtp_test_get_roc() -> Result<(), Error> {
    Ok(()) // TODO
}

fn srtp_test_set_receiver_roc() -> Result<(), Error> {
    Ok(()) // TODO
}

fn srtp_test_set_receiver_roc_then_rollover() -> Result<(), Error> {
    Ok(()) // TODO
}

fn srtp_test_set_sender_roc() -> Result<(), Error> {
    Ok(()) // TODO
}
