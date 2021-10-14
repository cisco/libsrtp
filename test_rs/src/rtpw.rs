use crate::include::cipher::*;
use crate::include::srtp::*;
use clap::Clap;
use packed_struct::PackedStructSlice;
use std::fs::File;
use std::io::{self, BufRead};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::os::raw::c_int;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn val_in_set(val: &str, set: &[&str]) -> Result<(), String> {
    if set.contains(&val) {
        Ok(())
    } else {
        Err(String::from("Invalid key size"))
    }
}

fn is_tag_size(val: &str) -> Result<(), String> {
    const VALUES: &[&'static str] = &["8", "16"];
    val_in_set(val, VALUES)
}

fn is_key_size(val: &str) -> Result<(), String> {
    const VALUES: &[&'static str] = &["128", "256"];
    val_in_set(val, VALUES)
}

struct HexData {
    data: Vec<u8>,
}

impl FromStr for HexData {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::decode(s).map(|data| Self { data: data })
    }
}

struct Base64Data {
    data: Vec<u8>,
}

impl FromStr for Base64Data {
    type Err = base64::DecodeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        base64::decode(s).map(|data| Self { data: data })
    }
}

#[derive(Clap)]
struct Config {
    #[clap(short = 'a', about = "use message authentication")]
    authentication: bool,

    #[clap(short = 'g', about = "Use AES-GCM mode (must be used with -e)")]
    gcm: bool,

    #[clap(short = 's', about = "act as rtp sender", conflicts_with = "receiver")]
    sender: bool,

    #[clap(short = 'r', about = "act as rtp receiver", conflicts_with = "sender")]
    receiver: bool,

    #[clap(short = 'l', about = "list debug modules")]
    list_debug_modules: bool,

    #[clap(short = 'e', about = "use encryption (use 128 or 256 for key size)", validator = is_key_size)]
    encryption_key_size: Option<usize>,

    #[clap(
        short = 't',
        about = "Tag size to use in GCM mode (use 8 or 16)",
        validator = is_tag_size,
        default_value = "8"
    )]
    tag_size: usize,

    #[clap(short = 'k', about = "sets the srtp master key given in hexadecimal")]
    master_key_hex: Option<HexData>,

    #[clap(short = 'b', about = "sets the srtp master key given in base64")]
    master_key_base64: Option<Base64Data>,

    #[clap(
        short = 'd',
        about = "turn on debugging for module <debug>",
        multiple_occurrences = true
    )]
    debug_modules: Vec<String>,

    #[clap(short = 'w', about = "use <wordsfile> for input")]
    words_file: Option<String>,

    #[clap()]
    dest_ip: IpAddr,

    #[clap()]
    dest_port: u16,
}

impl Config {
    const DEFAULT_KEY_SIZE: usize = 128;
    const DEFAULT_WORDS_FILE: &'static str = "words.txt";

    fn valid(&self) -> Result<(), String> {
        // We need to have a job to do
        if !self.sender && !self.receiver && !self.list_debug_modules {
            return Err(String::from("An action must be specified"));
        }

        // A key must be provided iff we are doing SRTP
        let sec_serv = self.security_services();
        let key = self.key();
        println!("{:?} {:?}", sec_serv, key);
        if (sec_serv != SecurityServices::None) != key.is_some() {
            return Err(String::from("A key must be provided iff SRTP is in use"));
        }

        // If a key is present, its size must match the expected key size
        if key.is_some() && (key.unwrap().len() != self.key_size()) {
            return Err(String::from("Key size does not match specified value"));
        }

        // GCM can only be enabled when authentication is provided
        if self.gcm && !sec_serv.auth() {
            return Err(String::from(
                "GCM mode cannot be used without authentication",
            ));
        }

        Ok(())
    }

    fn key<'a>(&'a self) -> Option<&'a [u8]> {
        self.master_key_hex
            .as_ref()
            .map(|k| k.data.as_slice())
            .or(self.master_key_base64.as_ref().map(|k| k.data.as_slice()))
    }

    fn master_key<'a>(&'a self) -> Option<MasterKey<'a>> {
        let key = match self.key() {
            Some(x) => x,
            None => return None,
        };

        let base_key_size = match key.len() {
            constants::AES_ICM_128_KEY_LEN_WSALT => constants::AES_128_KEY_LEN,
            constants::AES_ICM_192_KEY_LEN_WSALT => constants::AES_192_KEY_LEN,
            constants::AES_ICM_256_KEY_LEN_WSALT => constants::AES_256_KEY_LEN,
            constants::AES_GCM_128_KEY_LEN_WSALT => constants::AES_128_KEY_LEN,
            constants::AES_GCM_256_KEY_LEN_WSALT => constants::AES_256_KEY_LEN,
            _ => panic!("Invalid key size"),
        };

        Some(MasterKey {
            key: &key[..base_key_size],
            salt: &key[base_key_size..],
            id: &[],
        })
    }

    fn key_size(&self) -> usize {
        match self.encryption_key_size {
            Some(key_size) => key_size,
            None => Self::DEFAULT_KEY_SIZE,
        }
    }

    fn security_services(&self) -> SecurityServices {
        let confidentiality = self.encryption_key_size.is_some();
        let authentication = self.authentication || self.gcm;
        SecurityServices::from_flags(confidentiality, authentication)
    }

    fn words_file(&self) -> String {
        match self.words_file {
            Some(ref file) => file.clone(),
            None => String::from(Self::DEFAULT_WORDS_FILE),
        }
    }

    fn rtp_policy(&self) -> Result<CryptoPolicy, Error> {
        let conf = self.security_services().conf();
        let auth = self.security_services().auth();
        Ok(
            match (conf, auth, self.gcm, self.key_size(), self.tag_size) {
                (true, true, true, 128, 8) => CryptoPolicy::AES_GCM_128_8_AUTH,
                (true, true, true, 256, 8) => CryptoPolicy::AES_GCM_256_8_AUTH,
                (true, true, true, 128, 16) => CryptoPolicy::AES_GCM_128,
                (true, true, true, 256, 16) => CryptoPolicy::AES_GCM_256,
                (true, true, false, 128, _) => CryptoPolicy::RTP_DEFAULT,
                (true, true, false, 256, _) => CryptoPolicy::AES_ICM_256_HMAC_SHA1_80,
                (true, false, false, 128, _) => CryptoPolicy::AES_ICM_128_NULL_AUTH,
                (true, false, false, 256, _) => CryptoPolicy::AES_ICM_256_NULL_AUTH,
                (false, true, true, 128, 8) => CryptoPolicy::AES_GCM_128_8_AUTH_ONLY,
                (false, true, true, 256, 8) => CryptoPolicy::AES_GCM_256_8_AUTH_ONLY,
                (false, true, true, 128, 16) => CryptoPolicy::AES_GCM_128_AUTH_ONLY,
                (false, true, true, 256, 16) => CryptoPolicy::AES_GCM_256_AUTH_ONLY,
                (false, true, false, _, _) => CryptoPolicy::NULL_CIPHER_HMAC_SHA1_80,
                (false, false, _, _, _) => CryptoPolicy::NULL_CIPHER_NULL_AUTH,
                _ => return Err(Error::BadParam),
            },
        )
    }

    fn rtcp_policy(&self) -> Result<CryptoPolicy, Error> {
        let conf = self.security_services().conf();
        let auth = self.security_services().auth();
        Ok(
            match (conf, auth, self.gcm, self.key_size(), self.tag_size) {
                (true, true, false, 128, _) => CryptoPolicy::RTCP_DEFAULT,
                (true, true, false, 256, _) => CryptoPolicy::RTCP_DEFAULT,
                (true, false, false, 128, _) => CryptoPolicy::RTCP_DEFAULT,
                (true, false, false, 256, _) => CryptoPolicy::RTCP_DEFAULT,
                (false, true, true, 128, 16) => CryptoPolicy::AES_GCM_128_AUTH_ONLY,
                (false, true, true, 256, 16) => CryptoPolicy::AES_GCM_256_AUTH_ONLY,
                (false, true, false, _, _) => CryptoPolicy::RTCP_DEFAULT,
                _ => return self.rtp_policy(),
            },
        )
    }
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

fn ok_or_fail<V, T>(result: Result<V, T>) -> Result<V, Error> {
    result.map_err(|_| Error::Fail)
}

const SSRC: u32 = 0xdeadbeef;

#[no_mangle]
pub extern "C" fn rtpw_main() -> c_int {
    // process inputs
    let config = Config::parse();
    check!(config.valid());

    // report security services selected on the command line
    print!("security services: ");
    println!();
    match config.security_services() {
        SecurityServices::None => print!("none"),
        SecurityServices::Confidentiality => print!("confidentiality"),
        SecurityServices::Authentication => print!("message authentication"),
        SecurityServices::ConfAndAuth => print!("confidentiality message authentication"),
    }

    // set up the srtp policy and master key
    let policy = Policy {
        ssrc: Ssrc::Specific(SSRC),
        rtp: check!(config.rtp_policy()),
        rtcp: check!(config.rtcp_policy()),
        keys: &[config.master_key().unwrap()],
        window_size: 128,
        allow_repeat_tx: false,
        extension_headers_to_encrypt: &[],
    };

    // open socket
    let mut socket = check!(SrtpSocket::new(
        policy,
        config.dest_ip,
        config.dest_port,
        config.sender
    ));

    for mod_name in &config.debug_modules {
        check!(socket.srtp_ctx.set_debug_module(&mod_name, true));
    }

    if config.sender {
        // Read lines and send them as SRTP packets
        let file = check!(File::open(config.words_file()));
        for word in io::BufReader::new(file).lines() {
            let word = check!(word).into_bytes();
            check!(socket.send(&word));
        }
    } else if config.receiver {
        // Set a SIGTERM handler
        let term = Arc::new(AtomicBool::new(false));
        check!(signal_hook::flag::register(
            signal_hook::consts::SIGTERM,
            Arc::clone(&term)
        ));

        // Read packets until SIGTERM
        while !term.load(Ordering::Relaxed) {
            let word_data = check!(socket.recv());
            let word = check!(String::from_utf8(word_data.to_vec()));
            println!("\tword: {}", word);
        }
    } else if config.list_debug_modules {
        check!(socket.srtp_ctx.list_debug_modules());
    }

    0
}

struct SrtpSocket {
    socket: UdpSocket,
    srtp_ctx: Context,
    buffer: [u8; Self::SOCKET_BUFFER_SIZE],
    addr: (IpAddr, u16),
    header: RtpHeader,
}

impl SrtpSocket {
    const SOCKET_BUFFER_SIZE: usize = 1 << 14;
    const MULTICAST_TTL: u32 = 5;
    const RTP_HEADER_SIZE: usize = 12;

    fn new(policy: Policy, addr: IpAddr, port: u16, sender: bool) -> Result<Self, Error> {
        let sockaddr = (addr, port);
        let socket = ok_or_fail(UdpSocket::bind(sockaddr))?;
        if addr.is_multicast() {
            if sender {
                ok_or_fail(socket.set_multicast_ttl_v4(Self::MULTICAST_TTL))?;
            }

            match &sockaddr.0 {
                IpAddr::V4(addr) => {
                    ok_or_fail(socket.join_multicast_v4(addr, &Ipv4Addr::UNSPECIFIED))?
                }
                IpAddr::V6(addr) => ok_or_fail(socket.join_multicast_v6(addr, 0))?,
            }
        }

        Ok(Self {
            socket: socket,
            srtp_ctx: Context::new(&[policy])?,
            buffer: [0; Self::SOCKET_BUFFER_SIZE],
            addr: sockaddr,
            header: RtpHeader {
                v: 2,
                p: 0,
                x: 0,
                cc: 0,
                m: 0,
                pt: 1,
                seq: 0,
                ts: 0,
                ssrc: SSRC,
            },
        })
    }

    fn send(&mut self, msg: &[u8]) -> Result<(), Error> {
        // marshal data
        let rtp_size = Self::RTP_HEADER_SIZE + msg.len();
        self.buffer[Self::RTP_HEADER_SIZE..rtp_size].copy_from_slice(msg);

        // update header
        self.header.seq += 1;
        self.header.ts += 1;
        ok_or_fail(
            self.header
                .pack_to_slice(&mut self.buffer[..Self::RTP_HEADER_SIZE]),
        )?;

        // apply srtp
        let srtp_size = self.srtp_ctx.protect(&mut self.buffer, rtp_size)?;

        // send the packet
        let sent_size = self
            .socket
            .send_to(&self.buffer[..srtp_size], self.addr)
            .map_err(|_| Error::Fail)?;

        (sent_size == srtp_size).then(|| ()).ok_or(Error::Fail)
    }

    fn recv<'a>(&'a mut self) -> Result<&'a [u8], Error> {
        let srtp_size = ok_or_fail(self.socket.recv(&mut self.buffer))?;

        // verify rtp header
        let header = ok_or_fail(RtpHeader::unpack_from_slice(
            &mut self.buffer[..Self::RTP_HEADER_SIZE],
        ))?;
        if header.v != 2 || header.pt != 1 {
            return Err(Error::Fail);
        }

        // apply srtp
        let rtp_size = self.srtp_ctx.unprotect(&mut self.buffer[..srtp_size])?;

        Ok(&self.buffer[Self::RTP_HEADER_SIZE..rtp_size])
    }
}

impl Drop for SrtpSocket {
    fn drop(&mut self) {
        if self.addr.0.is_multicast() {
            match &self.addr.0 {
                IpAddr::V4(addr) => self
                    .socket
                    .leave_multicast_v4(addr, &Ipv4Addr::UNSPECIFIED)
                    .unwrap(),

                IpAddr::V6(addr) => self.socket.leave_multicast_v6(addr, 0).unwrap(),
            }
        }
    }
}
