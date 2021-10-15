use super::auth::*;
use super::cipher::*;
use packed_struct::prelude::*;
use std::marker::PhantomData;

const sec_serv_none: srtp_sec_serv_t = 0;
const sec_serv_conf: srtp_sec_serv_t = 1;
const sec_serv_auth: srtp_sec_serv_t = 2;
const sec_serv_conf_and_auth: srtp_sec_serv_t = 3;
type srtp_sec_serv_t = c_uint;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct srtp_crypto_policy_t {
    cipher_type: srtp_cipher_type_id_t,
    cipher_key_len: c_int,
    auth_type: srtp_auth_type_id_t,
    auth_key_len: c_int,
    auth_tag_len: c_int,
    sec_serv: srtp_sec_serv_t,
}

// const ssrc_undefined: srtp_ssrc_type_t = 0;
const ssrc_specific: srtp_ssrc_type_t = 1;
const ssrc_any_inbound: srtp_ssrc_type_t = 2;
const ssrc_any_outbound: srtp_ssrc_type_t = 3;
type srtp_ssrc_type_t = c_uint;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct srtp_ssrc_t {
    type_: srtp_ssrc_type_t,
    value: c_uint,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct srtp_master_key_t {
    key: *const c_uchar,
    mki_id: *const c_uchar,
    mki_size: c_uint,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct srtp_policy_t<'a> {
    ssrc: srtp_ssrc_t,
    rtp: srtp_crypto_policy_t,
    rtcp: srtp_crypto_policy_t,
    key: *const c_uchar,
    keys: *const *const srtp_master_key_t,
    num_master_keys: c_ulong,
    deprecated_ekt: *const c_void,
    window_size: c_ulong,
    allow_repeat_tx: c_int,
    enc_xtn_hdr: *const c_int,
    enc_xtn_hdr_count: c_int,
    next: *const srtp_policy_t<'a>,

    // This marker ensures that the srtp_policy_t doesn't outlive the PolicyConversionData from
    // which it is constructed.  This is important because the arrays here reference data held by
    // the Policy/PolicyConversionData.  This field is zero-sized, so it doesn't affect the size of
    // the struct, which is important for FFI purposes.
    //
    // XXX(RLB): It would be slightly safer to also apply this control at the srtp_master_key_t
    // level, but due to the contortions required to make the `keys` array, this would require
    // internal references inside of PolicyConversionData.
    _marker: PhantomData<&'a [u8]>,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct srtp_ctx_t {
    _unused: [u8; 0],
}
type srtp_t = *mut srtp_ctx_t;

extern "C" {
    fn srtp_init() -> srtp_err_status_t;
    fn srtp_shutdown() -> srtp_err_status_t;
    fn srtp_protect(ctx: srtp_t, rtp_hdr: *mut c_void, len_ptr: *mut c_int) -> srtp_err_status_t;
    fn srtp_protect_mki(
        ctx: *mut srtp_ctx_t,
        rtp_hdr: *mut c_void,
        pkt_octet_len: *mut c_int,
        use_mki: c_uint,
        mki_index: c_uint,
    ) -> srtp_err_status_t;
    fn srtp_unprotect(ctx: srtp_t, srtp_hdr: *mut c_void, len_ptr: *mut c_int)
        -> srtp_err_status_t;
    fn srtp_unprotect_mki(
        ctx: srtp_t,
        srtp_hdr: *mut c_void,
        len_ptr: *mut c_int,
        use_mki: c_uint,
    ) -> srtp_err_status_t;
    fn srtp_create<'a>(session: *mut srtp_t, policy: *const srtp_policy_t<'a>)
        -> srtp_err_status_t;
    /*
    fn srtp_add_stream<'a>(session: srtp_t, policy: *const srtp_policy_t<'a>) -> srtp_err_status_t;
    fn srtp_remove_stream(session: srtp_t, ssrc: c_uint) -> srtp_err_status_t;
    fn srtp_update<'a>(session: srtp_t, policy: *const srtp_policy_t<'a>) -> srtp_err_status_t;
    fn srtp_update_stream<'a>(
        session: srtp_t,
        policy: *const srtp_policy_t<'a>,
    ) -> srtp_err_status_t;
    fn srtp_crypto_policy_set_rtp_default(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_rtcp_default(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_aes_cm_128_null_auth(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_null_cipher_hmac_sha1_80(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_null_cipher_hmac_null(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_aes_cm_256_null_auth(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_aes_cm_192_hmac_sha1_80(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_aes_cm_192_hmac_sha1_32(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_aes_cm_192_null_auth(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_aes_gcm_128_8_auth(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_aes_gcm_256_8_auth(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_aes_gcm_128_8_only_auth(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_aes_gcm_256_8_only_auth(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_aes_gcm_128_16_auth(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_aes_gcm_256_16_auth(p: *mut srtp_crypto_policy_t);
    */
    fn srtp_dealloc(s: srtp_t) -> srtp_err_status_t;
}

/*
const srtp_profile_reserved: srtp_profile_t = 0;
const srtp_profile_aes128_cm_sha1_80: srtp_profile_t = 1;
const srtp_profile_aes128_cm_sha1_32: srtp_profile_t = 2;
const srtp_profile_null_sha1_80: srtp_profile_t = 5;
const srtp_profile_null_sha1_32: srtp_profile_t = 6;
const srtp_profile_aead_aes_128_gcm: srtp_profile_t = 7;
const srtp_profile_aead_aes_256_gcm: srtp_profile_t = 8;
type srtp_profile_t = c_uint;
*/

extern "C" {
    /*
    fn srtp_crypto_policy_set_from_profile_for_rtp(
        policy: *mut srtp_crypto_policy_t,
        profile: srtp_profile_t,
    ) -> srtp_err_status_t;
    fn srtp_crypto_policy_set_from_profile_for_rtcp(
        policy: *mut srtp_crypto_policy_t,
        profile: srtp_profile_t,
    ) -> srtp_err_status_t;
    fn srtp_profile_get_master_key_length(profile: srtp_profile_t) -> c_uint;
    fn srtp_profile_get_master_salt_length(profile: srtp_profile_t) -> c_uint;
    fn srtp_append_salt_to_key(
        key: *mut c_uchar,
        bytes_in_key: c_uint,
        salt: *mut c_uchar,
        bytes_in_salt: c_uint,
    );
    */
    fn srtp_protect_rtcp(
        ctx: srtp_t,
        rtcp_hdr: *mut c_void,
        pkt_octet_len: *mut c_int,
    ) -> srtp_err_status_t;
    fn srtp_protect_rtcp_mki(
        ctx: srtp_t,
        rtcp_hdr: *mut c_void,
        pkt_octet_len: *mut c_int,
        use_mki: c_uint,
        mki_index: c_uint,
    ) -> srtp_err_status_t;
    fn srtp_unprotect_rtcp(
        ctx: srtp_t,
        srtcp_hdr: *mut c_void,
        pkt_octet_len: *mut c_int,
    ) -> srtp_err_status_t;
    fn srtp_unprotect_rtcp_mki(
        ctx: srtp_t,
        srtcp_hdr: *mut c_void,
        pkt_octet_len: *mut c_int,
        use_mki: c_uint,
    ) -> srtp_err_status_t;
    /*
    fn srtp_set_user_data(ctx: srtp_t, data: *mut c_void);
    fn srtp_get_user_data(ctx: srtp_t) -> *mut c_void;
    */
}

/*
const event_ssrc_collision: srtp_event_t = 0;
const event_key_soft_limit: srtp_event_t = 1;
const event_key_hard_limit: srtp_event_t = 2;
const event_packet_index_limit: srtp_event_t = 3;
type srtp_event_t = c_uint;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct srtp_event_data_t {
    session: srtp_t,
    ssrc: u32,
    event: srtp_event_t,
}
*/

/*
type srtp_event_handler_func_t =
    ::std::option::Option<unsafe extern "C" fn(data: *mut srtp_event_data_t)>;
*/
extern "C" {
    /*
    fn srtp_install_event_handler(func: srtp_event_handler_func_t) -> srtp_err_status_t;
    fn srtp_get_version_string() -> *const c_char;
    fn srtp_get_version() -> c_uint;
    */
    fn srtp_set_debug_module(mod_name: *const c_char, v: c_int) -> srtp_err_status_t;
    fn srtp_list_debug_modules() -> srtp_err_status_t;
}

/*
const srtp_log_level_error: srtp_log_level_t = 0;
const srtp_log_level_warning: srtp_log_level_t = 1;
const srtp_log_level_info: srtp_log_level_t = 2;
const srtp_log_level_debug: srtp_log_level_t = 3;
type srtp_log_level_t = c_uint;

type srtp_log_handler_func_t = ::std::option::Option<
    unsafe extern "C" fn(level: srtp_log_level_t, msg: *const c_char, data: *mut c_void),
>;
*/

extern "C" {
    /*
    fn srtp_install_log_handler(
        func: srtp_log_handler_func_t,
        data: *mut c_void,
    ) -> srtp_err_status_t;
    */
    fn srtp_get_protect_trailer_length(
        session: srtp_t,
        use_mki: u32,
        mki_index: u32,
        length: *mut u32,
    ) -> srtp_err_status_t;
    fn srtp_get_protect_rtcp_trailer_length(
        session: srtp_t,
        use_mki: u32,
        mki_index: u32,
        length: *mut u32,
    ) -> srtp_err_status_t;
    fn srtp_set_stream_roc(session: srtp_t, ssrc: u32, roc: u32) -> srtp_err_status_t;
    fn srtp_get_stream_roc(session: srtp_t, ssrc: u32, roc: *mut u32) -> srtp_err_status_t;
}

////////////////////

pub use super::types::Error;

pub const MAX_TAG_LEN: usize = 16;
pub const MAX_MKI_LEN: usize = 128;
pub const MAX_TRAILER_LEN: usize = MAX_TAG_LEN + MAX_MKI_LEN;

// TODO: Refactor as struct{bool,bool}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityServices {
    None,
    Confidentiality,
    Authentication,
    ConfAndAuth,
}

impl SecurityServices {
    pub fn conf(&self) -> bool {
        match self {
            SecurityServices::Confidentiality | SecurityServices::ConfAndAuth => true,
            _ => false,
        }
    }

    pub fn auth(&self) -> bool {
        match self {
            SecurityServices::Authentication | SecurityServices::ConfAndAuth => true,
            _ => false,
        }
    }

    pub fn from_flags(conf: bool, auth: bool) -> Self {
        match (conf, auth) {
            (false, false) => Self::None,
            (true, false) => Self::Confidentiality,
            (false, true) => Self::Authentication,
            (true, true) => Self::ConfAndAuth,
        }
    }
}

impl Into<srtp_sec_serv_t> for SecurityServices {
    fn into(self) -> srtp_sec_serv_t {
        match self {
            SecurityServices::None => sec_serv_none,
            SecurityServices::Confidentiality => sec_serv_conf,
            SecurityServices::Authentication => sec_serv_auth,
            SecurityServices::ConfAndAuth => sec_serv_conf_and_auth,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CryptoPolicy {
    cipher: CipherTypeId,
    auth: AuthTypeId,
    security_services: SecurityServices,
}

impl CryptoPolicy {
    pub const RTP_DEFAULT: Self = Self::AES_ICM_128_HMAC_SHA1_80;

    pub const RTCP_DEFAULT: Self = Self::AES_ICM_128_HMAC_SHA1_80;

    pub const AES_ICM_128_HMAC_SHA1_80: Self = Self {
        cipher: CipherTypeId::AesIcm128,
        auth: AuthTypeId::HmacSha1(10),
        security_services: SecurityServices::ConfAndAuth,
    };

    /*
    pub const AES_ICM_128_HMAC_SHA1_32: Self = Self {
        cipher: CipherTypeId::AesIcm128,
        auth: AuthTypeId::HmacSha1(4),
        security_services: SecurityServices::ConfAndAuth,
    };
    */

    pub const AES_ICM_128_NULL_AUTH: Self = Self {
        cipher: CipherTypeId::AesIcm128,
        auth: AuthTypeId::Null,
        security_services: SecurityServices::Confidentiality,
    };

    pub const NULL_CIPHER_HMAC_SHA1_80: Self = Self {
        cipher: CipherTypeId::Null,
        auth: AuthTypeId::HmacSha1(10),
        security_services: SecurityServices::Authentication,
    };

    pub const NULL_CIPHER_NULL_AUTH: Self = Self {
        cipher: CipherTypeId::Null,
        auth: AuthTypeId::Null,
        security_services: SecurityServices::None,
    };

    pub const AES_ICM_256_HMAC_SHA1_80: Self = Self {
        cipher: CipherTypeId::AesIcm256,
        auth: AuthTypeId::HmacSha1(10),
        security_services: SecurityServices::ConfAndAuth,
    };

    /*
    pub const AES_ICM_256_HMAC_SHA1_32: Self = Self {
        cipher: CipherTypeId::AesIcm256,
        auth: AuthTypeId::HmacSha1(4),
        security_services: SecurityServices::ConfAndAuth,
    };
    */

    pub const AES_ICM_256_NULL_AUTH: Self = Self {
        cipher: CipherTypeId::AesIcm256,
        auth: AuthTypeId::Null,
        security_services: SecurityServices::Confidentiality,
    };

    /*
    pub const AES_ICM_192_HMAC_SHA1_80: Self = Self {
        cipher: CipherTypeId::AesIcm192,
        auth: AuthTypeId::HmacSha1(10),
        security_services: SecurityServices::ConfAndAuth,
    };

    pub const AES_ICM_192_HMAC_SHA1_32: Self = Self {
        cipher: CipherTypeId::AesIcm192,
        auth: AuthTypeId::HmacSha1(4),
        security_services: SecurityServices::ConfAndAuth,
    };

    pub const AES_ICM_192_NULL_AUTH: Self = Self {
        cipher: CipherTypeId::AesIcm192,
        auth: AuthTypeId::Null,
        security_services: SecurityServices::Confidentiality,
    };
    */

    pub const AES_GCM_128_8_AUTH: Self = Self {
        cipher: CipherTypeId::AesGcm128(8),
        auth: AuthTypeId::Null,
        security_services: SecurityServices::ConfAndAuth,
    };

    pub const AES_GCM_256_8_AUTH: Self = Self {
        cipher: CipherTypeId::AesGcm256(8),
        auth: AuthTypeId::Null,
        security_services: SecurityServices::ConfAndAuth,
    };

    pub const AES_GCM_128_8_AUTH_ONLY: Self = Self {
        cipher: CipherTypeId::AesGcm128(8),
        auth: AuthTypeId::Null,
        security_services: SecurityServices::Authentication,
    };

    pub const AES_GCM_256_8_AUTH_ONLY: Self = Self {
        cipher: CipherTypeId::AesGcm256(8),
        auth: AuthTypeId::Null,
        security_services: SecurityServices::Authentication,
    };

    pub const AES_GCM_128: Self = Self {
        cipher: CipherTypeId::AesGcm128(16),
        auth: AuthTypeId::Null,
        security_services: SecurityServices::ConfAndAuth,
    };

    pub const AES_GCM_256: Self = Self {
        cipher: CipherTypeId::AesGcm256(16),
        auth: AuthTypeId::Null,
        security_services: SecurityServices::ConfAndAuth,
    };

    pub const AES_GCM_128_AUTH_ONLY: Self = Self {
        cipher: CipherTypeId::AesGcm128(16),
        auth: AuthTypeId::Null,
        security_services: SecurityServices::Authentication,
    };

    pub const AES_GCM_256_AUTH_ONLY: Self = Self {
        cipher: CipherTypeId::AesGcm256(16),
        auth: AuthTypeId::Null,
        security_services: SecurityServices::Authentication,
    };

    pub fn conf(&self) -> bool {
        self.security_services.conf()
    }

    pub fn auth(&self) -> bool {
        self.security_services.auth()
    }

    fn as_srtp_crypto_policy_t(&self) -> Result<srtp_crypto_policy_t, Error> {
        let tag_size = match (self.cipher.tag_size(), self.auth.tag_size()) {
            (x, y) if x == y => x,
            (x, 0) | (0, x) => x,
            (_, _) => return Err(Error::BadParam),
        };

        Ok(srtp_crypto_policy_t {
            cipher_type: self.cipher.into(),
            cipher_key_len: self.cipher.key_size() as c_int,
            auth_type: self.auth.into(),
            auth_key_len: self.auth.key_size() as c_int,
            auth_tag_len: tag_size as c_int,
            sec_serv: self.security_services.into(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Ssrc {
    // Undefined,
    Specific(u32),
    AnyInbound,
    AnyOutbound,
}

impl Into<srtp_ssrc_t> for Ssrc {
    fn into(self) -> srtp_ssrc_t {
        let (type_, value) = match self {
            // Ssrc::Undefined => (ssrc_undefined, 0),
            Ssrc::Specific(ssrc) => (ssrc_specific, ssrc),
            Ssrc::AnyInbound => (ssrc_any_inbound, 0),
            Ssrc::AnyOutbound => (ssrc_any_outbound, 0),
        };

        srtp_ssrc_t {
            type_: type_,
            value: value,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MasterKey<'a> {
    pub key: &'a [u8],
    pub salt: &'a [u8],
    pub id: &'a [u8],
}

struct MasterKeyConversionData<'a> {
    master_key: &'a MasterKey<'a>,
    key_and_salt: Vec<u8>,
}

impl<'a> MasterKey<'a> {
    fn convert<'b>(&'b self) -> MasterKeyConversionData<'b> {
        let mut mkcd = MasterKeyConversionData {
            master_key: &self,
            key_and_salt: Vec::with_capacity(self.key.len() + self.salt.len()),
        };

        mkcd.key_and_salt.extend_from_slice(self.key);
        mkcd.key_and_salt.extend_from_slice(self.salt);
        mkcd
    }
}

impl<'a> MasterKeyConversionData<'a> {
    fn as_srtp_master_key_t(&self) -> srtp_master_key_t {
        srtp_master_key_t {
            key: self.key_and_salt.as_ptr(),
            mki_id: self.master_key.id.as_ptr(),
            mki_size: self.master_key.id.len() as c_uint,
        }
    }
}

type ExtensionHeaderId = u8;

#[derive(Clone, Debug)]
pub struct Policy<'a> {
    pub ssrc: Ssrc,
    pub rtp: CryptoPolicy,
    pub rtcp: CryptoPolicy,
    pub keys: &'a [MasterKey<'a>],
    pub window_size: usize,
    pub allow_repeat_tx: bool,
    pub extension_headers_to_encrypt: &'a [ExtensionHeaderId],
}

struct PolicyConversionData<'a> {
    policy: &'a Policy<'a>,
    key_conversion_data: Vec<MasterKeyConversionData<'a>>,
    keys: Vec<srtp_master_key_t>,
    key_ptrs: Vec<*const srtp_master_key_t>,
    enc_xtn_hdr: Vec<c_int>,
}

impl<'a> Policy<'a> {
    fn convert<'b>(&'b self) -> PolicyConversionData<'b> {
        let mut pcd = PolicyConversionData {
            policy: &self,
            key_conversion_data: Vec::with_capacity(self.keys.len()),
            keys: Vec::with_capacity(self.keys.len()),
            key_ptrs: Vec::with_capacity(self.keys.len()),
            enc_xtn_hdr: Vec::with_capacity(self.extension_headers_to_encrypt.len()),
        };

        for key in self.keys {
            let mkcd = key.convert();
            pcd.keys.push(mkcd.as_srtp_master_key_t());
            pcd.key_ptrs.push(&pcd.keys[pcd.keys.len() - 1]);
            pcd.key_conversion_data.push(mkcd);
        }

        for hdr in self.extension_headers_to_encrypt {
            pcd.enc_xtn_hdr.push(*hdr as c_int);
        }

        pcd
    }
}

impl<'a> PolicyConversionData<'a> {
    fn as_srtp_policy_t<'b>(&'b self) -> Result<srtp_policy_t<'b>, Error> {
        Ok(srtp_policy_t {
            ssrc: self.policy.ssrc.into(),
            rtp: self.policy.rtp.as_srtp_crypto_policy_t()?,
            rtcp: self.policy.rtcp.as_srtp_crypto_policy_t()?,
            key: std::ptr::null(),
            keys: self.key_ptrs.as_ptr(),
            num_master_keys: self.key_ptrs.len() as c_ulong,
            deprecated_ekt: std::ptr::null(),
            window_size: self.policy.window_size as c_ulong,
            allow_repeat_tx: if self.policy.allow_repeat_tx { 1 } else { 0 },
            enc_xtn_hdr: self.enc_xtn_hdr.as_ptr(),
            enc_xtn_hdr_count: self.enc_xtn_hdr.len() as c_int,
            next: std::ptr::null(),
            _marker: PhantomData,
        })
    }
}

use std::sync::atomic::AtomicU64;

static mut SRTP_REFCOUNT: AtomicU64 = AtomicU64::new(0);

pub struct Context {
    ctx: *mut srtp_ctx_t,
}

impl Context {
    pub fn new(policies: &[Policy]) -> Result<Self, Error> {
        // Ensure srtp_init
        let ctr = unsafe { SRTP_REFCOUNT.get_mut() };
        *ctr += 1;
        if *ctr == 1 {
            unsafe { srtp_init().as_result()? };
        }

        // Translate and chain the policies
        let pcd_vec: Vec<_> = policies.iter().map(|p| p.convert()).collect();
        let mut policy_vec: Vec<srtp_policy_t> = Vec::with_capacity(pcd_vec.len());
        for (i, pcd) in pcd_vec.iter().enumerate() {
            policy_vec.push(pcd.as_srtp_policy_t()?);
            if i > 0 {
                policy_vec[i - 1].next = &policy_vec[i];
            }
        }

        // Create the context
        let mut ctx = Context {
            ctx: std::ptr::null_mut(),
        };
        unsafe {
            srtp_create(&mut ctx.ctx, &policy_vec[0])
                .as_result()
                .map(|_| ctx)
        }
    }

    pub fn list_debug_modules(&self) -> Result<(), Error> {
        unsafe { srtp_list_debug_modules().as_result() }
    }

    pub fn set_debug_module(&mut self, mod_name: &str, enabled: bool) -> Result<(), Error> {
        let mod_name = mod_name.as_ptr() as *const i8;
        let enabled: c_int = if enabled { 1 } else { 0 };
        unsafe { srtp_set_debug_module(mod_name, enabled).as_result() }
    }

    pub fn protect(&mut self, data: &mut [u8], pt_size: usize) -> Result<usize, Error> {
        let rtp_hdr = data.as_mut_ptr() as *mut c_void;
        let mut len: c_int = pt_size as c_int;
        unsafe { srtp_protect(self.ctx, rtp_hdr, &mut len).as_result()? };
        Ok(len as usize)
    }

    pub fn protect_mki(
        &mut self,
        data: &mut [u8],
        pt_size: usize,
        mki_index: usize,
    ) -> Result<usize, Error> {
        let rtp_hdr = data.as_mut_ptr() as *mut c_void;
        let mut len: c_int = pt_size as c_int;
        let mki_index: c_uint = mki_index as c_uint;
        unsafe { srtp_protect_mki(self.ctx, rtp_hdr, &mut len, 1, mki_index).as_result()? };
        Ok(len as usize)
    }

    pub fn unprotect(&mut self, data: &mut [u8]) -> Result<usize, Error> {
        let rtp_hdr = data.as_mut_ptr() as *mut c_void;
        let mut len: c_int = data.len() as c_int;
        unsafe { srtp_unprotect(self.ctx, rtp_hdr, &mut len).as_result()? };
        Ok(len as usize)
    }

    pub fn unprotect_mki(&mut self, data: &mut [u8]) -> Result<usize, Error> {
        let rtp_hdr = data.as_mut_ptr() as *mut c_void;
        let mut len: c_int = data.len() as c_int;
        unsafe { srtp_unprotect_mki(self.ctx, rtp_hdr, &mut len, 1).as_result()? };
        Ok(len as usize)
    }

    pub fn protect_rtcp(&mut self, data: &mut [u8], pt_size: usize) -> Result<usize, Error> {
        let rtcp_hdr = data.as_mut_ptr() as *mut c_void;
        let mut len: c_int = pt_size as c_int;
        unsafe { srtp_protect_rtcp(self.ctx, rtcp_hdr, &mut len).as_result()? };
        Ok(len as usize)
    }

    pub fn protect_rtcp_mki(
        &mut self,
        data: &mut [u8],
        pt_size: usize,
        mki_index: usize,
    ) -> Result<usize, Error> {
        let rtcp_hdr = data.as_mut_ptr() as *mut c_void;
        let mut len: c_int = pt_size as c_int;
        let mki_index: c_uint = mki_index as c_uint;
        unsafe { srtp_protect_rtcp_mki(self.ctx, rtcp_hdr, &mut len, 1, mki_index).as_result()? };
        Ok(len as usize)
    }

    pub fn unprotect_rtcp(&mut self, data: &mut [u8]) -> Result<usize, Error> {
        let rtcp_hdr = data.as_mut_ptr() as *mut c_void;
        let mut len: c_int = data.len() as c_int;
        unsafe { srtp_unprotect_rtcp(self.ctx, rtcp_hdr, &mut len).as_result()? };
        Ok(len as usize)
    }

    pub fn unprotect_rtcp_mki(&mut self, data: &mut [u8]) -> Result<usize, Error> {
        let rtcp_hdr = data.as_mut_ptr() as *mut c_void;
        let mut len: c_int = data.len() as c_int;
        unsafe { srtp_unprotect_rtcp_mki(self.ctx, rtcp_hdr, &mut len, 1).as_result()? };
        Ok(len as usize)
    }

    // XXX(RLB) Different name here to better capture the behavior.  A given context can have
    // multiple ciphers in play, and srtp_get_protect_trailer_length takes the max over them (with
    // the given MKI)
    pub fn max_trailer_size(&self, mki_index: Option<usize>) -> Result<usize, Error> {
        let (use_mki, mki_index): (u32, u32) = match mki_index {
            Some(mki_index) => (1, mki_index as u32),
            None => (0, 0),
        };
        let mut length: u32 = 0;
        unsafe {
            srtp_get_protect_trailer_length(self.ctx, use_mki, mki_index, &mut length)
                .as_result()?
        };
        Ok(length as usize)
    }

    pub fn max_trailer_size_rtcp(&self, mki_index: Option<usize>) -> Result<usize, Error> {
        let (use_mki, mki_index): (u32, u32) = match mki_index {
            Some(mki_index) => (1, mki_index as u32),
            None => (0, 0),
        };
        let mut length: u32 = 0;
        unsafe {
            srtp_get_protect_rtcp_trailer_length(self.ctx, use_mki, mki_index, &mut length)
                .as_result()?
        };
        Ok(length as usize)
    }

    pub fn set_roc(&self, ssrc: u32, roc: u32) -> Result<(), Error> {
        unsafe { srtp_set_stream_roc(self.ctx, ssrc, roc).as_result() }
    }

    pub fn get_roc(&self, ssrc: u32) -> Result<u32, Error> {
        let mut roc: u32 = 0;
        unsafe { srtp_get_stream_roc(self.ctx, ssrc, &mut roc).as_result()? };
        Ok(roc)
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // Deallocate the context
        if !self.ctx.is_null() {
            unsafe { srtp_dealloc(self.ctx).as_result().unwrap() };
        }

        // Call srtp_shutdown if done
        let ctr = unsafe { SRTP_REFCOUNT.get_mut() };
        *ctr -= 1;
        if *ctr == 0 {
            unsafe { srtp_shutdown().as_result().unwrap() };
        }
    }
}

// https://datatracker.ietf.org/doc/html/rfc3711#section-3.1
//
//      0                   1                   2                   3
//      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+
//     |V=2|P|X|  CC   |M|     PT      |       sequence number         | |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
//     |                           timestamp                           | |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
//     |           synchronization source (SSRC) identifier            | |
//     +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
//     |            contributing source (CSRC) identifiers             | |
//     |                               ....                            | |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
//     |                   RTP extension (OPTIONAL)                    | |
//   +>+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
//   | |                          payload  ...                         | |
//   | |                               +-------------------------------+ |
//   | |                               | RTP padding   | RTP pad count | |
//   +>+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+
//   | ~                     SRTP MKI (OPTIONAL)                       ~ |
//   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
//   | :                 authentication tag (RECOMMENDED)              : |
//   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
//   |                                                                   |
//   +- Encrypted Portion*                      Authenticated Portion ---+
#[derive(PackedStruct)]
#[packed_struct(bit_numbering = "msb0")]
pub struct RtpHeader {
    #[packed_field(bits = "0..2")]
    pub v: u8,

    #[packed_field(bits = "2")]
    pub p: u8,

    #[packed_field(bits = "3")]
    pub x: u8,

    #[packed_field(bits = "4..8")]
    pub cc: u8,

    #[packed_field(bits = "8")]
    pub m: u8,

    #[packed_field(bits = "9..16")]
    pub pt: u8,

    #[packed_field(endian = "msb")]
    pub seq: u16,

    #[packed_field(endian = "msb")]
    pub ts: u32,

    #[packed_field(endian = "msb")]
    pub ssrc: u32,
}
