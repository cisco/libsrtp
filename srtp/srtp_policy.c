/*
 * srtp_policy.c
 *
 * extensible policy API for libSRTP
 */
/*
 *
 * Copyright (c) 2026
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "srtp_priv.h"

#include <string.h>

#include "alloc.h"

/**
 * @brief srtp_crypto_policy_set_rtp_default() sets a crypto policy
 * structure to the SRTP default policy for RTP protection.
 *
 * @param p is a pointer to the policy structure to be set
 *
 * The function call srtp_crypto_policy_set_rtp_default(&p) sets the
 * srtp_crypto_policy_t at location p to the SRTP default policy for RTP
 * protection, as defined in the specification.  This function is a
 * convenience that helps to avoid dealing directly with the policy
 * data structure.  You are encouraged to initialize policy elements
 * with this function call.  Doing so may allow your code to be
 * forward compatible with later versions of libSRTP that include more
 * elements in the srtp_crypto_policy_t datatype.
 *
 * @return void.
 *
 */
void srtp_crypto_policy_set_rtp_default(srtp_crypto_policy_t *p);

/**
 * @brief srtp_crypto_policy_set_rtcp_default() sets a crypto policy
 * structure to the SRTP default policy for RTCP protection.
 *
 * @param p is a pointer to the policy structure to be set
 *
 * The function call srtp_crypto_policy_set_rtcp_default(&p) sets the
 * srtp_crypto_policy_t at location p to the SRTP default policy for RTCP
 * protection, as defined in the specification.  This function is a
 * convenience that helps to avoid dealing directly with the policy
 * data structure.  You are encouraged to initialize policy elements
 * with this function call.  Doing so may allow your code to be
 * forward compatible with later versions of libSRTP that include more
 * elements in the srtp_crypto_policy_t datatype.
 *
 * @return void.
 *
 */
void srtp_crypto_policy_set_rtcp_default(srtp_crypto_policy_t *p);

/**
 * @brief srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80() sets a crypto
 * policy structure to the SRTP default policy for RTP protection.
 *
 * @param p is a pointer to the policy structure to be set
 *
 * The function srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80() is a
 * synonym for srtp_crypto_policy_set_rtp_default().  It conforms to the
 * naming convention used in RFC 4568 (SDP Security Descriptions for
 * Media Streams).
 *
 * @return void.
 *
 */
#define srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(p)                      \
    srtp_crypto_policy_set_rtp_default(p)

/**
 * @brief srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32() sets a crypto
 * policy structure to a short-authentication tag policy
 *
 * @param p is a pointer to the policy structure to be set
 *
 * The function call srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&p)
 * sets the srtp_crypto_policy_t at location p to use policy
 * AES_CM_128_HMAC_SHA1_32 as defined in RFC 4568.
 * This policy uses AES-128
 * Counter Mode encryption and HMAC-SHA1 authentication, with an
 * authentication tag that is only 32 bits long.  This length is
 * considered adequate only for protecting audio and video media that
 * use a stateless playback function.  See Section 7.5 of RFC 3711
 * (http://www.ietf.org/rfc/rfc3711.txt).
 *
 * This function is a convenience that helps to avoid dealing directly
 * with the policy data structure.  You are encouraged to initialize
 * policy elements with this function call.  Doing so may allow your
 * code to be forward compatible with later versions of libSRTP that
 * include more elements in the srtp_crypto_policy_t datatype.
 *
 * @warning This crypto policy is intended for use in SRTP, but not in
 * SRTCP.  It is recommended that a policy that uses longer
 * authentication tags be used for SRTCP.  See Section 7.5 of RFC 3711
 * (http://www.ietf.org/rfc/rfc3711.txt).
 *
 * @return void.
 *
 */
void srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(srtp_crypto_policy_t *p);

/**
 * @brief srtp_crypto_policy_set_aes_cm_128_null_auth() sets a crypto
 * policy structure to an encryption-only policy
 *
 * @param p is a pointer to the policy structure to be set
 *
 * The function call srtp_crypto_policy_set_aes_cm_128_null_auth(&p) sets
 * the srtp_crypto_policy_t at location p to use the SRTP default cipher
 * (AES-128 Counter Mode), but to use no authentication method.  This
 * policy is NOT RECOMMENDED unless it is unavoidable; see Section 7.5
 * of RFC 3711 (http://www.ietf.org/rfc/rfc3711.txt).
 *
 * This function is a convenience that helps to avoid dealing directly
 * with the policy data structure.  You are encouraged to initialize
 * policy elements with this function call.  Doing so may allow your
 * code to be forward compatible with later versions of libSRTP that
 * include more elements in the srtp_crypto_policy_t datatype.
 *
 * @warning This policy is NOT RECOMMENDED for SRTP unless it is
 * unavoidable, and it is NOT RECOMMENDED at all for SRTCP; see
 * Section 7.5 of RFC 3711 (http://www.ietf.org/rfc/rfc3711.txt).
 *
 * @return void.
 *
 */
void srtp_crypto_policy_set_aes_cm_128_null_auth(srtp_crypto_policy_t *p);

/**
 * @brief srtp_crypto_policy_set_null_cipher_hmac_sha1_80() sets a crypto
 * policy structure to an authentication-only policy
 *
 * @param p is a pointer to the policy structure to be set
 *
 * The function call srtp_crypto_policy_set_null_cipher_hmac_sha1_80(&p)
 * sets the srtp_crypto_policy_t at location p to use HMAC-SHA1 with an 80
 * bit authentication tag to provide message authentication, but to
 * use no encryption.  This policy is NOT RECOMMENDED for SRTP unless
 * there is a requirement to forgo encryption.
 *
 * This function is a convenience that helps to avoid dealing directly
 * with the policy data structure.  You are encouraged to initialize
 * policy elements with this function call.  Doing so may allow your
 * code to be forward compatible with later versions of libSRTP that
 * include more elements in the srtp_crypto_policy_t datatype.
 *
 * @warning This policy is NOT RECOMMENDED for SRTP unless there is a
 * requirement to forgo encryption.
 *
 * @return void.
 *
 */
void srtp_crypto_policy_set_null_cipher_hmac_sha1_80(srtp_crypto_policy_t *p);

/**
 * @brief srtp_crypto_policy_set_null_cipher_hmac_null() sets a crypto
 * policy structure to use no encryption or authentication.
 *
 * @param p is a pointer to the policy structure to be set
 *
 * The function call srtp_crypto_policy_set_null_cipher_hmac_null(&p)
 * sets the srtp_crypto_policy_t at location p to use no encryption and
 * no authentication.  This policy should only be used for testing and
 * troubleshooting.
 *
 * This function is a convenience that helps to avoid dealing directly
 * with the policy data structure.  You are encouraged to initialize
 * policy elements with this function call.  Doing so may allow your
 * code to be forward compatible with later versions of libSRTP that
 * include more elements in the srtp_crypto_policy_t datatype.
 *
 * @warning This policy is NOT RECOMMENDED for SRTP unless there is a
 * requirement to forgo encryption and authentication.
 *
 * @return void.
 *
 */
void srtp_crypto_policy_set_null_cipher_hmac_null(srtp_crypto_policy_t *p);

/**
 * @brief srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80() sets a crypto
 * policy structure to a encryption and authentication policy using AES-256
 * for RTP protection.
 *
 * @param p is a pointer to the policy structure to be set
 *
 * The function call srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(&p)
 * sets the srtp_crypto_policy_t at location p to use policy
 * AES_CM_256_HMAC_SHA1_80 as defined in RFC 6188.  This policy uses AES-256
 * Counter Mode encryption and HMAC-SHA1 authentication, with an 80 bit
 * authentication tag.
 *
 * This function is a convenience that helps to avoid dealing directly
 * with the policy data structure.  You are encouraged to initialize
 * policy elements with this function call.  Doing so may allow your
 * code to be forward compatible with later versions of libSRTP that
 * include more elements in the srtp_crypto_policy_t datatype.
 *
 * @return void.
 *
 */
void srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(srtp_crypto_policy_t *p);

/**
 * @brief srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32() sets a crypto
 * policy structure to a short-authentication tag policy using AES-256
 * encryption.
 *
 * @param p is a pointer to the policy structure to be set
 *
 * The function call srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32(&p)
 * sets the srtp_crypto_policy_t at location p to use policy
 * AES_CM_256_HMAC_SHA1_32 as defined in RFC 6188.  This policy uses AES-256
 * Counter Mode encryption and HMAC-SHA1 authentication, with an
 * authentication tag that is only 32 bits long.  This length is
 * considered adequate only for protecting audio and video media that
 * use a stateless playback function.  See Section 7.5 of RFC 3711
 * (http://www.ietf.org/rfc/rfc3711.txt).
 *
 * This function is a convenience that helps to avoid dealing directly
 * with the policy data structure.  You are encouraged to initialize
 * policy elements with this function call.  Doing so may allow your
 * code to be forward compatible with later versions of libSRTP that
 * include more elements in the srtp_crypto_policy_t datatype.
 *
 * @warning This crypto policy is intended for use in SRTP, but not in
 * SRTCP.  It is recommended that a policy that uses longer
 * authentication tags be used for SRTCP.  See Section 7.5 of RFC 3711
 * (http://www.ietf.org/rfc/rfc3711.txt).
 *
 * @return void.
 *
 */
void srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32(srtp_crypto_policy_t *p);

/**
 * @brief srtp_crypto_policy_set_aes_cm_256_null_auth() sets a crypto
 * policy structure to an encryption-only policy
 *
 * @param p is a pointer to the policy structure to be set
 *
 * The function call srtp_crypto_policy_set_aes_cm_256_null_auth(&p) sets
 * the srtp_crypto_policy_t at location p to use the SRTP default cipher
 * (AES-256 Counter Mode), but to use no authentication method.  This
 * policy is NOT RECOMMENDED unless it is unavoidable; see Section 7.5
 * of RFC 3711 (http://www.ietf.org/rfc/rfc3711.txt).
 *
 * This function is a convenience that helps to avoid dealing directly
 * with the policy data structure.  You are encouraged to initialize
 * policy elements with this function call.  Doing so may allow your
 * code to be forward compatible with later versions of libSRTP that
 * include more elements in the srtp_crypto_policy_t datatype.
 *
 * @warning This policy is NOT RECOMMENDED for SRTP unless it is
 * unavoidable, and it is NOT RECOMMENDED at all for SRTCP; see
 * Section 7.5 of RFC 3711 (http://www.ietf.org/rfc/rfc3711.txt).
 *
 * @return void.
 *
 */
void srtp_crypto_policy_set_aes_cm_256_null_auth(srtp_crypto_policy_t *p);

/**
 * @brief srtp_crypto_policy_set_aes_cm_192_hmac_sha1_80() sets a crypto
 * policy structure to a encryption and authentication policy using AES-192
 * for RTP protection.
 *
 * @param p is a pointer to the policy structure to be set
 *
 * The function call srtp_crypto_policy_set_aes_cm_192_hmac_sha1_80(&p)
 * sets the srtp_crypto_policy_t at location p to use policy
 * AES_CM_192_HMAC_SHA1_80 as defined in RFC 6188.  This policy uses AES-192
 * Counter Mode encryption and HMAC-SHA1 authentication, with an 80 bit
 * authentication tag.
 *
 * This function is a convenience that helps to avoid dealing directly
 * with the policy data structure.  You are encouraged to initialize
 * policy elements with this function call.  Doing so may allow your
 * code to be forward compatible with later versions of libSRTP that
 * include more elements in the srtp_crypto_policy_t datatype.
 *
 * @return void.
 *
 */
void srtp_crypto_policy_set_aes_cm_192_hmac_sha1_80(srtp_crypto_policy_t *p);

/**
 * @brief srtp_crypto_policy_set_aes_cm_192_hmac_sha1_32() sets a crypto
 * policy structure to a short-authentication tag policy using AES-192
 * encryption.
 *
 * @param p is a pointer to the policy structure to be set
 *
 * The function call srtp_crypto_policy_set_aes_cm_192_hmac_sha1_32(&p)
 * sets the srtp_crypto_policy_t at location p to use policy
 * AES_CM_192_HMAC_SHA1_32 as defined in RFC 6188.  This policy uses AES-192
 * Counter Mode encryption and HMAC-SHA1 authentication, with an
 * authentication tag that is only 32 bits long.  This length is
 * considered adequate only for protecting audio and video media that
 * use a stateless playback function.  See Section 7.5 of RFC 3711
 * (http://www.ietf.org/rfc/rfc3711.txt).
 *
 * This function is a convenience that helps to avoid dealing directly
 * with the policy data structure.  You are encouraged to initialize
 * policy elements with this function call.  Doing so may allow your
 * code to be forward compatible with later versions of libSRTP that
 * include more elements in the srtp_crypto_policy_t datatype.
 *
 * @warning This crypto policy is intended for use in SRTP, but not in
 * SRTCP.  It is recommended that a policy that uses longer
 * authentication tags be used for SRTCP.  See Section 7.5 of RFC 3711
 * (http://www.ietf.org/rfc/rfc3711.txt).
 *
 * @return void.
 *
 */
void srtp_crypto_policy_set_aes_cm_192_hmac_sha1_32(srtp_crypto_policy_t *p);

/**
 * @brief srtp_crypto_policy_set_aes_cm_192_null_auth() sets a crypto
 * policy structure to an encryption-only policy
 *
 * @param p is a pointer to the policy structure to be set
 *
 * The function call srtp_crypto_policy_set_aes_cm_192_null_auth(&p) sets
 * the srtp_crypto_policy_t at location p to use the SRTP default cipher
 * (AES-192 Counter Mode), but to use no authentication method.  This
 * policy is NOT RECOMMENDED unless it is unavoidable; see Section 7.5
 * of RFC 3711 (http://www.ietf.org/rfc/rfc3711.txt).
 *
 * This function is a convenience that helps to avoid dealing directly
 * with the policy data structure.  You are encouraged to initialize
 * policy elements with this function call.  Doing so may allow your
 * code to be forward compatible with later versions of libSRTP that
 * include more elements in the srtp_crypto_policy_t datatype.
 *
 * @warning This policy is NOT RECOMMENDED for SRTP unless it is
 * unavoidable, and it is NOT RECOMMENDED at all for SRTCP; see
 * Section 7.5 of RFC 3711 (http://www.ietf.org/rfc/rfc3711.txt).
 *
 * @return void.
 *
 */
void srtp_crypto_policy_set_aes_cm_192_null_auth(srtp_crypto_policy_t *p);

/**
 * @brief srtp_crypto_policy_set_aes_gcm_128_16_auth() sets a crypto
 * policy structure to an AEAD encryption policy.
 *
 * @param p is a pointer to the policy structure to be set
 *
 * The function call srtp_crypto_policy_set_aes_gcm_128_16_auth(&p) sets
 * the srtp_crypto_policy_t at location p to use the SRTP default cipher
 * (AES-128 Galois Counter Mode) with 16 octet auth tag.  This
 * policy applies confidentiality and authentication to both the
 * RTP and RTCP packets.
 *
 * This function is a convenience that helps to avoid dealing directly
 * with the policy data structure.  You are encouraged to initialize
 * policy elements with this function call.  Doing so may allow your
 * code to be forward compatible with later versions of libSRTP that
 * include more elements in the srtp_crypto_policy_t datatype.
 *
 * @return void.
 *
 */
void srtp_crypto_policy_set_aes_gcm_128_16_auth(srtp_crypto_policy_t *p);

/**
 * @brief srtp_crypto_policy_set_aes_gcm_256_16_auth() sets a crypto
 * policy structure to an AEAD encryption policy
 *
 * @param p is a pointer to the policy structure to be set
 *
 * The function call srtp_crypto_policy_set_aes_gcm_256_16_auth(&p) sets
 * the srtp_crypto_policy_t at location p to use the SRTP default cipher
 * (AES-256 Galois Counter Mode) with 16 octet auth tag.  This
 * policy applies confidentiality and authentication to both the
 * RTP and RTCP packets.
 *
 * This function is a convenience that helps to avoid dealing directly
 * with the policy data structure.  You are encouraged to initialize
 * policy elements with this function call.  Doing so may allow your
 * code to be forward compatible with later versions of libSRTP that
 * include more elements in the srtp_crypto_policy_t datatype.
 *
 * @return void.
 *
 */
void srtp_crypto_policy_set_aes_gcm_256_16_auth(srtp_crypto_policy_t *p);

/**
 * @brief srtp_crypto_policy_set_from_profile_for_rtp() sets a crypto policy
 * structure to the appropriate value for RTP based on an srtp_profile_t
 *
 * @param policy is a pointer to the policy structure to be set
 *
 * @param profile is an enumeration for the policy to be set
 *
 * The function call srtp_crypto_policy_set_rtp_default(&policy, profile)
 * sets the srtp_crypto_policy_t at location policy to the policy for RTP
 * protection, as defined by the srtp_profile_t profile.
 *
 * This function is a convenience that helps to avoid dealing directly
 * with the policy data structure.  You are encouraged to initialize
 * policy elements with this function call.  Doing so may allow your
 * code to be forward compatible with later versions of libSRTP that
 * include more elements in the srtp_crypto_policy_t datatype.
 *
 * @return values
 *     - srtp_err_status_ok         no problems were encountered
 *     - srtp_err_status_bad_param  the profile is not supported
 *
 */
srtp_err_status_t srtp_crypto_policy_set_from_profile_for_rtp(
    srtp_crypto_policy_t *policy,
    srtp_profile_t profile);

/**
 * @brief srtp_crypto_policy_set_from_profile_for_rtcp() sets a crypto policy
 * structure to the appropriate value for RTCP based on an srtp_profile_t
 *
 * @param policy is a pointer to the policy structure to be set
 *
 * @param profile is an enumeration for the policy to be set
 *
 * The function call srtp_crypto_policy_set_rtcp_default(&policy, profile)
 * sets the srtp_crypto_policy_t at location policy to the policy for RTCP
 * protection, as defined by the srtp_profile_t profile.
 *
 * This function is a convenience that helps to avoid dealing directly
 * with the policy data structure.  You are encouraged to initialize
 * policy elements with this function call.  Doing so may allow your
 * code to be forward compatible with later versions of libSRTP that
 * include more elements in the srtp_crypto_policy_t datatype.
 *
 * @return values
 *     - srtp_err_status_ok         no problems were encountered
 *     - srtp_err_status_bad_param  the profile is not supported
 *
 */
srtp_err_status_t srtp_crypto_policy_set_from_profile_for_rtcp(
    srtp_crypto_policy_t *policy,
    srtp_profile_t profile);

/*
 * The default policy - provides a convenient way for callers to use
 * the default security policy
 *
 * The default policy is defined in RFC 3711
 * (Section 5. Default and mandatory-to-implement Transforms)
 *
 */

/*
 * NOTE: cipher_key_len is really key len (128 bits) plus salt len
 *  (112 bits)
 */
/* There are hard-coded 16's for base_key_len in the key generation code */

void srtp_crypto_policy_set_rtp_default(srtp_crypto_policy_t *p)
{
    p->cipher_type = SRTP_AES_ICM_128;
    p->cipher_key_len =
        SRTP_AES_ICM_128_KEY_LEN_WSALT; /* default 128 bits per RFC 3711 */
    p->auth_type = SRTP_HMAC_SHA1;
    p->auth_key_len = 20; /* default 160 bits per RFC 3711 */
    p->auth_tag_len = 10; /* default 80 bits per RFC 3711 */
    p->sec_serv = sec_serv_conf_and_auth;
}

void srtp_crypto_policy_set_rtcp_default(srtp_crypto_policy_t *p)
{
    p->cipher_type = SRTP_AES_ICM_128;
    p->cipher_key_len =
        SRTP_AES_ICM_128_KEY_LEN_WSALT; /* default 128 bits per RFC 3711 */
    p->auth_type = SRTP_HMAC_SHA1;
    p->auth_key_len = 20; /* default 160 bits per RFC 3711 */
    p->auth_tag_len = 10; /* default 80 bits per RFC 3711 */
    p->sec_serv = sec_serv_conf_and_auth;
}

void srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(srtp_crypto_policy_t *p)
{
    /*
     * corresponds to RFC 4568
     *
     * note that this crypto policy is intended for SRTP, but not SRTCP
     */

    p->cipher_type = SRTP_AES_ICM_128;
    p->cipher_key_len =
        SRTP_AES_ICM_128_KEY_LEN_WSALT; /* 128 bit key, 112 bit salt */
    p->auth_type = SRTP_HMAC_SHA1;
    p->auth_key_len = 20; /* 160 bit key               */
    p->auth_tag_len = 4;  /* 32 bit tag                */
    p->sec_serv = sec_serv_conf_and_auth;
}

void srtp_crypto_policy_set_aes_cm_128_null_auth(srtp_crypto_policy_t *p)
{
    /*
     * corresponds to RFC 4568
     *
     * note that this crypto policy is intended for SRTP, but not SRTCP
     */

    p->cipher_type = SRTP_AES_ICM_128;
    p->cipher_key_len =
        SRTP_AES_ICM_128_KEY_LEN_WSALT; /* 128 bit key, 112 bit salt */
    p->auth_type = SRTP_NULL_AUTH;
    p->auth_key_len = 0;
    p->auth_tag_len = 0;
    p->sec_serv = sec_serv_conf;
}

void srtp_crypto_policy_set_null_cipher_hmac_sha1_80(srtp_crypto_policy_t *p)
{
    /*
     * corresponds to RFC 4568
     */

    p->cipher_type = SRTP_NULL_CIPHER;
    p->cipher_key_len =
        SRTP_AES_ICM_128_KEY_LEN_WSALT; /* 128 bit key, 112 bit salt */
    p->auth_type = SRTP_HMAC_SHA1;
    p->auth_key_len = 20;
    p->auth_tag_len = 10;
    p->sec_serv = sec_serv_auth;
}

void srtp_crypto_policy_set_null_cipher_hmac_null(srtp_crypto_policy_t *p)
{
    /*
     * Should only be used for testing
     */

    p->cipher_type = SRTP_NULL_CIPHER;
    p->cipher_key_len = 0;
    p->auth_type = SRTP_NULL_AUTH;
    p->auth_key_len = 0;
    p->auth_tag_len = 0;
    p->sec_serv = sec_serv_none;
}

void srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(srtp_crypto_policy_t *p)
{
    /*
     * corresponds to RFC 6188
     */

    p->cipher_type = SRTP_AES_ICM_256;
    p->cipher_key_len = SRTP_AES_ICM_256_KEY_LEN_WSALT;
    p->auth_type = SRTP_HMAC_SHA1;
    p->auth_key_len = 20; /* default 160 bits per RFC 3711 */
    p->auth_tag_len = 10; /* default 80 bits per RFC 3711 */
    p->sec_serv = sec_serv_conf_and_auth;
}

void srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32(srtp_crypto_policy_t *p)
{
    /*
     * corresponds to RFC 6188
     *
     * note that this crypto policy is intended for SRTP, but not SRTCP
     */

    p->cipher_type = SRTP_AES_ICM_256;
    p->cipher_key_len = SRTP_AES_ICM_256_KEY_LEN_WSALT;
    p->auth_type = SRTP_HMAC_SHA1;
    p->auth_key_len = 20; /* default 160 bits per RFC 3711 */
    p->auth_tag_len = 4;  /* default 80 bits per RFC 3711 */
    p->sec_serv = sec_serv_conf_and_auth;
}

/*
 * AES-256 with no authentication.
 */
void srtp_crypto_policy_set_aes_cm_256_null_auth(srtp_crypto_policy_t *p)
{
    p->cipher_type = SRTP_AES_ICM_256;
    p->cipher_key_len = SRTP_AES_ICM_256_KEY_LEN_WSALT;
    p->auth_type = SRTP_NULL_AUTH;
    p->auth_key_len = 0;
    p->auth_tag_len = 0;
    p->sec_serv = sec_serv_conf;
}

void srtp_crypto_policy_set_aes_cm_192_hmac_sha1_80(srtp_crypto_policy_t *p)
{
    /*
     * corresponds to RFC 6188
     */

    p->cipher_type = SRTP_AES_ICM_192;
    p->cipher_key_len = SRTP_AES_ICM_192_KEY_LEN_WSALT;
    p->auth_type = SRTP_HMAC_SHA1;
    p->auth_key_len = 20; /* default 160 bits per RFC 3711 */
    p->auth_tag_len = 10; /* default 80 bits per RFC 3711 */
    p->sec_serv = sec_serv_conf_and_auth;
}

void srtp_crypto_policy_set_aes_cm_192_hmac_sha1_32(srtp_crypto_policy_t *p)
{
    /*
     * corresponds to RFC 6188
     *
     * note that this crypto policy is intended for SRTP, but not SRTCP
     */

    p->cipher_type = SRTP_AES_ICM_192;
    p->cipher_key_len = SRTP_AES_ICM_192_KEY_LEN_WSALT;
    p->auth_type = SRTP_HMAC_SHA1;
    p->auth_key_len = 20; /* default 160 bits per RFC 3711 */
    p->auth_tag_len = 4;  /* default 80 bits per RFC 3711 */
    p->sec_serv = sec_serv_conf_and_auth;
}

/*
 * AES-192 with no authentication.
 */
void srtp_crypto_policy_set_aes_cm_192_null_auth(srtp_crypto_policy_t *p)
{
    p->cipher_type = SRTP_AES_ICM_192;
    p->cipher_key_len = SRTP_AES_ICM_192_KEY_LEN_WSALT;
    p->auth_type = SRTP_NULL_AUTH;
    p->auth_key_len = 0;
    p->auth_tag_len = 0;
    p->sec_serv = sec_serv_conf;
}

/*
 * AES-128 GCM mode with 16 octet auth tag.
 */
void srtp_crypto_policy_set_aes_gcm_128_16_auth(srtp_crypto_policy_t *p)
{
    p->cipher_type = SRTP_AES_GCM_128;
    p->cipher_key_len = SRTP_AES_GCM_128_KEY_LEN_WSALT;
    p->auth_type = SRTP_NULL_AUTH; /* GCM handles the auth for us */
    p->auth_key_len = 0;
    p->auth_tag_len = 16; /* 16 octet tag length */
    p->sec_serv = sec_serv_conf_and_auth;
}

/*
 * AES-256 GCM mode with 16 octet auth tag.
 */
void srtp_crypto_policy_set_aes_gcm_256_16_auth(srtp_crypto_policy_t *p)
{
    p->cipher_type = SRTP_AES_GCM_256;
    p->cipher_key_len = SRTP_AES_GCM_256_KEY_LEN_WSALT;
    p->auth_type = SRTP_NULL_AUTH; /* GCM handles the auth for us */
    p->auth_key_len = 0;
    p->auth_tag_len = 16; /* 16 octet tag length */
    p->sec_serv = sec_serv_conf_and_auth;
}

srtp_err_status_t srtp_crypto_policy_set_from_profile_for_rtp(
    srtp_crypto_policy_t *policy,
    srtp_profile_t profile)
{
    /* set SRTP policy from the SRTP profile in the key set */
    switch (profile) {
    case srtp_profile_reserved:
        return srtp_err_status_bad_param;
    case srtp_profile_null_null:
        srtp_crypto_policy_set_null_cipher_hmac_null(policy);
        return srtp_err_status_ok;
    case srtp_profile_aes128_cm_sha1_80:
        srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(policy);
        return srtp_err_status_ok;
    case srtp_profile_aes128_cm_sha1_32:
        srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(policy);
        return srtp_err_status_ok;
    case srtp_profile_aes192_cm_sha1_80:
        srtp_crypto_policy_set_aes_cm_192_hmac_sha1_80(policy);
        return srtp_err_status_ok;
    case srtp_profile_aes192_cm_sha1_32:
        srtp_crypto_policy_set_aes_cm_192_hmac_sha1_32(policy);
        return srtp_err_status_ok;
    case srtp_profile_aes256_cm_sha1_80:
        srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(policy);
        return srtp_err_status_ok;
    case srtp_profile_aes256_cm_sha1_32:
        srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32(policy);
        return srtp_err_status_ok;
    case srtp_profile_null_sha1_80:
        srtp_crypto_policy_set_null_cipher_hmac_sha1_80(policy);
        return srtp_err_status_ok;
#ifdef GCM
    case srtp_profile_aead_aes_128_gcm:
        srtp_crypto_policy_set_aes_gcm_128_16_auth(policy);
        return srtp_err_status_ok;
    case srtp_profile_aead_aes_256_gcm:
        srtp_crypto_policy_set_aes_gcm_256_16_auth(policy);
        return srtp_err_status_ok;
#else
    case srtp_profile_aead_aes_128_gcm:
        return srtp_err_status_bad_param;
    case srtp_profile_aead_aes_256_gcm:
        return srtp_err_status_bad_param;
#endif
    case srtp_profile_null_sha1_32:
        srtp_crypto_policy_set_null_cipher_hmac_sha1_80(policy);
        policy->auth_tag_len = 4;
        return srtp_err_status_ok;
    }

    return srtp_err_status_bad_param;
}

srtp_err_status_t srtp_crypto_policy_set_from_profile_for_rtcp(
    srtp_crypto_policy_t *policy,
    srtp_profile_t profile)
{
    /* set SRTP policy from the SRTP profile in the key set */
    switch (profile) {
    case srtp_profile_reserved:
        return srtp_err_status_bad_param;
    case srtp_profile_null_null:
        srtp_crypto_policy_set_null_cipher_hmac_null(policy);
        return srtp_err_status_ok;
    case srtp_profile_aes128_cm_sha1_80:
        srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(policy);
        return srtp_err_status_ok;
    case srtp_profile_aes128_cm_sha1_32:
        /* We do not honor the 32-bit auth tag request since
         * this is not compliant with RFC 3711 */
        srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(policy);
        return srtp_err_status_ok;
    case srtp_profile_aes192_cm_sha1_80:
        srtp_crypto_policy_set_aes_cm_192_hmac_sha1_80(policy);
        return srtp_err_status_ok;
    case srtp_profile_aes192_cm_sha1_32:
        /* We do not honor the 32-bit auth tag request since
         * this is not compliant with RFC 3711 */
        srtp_crypto_policy_set_aes_cm_192_hmac_sha1_80(policy);
        return srtp_err_status_ok;
    case srtp_profile_aes256_cm_sha1_80:
        srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(policy);
        return srtp_err_status_ok;
    case srtp_profile_aes256_cm_sha1_32:
        /* We do not honor the 32-bit auth tag request since
         * this is not compliant with RFC 6188 */
        srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(policy);
        return srtp_err_status_ok;
    case srtp_profile_null_sha1_80:
        srtp_crypto_policy_set_null_cipher_hmac_sha1_80(policy);
        return srtp_err_status_ok;
#ifdef GCM
    case srtp_profile_aead_aes_128_gcm:
        srtp_crypto_policy_set_aes_gcm_128_16_auth(policy);
        return srtp_err_status_ok;
    case srtp_profile_aead_aes_256_gcm:
        srtp_crypto_policy_set_aes_gcm_256_16_auth(policy);
        return srtp_err_status_ok;
#else
    case srtp_profile_aead_aes_128_gcm:
        return srtp_err_status_bad_param;
    case srtp_profile_aead_aes_256_gcm:
        return srtp_err_status_bad_param;
#endif
    case srtp_profile_null_sha1_32:
        /* We do not honor the 32-bit auth tag request since
         * this is not compliant with RFC 3711 */
        srtp_crypto_policy_set_null_cipher_hmac_sha1_80(policy);
        return srtp_err_status_ok;
    }

    return srtp_err_status_bad_param;
}

srtp_err_status_t srtp_policy_create(srtp_policy_t *policy)
{
    srtp_policy_t p;

    if (policy == NULL) {
        return srtp_err_status_bad_param;
    }

    p = (srtp_policy_t)srtp_crypto_alloc(sizeof(*p));
    if (p == NULL) {
        *policy = NULL;
        return srtp_err_status_alloc_fail;
    }

    *policy = p;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_policy_clone(srtp_policy_t policy,
                                    srtp_policy_t *cloned_policy)
{
    if (policy == NULL || cloned_policy == NULL) {
        return srtp_err_status_bad_param;
    }

    srtp_policy_t p;
    srtp_err_status_t status = srtp_policy_create(&p);
    if (status != srtp_err_status_ok) {
        return status;
    }

    memcpy(p, policy, sizeof(*p));

    *cloned_policy = p;

    return srtp_err_status_ok;
}

void srtp_policy_destroy(srtp_policy_t policy)
{
    if (policy == NULL) {
        return;
    }

    octet_string_set_to_zero(policy->master_keys, sizeof(policy->master_keys));
    srtp_crypto_free(policy);
}

srtp_err_status_t srtp_policy_validate(srtp_policy_t policy)
{
    if (policy == NULL) {
        return srtp_err_status_bad_param;
    }

    if (policy->profile == srtp_profile_reserved) {
        return srtp_err_status_bad_param;
    }

    if (policy->ssrc.type == ssrc_undefined) {
        return srtp_err_status_bad_param;
    }

    bool null_cipher_null_auth = srtp_policy_is_null_cipher_null_auth(policy);

    if (null_cipher_null_auth) {
        if (policy->num_master_keys != 0 || policy->use_mki ||
            policy->mki_size != 0) {
            return srtp_err_status_bad_param;
        }
    } else if (policy->num_master_keys == 0) {
        return srtp_err_status_bad_param;
    }

    if (policy->num_master_keys > SRTP_MAX_NUM_MASTER_KEYS) {
        return srtp_err_status_bad_param;
    }

    if (policy->use_mki) {
        if (policy->mki_size == 0 || policy->mki_size > SRTP_MAX_MKI_LEN) {
            return srtp_err_status_bad_param;
        }
    } else if (policy->mki_size != 0) {
        return srtp_err_status_bad_param;
    }

    if (!policy->use_mki && policy->num_master_keys > 1) {
        return srtp_err_status_bad_param;
    }

    size_t expected_key_len =
        srtp_profile_get_master_key_length(policy->profile);
    size_t expected_salt_len =
        srtp_profile_get_master_salt_length(policy->profile);

    for (size_t i = 0; i < policy->num_master_keys; i++) {
        if (policy->master_keys[i].key_len == 0) {
            return srtp_err_status_bad_param;
        }
        if (policy->master_keys[i].key_len != expected_key_len ||
            policy->master_keys[i].salt_len != expected_salt_len) {
            return srtp_err_status_bad_param;
        }
        if (policy->use_mki &&
            policy->mki_size != policy->master_keys[i].mki_id_len) {
            return srtp_err_status_bad_param;
        }
        if (!policy->use_mki && policy->master_keys[i].mki_id_len != 0) {
            return srtp_err_status_bad_param;
        }
    }

    if (!srtp_policy_is_valid_window_size(policy->window_size)) {
        return srtp_err_status_bad_param;
    }

    // Not a valid combination
    if (policy->enc_xtn_hdr_count > 0 && policy->use_cryptex) {
        return srtp_err_status_bad_param;
    }

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_policy_set_ssrc(srtp_policy_t policy, srtp_ssrc_t ssrc)
{
    if (policy == NULL) {
        return srtp_err_status_bad_param;
    }

    if (ssrc.type != ssrc_any_inbound && ssrc.type != ssrc_any_outbound &&
        ssrc.type != ssrc_specific) {
        return srtp_err_status_bad_param;
    }

    policy->ssrc = ssrc;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_policy_set_profile(srtp_policy_t policy,
                                          srtp_profile_t profile)
{
    if (policy == NULL) {
        return srtp_err_status_bad_param;
    }

    srtp_err_status_t status;
    status = srtp_crypto_policy_set_from_profile_for_rtp(&policy->rtp, profile);
    if (status != srtp_err_status_ok) {
        return status;
    }
    status =
        srtp_crypto_policy_set_from_profile_for_rtcp(&policy->rtcp, profile);
    if (status != srtp_err_status_ok) {
        return status;
    }

    policy->profile = profile;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_policy_get_profile(srtp_policy_t policy,
                                          srtp_profile_t *profile)
{
    if (policy == NULL || profile == NULL) {
        return srtp_err_status_bad_param;
    }

    *profile = policy->profile;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_policy_set_sec_serv(srtp_policy_t policy,
                                           srtp_sec_serv_t rtp_sec_serv,
                                           srtp_sec_serv_t rtcp_sec_serv)
{
    if (policy == NULL) {
        return srtp_err_status_bad_param;
    }

    if (policy->profile == srtp_profile_reserved) {
        return srtp_err_status_bad_param;
    }

    policy->rtp.sec_serv = rtp_sec_serv;
    policy->rtcp.sec_serv = rtcp_sec_serv;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_policy_use_mki(srtp_policy_t policy, size_t mki_len)
{
    if (policy == NULL) {
        return srtp_err_status_bad_param;
    }

    if (mki_len > SRTP_MAX_MKI_LEN) {
        return srtp_err_status_bad_param;
    }

    policy->use_mki = mki_len != 0;
    policy->mki_size = mki_len;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_policy_get_mki_length(srtp_policy_t policy,
                                             size_t *mki_len)
{
    if (policy == NULL || mki_len == NULL) {
        return srtp_err_status_bad_param;
    }

    *mki_len = policy->mki_size;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_policy_set_rcc_mode_tx_rate(srtp_policy_t policy, srtp_rcc_mode_t rcc_mode, uint16_t roc_tx_rate)
{
    if (policy == NULL) {
        return srtp_err_status_bad_param;
    }
    
    policy->rcc_mode = rcc_mode;
    policy->roc_tx_rate = roc_tx_rate;
    
    return srtp_err_status_ok;
}

srtp_err_status_t srtp_policy_add_key(srtp_policy_t policy,
                                      const uint8_t *key,
                                      size_t key_len,
                                      const uint8_t *salt,
                                      size_t salt_len,
                                      const uint8_t *mki,
                                      size_t mki_len)
{
    if (policy == NULL) {
        return srtp_err_status_bad_param;
    }
    if (key == NULL || salt == NULL) {
        return srtp_err_status_bad_param;
    }
    if (mki_len > 0 && mki == NULL) {
        return srtp_err_status_bad_param;
    }

    if (policy->use_mki) {
        if (mki_len != policy->mki_size) {
            return srtp_err_status_bad_param;
        }
    } else {
        if (mki_len != 0) {
            return srtp_err_status_bad_param;
        }
        if (policy->num_master_keys > 0) {
            return srtp_err_status_bad_param;
        }
    }

    if (key_len + salt_len > SRTP_MAX_KEY_LEN) {
        return srtp_err_status_bad_param;
    }

    if (mki_len > SRTP_MAX_MKI_LEN) {
        return srtp_err_status_bad_param;
    }

    if (policy->num_master_keys >= SRTP_MAX_NUM_MASTER_KEYS) {
        return srtp_err_status_bad_param;
    }

    size_t key_index = policy->num_master_keys;
    memcpy(policy->master_keys[key_index].key, key, key_len);
    policy->master_keys[key_index].key_len = key_len;
    memcpy(policy->master_keys[key_index].key + key_len, salt, salt_len);
    policy->master_keys[key_index].salt_len = salt_len;
    if (mki_len > 0) {
        memcpy(policy->master_keys[key_index].mki_id, mki, mki_len);
    }
    policy->master_keys[key_index].mki_id_len = mki_len;
    policy->num_master_keys++;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_policy_remove_keys(srtp_policy_t policy)
{
    if (policy == NULL) {
        return srtp_err_status_bad_param;
    }

    octet_string_set_to_zero(policy->master_keys, sizeof(policy->master_keys));
    policy->num_master_keys = 0;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_policy_set_window_size(srtp_policy_t policy,
                                              size_t window_size)
{
    if (policy == NULL) {
        return srtp_err_status_bad_param;
    }

    if (!srtp_policy_is_valid_window_size(window_size)) {
        return srtp_err_status_bad_param;
    }

    policy->window_size = window_size;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_policy_set_allow_repeat_tx(srtp_policy_t policy,
                                                  bool allow)
{
    if (policy == NULL) {
        return srtp_err_status_bad_param;
    }

    policy->allow_repeat_tx = allow;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_policy_set_cryptex(srtp_policy_t policy,
                                          bool use_cryptex)
{
    if (policy == NULL) {
        return srtp_err_status_bad_param;
    }

    policy->use_cryptex = use_cryptex;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_policy_add_enc_hdr_xtnd_id(srtp_policy_t policy,
                                                  uint8_t hdr_xtnd_id)
{
    if (policy == NULL) {
        return srtp_err_status_bad_param;
    }

    if (policy->enc_xtn_hdr_count >= SRTP_MAX_NUM_ENC_HDR_XTND_IDS) {
        return srtp_err_status_bad_param;
    }

    for (size_t i = 0; i < policy->enc_xtn_hdr_count; i++) {
        if (policy->enc_xtn_hdr[i] == hdr_xtnd_id) {
            return srtp_err_status_bad_param;
        }
    }

    policy->enc_xtn_hdr[policy->enc_xtn_hdr_count] = hdr_xtnd_id;
    policy->enc_xtn_hdr_count++;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_policy_remove_enc_hdr_xtnd_ids(srtp_policy_t policy)
{
    if (policy == NULL) {
        return srtp_err_status_bad_param;
    }

    octet_string_set_to_zero(policy->enc_xtn_hdr, sizeof(policy->enc_xtn_hdr));
    policy->enc_xtn_hdr_count = 0;

    return srtp_err_status_ok;
}
