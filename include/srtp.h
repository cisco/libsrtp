/*
 * srtp.h
 *
 * interface to libsrtp
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 */
/*
 *
 * Copyright (c) 2001-2017, Cisco Systems, Inc.
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
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
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

#ifndef SRTP_SRTP_H
#define SRTP_SRTP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup SRTP Secure RTP
 *
 * @brief libSRTP provides functions for protecting RTP and RTCP.  See
 * Section @ref Overview for an introduction to the use of the library.
 *
 * @{
 */

/*
 * SRTP_MASTER_KEY_LEN is the nominal master key length supported by libSRTP
 */

#define SRTP_MASTER_KEY_LEN 30

/*
 * SRTP_MAX_KEY_LEN is the maximum key length supported by libSRTP
 */
#define SRTP_MAX_KEY_LEN 64

/*
 * SRTP_MAX_TAG_LEN is the maximum tag length supported by libSRTP
 */

#define SRTP_MAX_TAG_LEN 16

/**
 * SRTP_MAX_MKI_LEN is the maximum size the MKI could be which is
 * 128 bytes
 */
#define SRTP_MAX_MKI_LEN 128

/**
 * SRTP_MAX_TRAILER_LEN is the maximum length of the SRTP trailer
 * (authentication tag and MKI) supported by libSRTP.  This value is
 * the maximum number of octets that will be added to an RTP packet by
 * srtp_protect().
 *
 * @brief the maximum number of octets added by srtp_protect().
 */
#define SRTP_MAX_TRAILER_LEN (SRTP_MAX_TAG_LEN + SRTP_MAX_MKI_LEN)

/**
 * SRTP_SRCTP_INDEX_LEN is the size the SRTCP index which is
 * 4 bytes
 */
#define SRTP_SRCTP_INDEX_LEN 4

/**
 * SRTP_MAX_SRTCP_TRAILER_LEN is the maximum length of the SRTCP trailer
 * (index, authentication tag and MKI) supported by libSRTP.  This value is
 * the maximum number of octets that will be added to an RTCP packet by
 * srtp_protect_rtcp().
 *
 * @brief the maximum number of octets added by srtp_protect().
 */
#define SRTP_MAX_SRTCP_TRAILER_LEN                                             \
    (SRTP_SRCTP_INDEX_LEN + SRTP_MAX_TAG_LEN + SRTP_MAX_MKI_LEN)

/**
 * SRTP_MAX_NUM_MASTER_KEYS is the maximum number of Master keys for
 * MKI supported by libSRTP.
 *
 */
#define SRTP_MAX_NUM_MASTER_KEYS 16

#define SRTP_MAX_NUM_ENC_HDR_XTND_IDS 16

#define SRTP_SALT_LEN 14

/*
 * SRTP_AEAD_SALT_LEN is the length of the SALT values used with
 * GCM mode.  GCM mode requires an IV.  The SALT value is used
 * as part of the IV formation logic applied to each RTP packet.
 */
#define SRTP_AEAD_SALT_LEN 12

#define SRTP_AES_128_KEY_LEN 16
#define SRTP_AES_192_KEY_LEN 24
#define SRTP_AES_256_KEY_LEN 32

#define SRTP_AES_ICM_128_KEY_LEN_WSALT (SRTP_SALT_LEN + SRTP_AES_128_KEY_LEN)
#define SRTP_AES_ICM_192_KEY_LEN_WSALT (SRTP_SALT_LEN + SRTP_AES_192_KEY_LEN)
#define SRTP_AES_ICM_256_KEY_LEN_WSALT (SRTP_SALT_LEN + SRTP_AES_256_KEY_LEN)

#define SRTP_AES_GCM_128_KEY_LEN_WSALT                                         \
    (SRTP_AEAD_SALT_LEN + SRTP_AES_128_KEY_LEN)
#define SRTP_AES_GCM_192_KEY_LEN_WSALT                                         \
    (SRTP_AEAD_SALT_LEN + SRTP_AES_192_KEY_LEN)
#define SRTP_AES_GCM_256_KEY_LEN_WSALT                                         \
    (SRTP_AEAD_SALT_LEN + SRTP_AES_256_KEY_LEN)

/**
 *  @brief A srtp_cipher_type_id_t is an identifier for a particular cipher
 *  type.
 *
 *  A srtp_cipher_type_id_t is an integer that represents a particular
 *  cipher type, e.g. the Advanced Encryption Standard (AES).  A
 *  SRTP_NULL_CIPHER is available; this cipher leaves the data unchanged,
 *  and can be selected to indicate that no encryption is to take
 *  place.
 *
 *  @ingroup Ciphers
 */
typedef uint32_t srtp_cipher_type_id_t;

/**
 *  @brief An srtp_auth_type_id_t is an identifier for a particular
 * authentication
 *   function.
 *
 *  An srtp_auth_type_id_t is an integer that represents a particular
 *  authentication function type, e.g. HMAC-SHA1.  A SRTP_NULL_AUTH is
 *  available; this authentication function performs no computation,
 *  and can be selected to indicate that no authentication is to take
 *  place.
 *
 *  @ingroup Authentication
 */
typedef uint32_t srtp_auth_type_id_t;

/**
 * @brief srtp_err_status_t defines error codes.
 *
 * The enumeration srtp_err_status_t defines error codes.  Note that the
 * value of srtp_err_status_ok is equal to zero, which can simplify error
 * checking somewhat.
 *
 */
typedef enum {
    srtp_err_status_ok = 0,             /**< nothing to report               */
    srtp_err_status_fail = 1,           /**< unspecified failure             */
    srtp_err_status_bad_param = 2,      /**< unsupported parameter           */
    srtp_err_status_alloc_fail = 3,     /**< couldn't allocate memory        */
    srtp_err_status_dealloc_fail = 4,   /**< couldn't deallocate properly    */
    srtp_err_status_init_fail = 5,      /**< couldn't initialize             */
    srtp_err_status_terminus = 6,       /**< can't process as much data as   */
                                        /**< requested                       */
    srtp_err_status_auth_fail = 7,      /**< authentication failure          */
    srtp_err_status_cipher_fail = 8,    /**< cipher failure                  */
    srtp_err_status_replay_fail = 9,    /**< replay check failed (bad index) */
    srtp_err_status_replay_old = 10,    /**< replay check failed (index too  */
                                        /**< old)                            */
    srtp_err_status_algo_fail = 11,     /**< algorithm failed test routine   */
    srtp_err_status_no_such_op = 12,    /**< unsupported operation           */
    srtp_err_status_no_ctx = 13,        /**< no appropriate context found    */
    srtp_err_status_cant_check = 14,    /**< unable to perform desired       */
                                        /**< validation                      */
    srtp_err_status_key_expired = 15,   /**< can't use key any more          */
    srtp_err_status_socket_err = 16,    /**< error in use of socket          */
    srtp_err_status_signal_err = 17,    /**< error in use POSIX signals      */
    srtp_err_status_nonce_bad = 18,     /**< nonce check failed              */
    srtp_err_status_read_fail = 19,     /**< couldn't read data              */
    srtp_err_status_write_fail = 20,    /**< couldn't write data             */
    srtp_err_status_parse_err = 21,     /**< error parsing data              */
    srtp_err_status_encode_err = 22,    /**< error encoding data             */
    srtp_err_status_semaphore_err = 23, /**< error while using semaphores    */
    srtp_err_status_pfkey_err = 24,     /**< error while using pfkey         */
    srtp_err_status_bad_mki = 25,       /**< error MKI present in packet is  */
                                        /**< invalid                         */
    srtp_err_status_pkt_idx_old = 26,   /**< packet index is too old to      */
                                        /**< consider                        */
    srtp_err_status_pkt_idx_adv = 27,   /**< packet index advanced, reset    */
                                        /**< needed                          */
    srtp_err_status_buffer_small = 28,  /**< out buffer is too small         */
    srtp_err_status_cryptex_err = 29,   /**< unsupported cryptex operation   */
    srtp_err_status_direction_mismatch =
        30, /**< operation does not match stream direction */
} srtp_err_status_t;

typedef struct srtp_ctx_t_ srtp_ctx_t;

/**
 * @brief srtp_sec_serv_t describes a set of security services.
 *
 * A srtp_sec_serv_t enumeration is used to describe the particular
 * security services that will be applied by a particular crypto
 * policy (or other mechanism).
 */
typedef enum {
    sec_serv_none = 0,         /**< no services                        */
    sec_serv_conf = 1,         /**< confidentiality                    */
    sec_serv_auth = 2,         /**< authentication                     */
    sec_serv_conf_and_auth = 3 /**< confidentiality and authentication */
} srtp_sec_serv_t;

/**
 * @brief srtp_ssrc_type_t describes the type of an SSRC.
 *
 * An srtp_ssrc_type_t enumeration is used to indicate a type of SSRC.  See
 * @ref srtp_policy_t for more information.
 */
typedef enum {
    ssrc_undefined = 0,   /**< Indicates an undefined SSRC type.    */
    ssrc_specific = 1,    /**< Indicates a specific SSRC value      */
    ssrc_any_inbound = 2, /**< Indicates any inbound SSRC value     */
                          /**< (i.e. a value that is used in the    */
                          /**< function srtp_unprotect())           */
    ssrc_any_outbound = 3 /**< Indicates any outbound SSRC value    */
                          /**< (i.e. a value that is used in the    */
                          /**< function srtp_protect())             */
} srtp_ssrc_type_t;

/**
 * @brief An srtp_ssrc_t represents a particular SSRC value, or a `wildcard'
 * SSRC.
 *
 * An srtp_ssrc_t represents a particular SSRC value (if its type is
 * ssrc_specific), or a wildcard SSRC value that will match all
 * outbound SSRCs (if its type is ssrc_any_outbound) or all inbound
 * SSRCs (if its type is ssrc_any_inbound).
 */
typedef struct {
    srtp_ssrc_type_t type; /**< The type of this particular SSRC */
    uint32_t value;        /**< The value of this SSRC, if it is not a */
                           /**< wildcard */
} srtp_ssrc_t;

/*
 * @brief identifies a particular SRTP profile
 *
 * An srtp_profile_t enumeration is used to identify a particular SRTP
 * profile (that is, a set of algorithms and parameters).
 */
typedef enum {
    srtp_profile_reserved = 0,
    srtp_profile_null_null = 1,
    srtp_profile_aes128_cm_sha1_80 = 2,
    srtp_profile_aes128_cm_sha1_32 = 3,
    srtp_profile_aes192_cm_sha1_80 = 4,
    srtp_profile_aes192_cm_sha1_32 = 5,
    srtp_profile_aes256_cm_sha1_80 = 6,
    srtp_profile_aes256_cm_sha1_32 = 7,
    srtp_profile_null_sha1_80 = 8,
    srtp_profile_null_sha1_32 = 9,
    srtp_profile_aead_aes_128_gcm = 10,
    srtp_profile_aead_aes_256_gcm = 11
} srtp_profile_t;

typedef struct srtp_policy_ctx_t_ srtp_policy_ctx_t;
typedef srtp_policy_ctx_t *srtp_policy_t;

/**
 * @brief Allocate a new policy handle.
 *
 * A policy handle describes one SRTP stream policy. Configure it with
 * srtp_policy_set_ssrc(), srtp_policy_set_profile(), optional MKI and
 * feature setters, and srtp_policy_add_key() before passing it to
 * srtp_create() or srtp_stream_add().
 *
 * @param policy output pointer that receives the allocated policy.
 *
 * @return
 *    - srtp_err_status_ok if allocation succeeded.
 *    - srtp_err_status_bad_param if policy is NULL.
 *    - srtp_err_status_alloc_fail if allocation failed.
 */
srtp_err_status_t srtp_policy_create(srtp_policy_t *policy);

/**
 * @brief Clone an existing policy handle.
 *
 * @param policy source policy to clone.
 * @param cloned_policy output pointer that receives the cloned policy.
 *
 * This copies all fields of the source policy, including configured keys. The
 * cloned policy can be modified independently from the source policy.
 *
 * @return
 *    - srtp_err_status_ok if cloning succeeded.
 *    - srtp_err_status_bad_param if either argument is NULL.
 *    - srtp_err_status_alloc_fail if allocation failed.
 */
srtp_err_status_t srtp_policy_clone(srtp_policy_t policy,
                                    srtp_policy_t *cloned_policy);

/**
 * @brief Set the policy SSRC selector.
 *
 * @param policy policy handle.
 * @param ssrc SSRC selector to apply.
 *
 * Valid selectors are ssrc_specific, ssrc_any_inbound, and ssrc_any_outbound.
 *
 * @return
 *    - srtp_err_status_ok if the SSRC selector was accepted.
 *    - srtp_err_status_bad_param if policy is NULL or ssrc.type is invalid.
 */
srtp_err_status_t srtp_policy_set_ssrc(srtp_policy_t policy, srtp_ssrc_t ssrc);

/**
 * @brief Set the SRTP profile and initialize RTP/RTCP crypto settings.
 *
 * @param policy policy handle.
 * @param profile profile to apply.
 *
 * Call this before srtp_policy_set_sec_serv() and before validation. Keys
 * added with srtp_policy_add_key() must match this profile's master key and
 * salt lengths when the policy is validated.
 *
 * @return
 *    - srtp_err_status_ok if the profile was applied.
 *    - srtp_err_status_bad_param if policy is NULL or profile is invalid.
 *    - [other] if profile-to-crypto mapping failed.
 */
srtp_err_status_t srtp_policy_set_profile(srtp_policy_t policy,
                                          srtp_profile_t profile);

/**
 * @brief Get the profile currently set on a policy.
 *
 * @param policy policy handle.
 * @param profile output pointer that receives the configured profile.
 *
 * @return
 *    - srtp_err_status_ok if the profile was returned.
 *    - srtp_err_status_bad_param if any argument is NULL.
 */
srtp_err_status_t srtp_policy_get_profile(srtp_policy_t policy,
                                          srtp_profile_t *profile);

/**
 * @brief Override security-service flags for RTP and RTCP.
 *
 * @param policy policy handle.
 * @param rtp_sec_serv RTP security-service flags.
 * @param rtcp_sec_serv RTCP security-service flags.
 *
 * The policy must already have a profile set with srtp_policy_set_profile().
 *
 * @return
 *    - srtp_err_status_ok if flags were applied.
 *    - srtp_err_status_bad_param if policy is NULL or profile is unset.
 */
srtp_err_status_t srtp_policy_set_sec_serv(srtp_policy_t policy,
                                           srtp_sec_serv_t rtp_sec_serv,
                                           srtp_sec_serv_t rtcp_sec_serv);

/**
 * @brief srtp_rcc_mode_t selects the RFC 4771 Roll-over Counter Carrying
 * (RCC) integrity transform mode for an SRTP stream.
 *
 * RFC 4771 allows the sender's ROC to be carried inside the SRTP
 * authentication tag of selected packets (those whose RTP sequence number
 * is congruent to 0 modulo the transmission rate @c roc_tx_rate, "R").
 * For a packet that carries the ROC the tag is built as
 * @c TAG @c = @c ROC(4 @c octets) @c || @c MAC_tr, where @c MAC_tr is the
 * @c (auth_tag_len @c - @c 4) most significant octets of the HMAC.
 *
 * Modes 1 and 2 use the HMAC-SHA1 integrity transform and are defined only
 * for the AES-CM ciphers.  Mode 3 is the RFC 4771 NULL-MAC variant: it
 * carries only the 4-octet ROC with no MAC of its own.  Mode 3 is supported
 * here on top of AES-GCM (RFC 7714); the AEAD tag authenticates the packet
 * and the ROC occupies the SRTP authentication tag field, which RFC 7714
 * section 8.2 places at the end of the packet, after the optional MKI.
 */
typedef enum {
    srtp_rcc_mode_none = 0, /**< RCC disabled (default RFC 3711 transform). */
    srtp_rcc_mode_1 = 1,    /**< RFC 4771 mode 1: only ROC-carrying packets  */
                            /**< are integrity protected; other packets     */
                            /**< carry no authentication tag.               */
    srtp_rcc_mode_2 = 2,    /**< RFC 4771 mode 2: ROC-carrying packets use   */
                            /**< the RCC tag, all other packets use the     */
                            /**< default integrity transform.               */
    srtp_rcc_mode_3 = 3     /**< RFC 4771 mode 3: NULL-MAC, ROC only.        */
                            /**< Supported with AES-GCM, where the ROC is   */
                            /**< the last field, after the optional MKI.    */
} srtp_rcc_mode_t;

/**
 * @brief Enable or disable MKI on the policy.
 *
 * @param policy policy handle.
 * @param mki_len MKI length in octets (0 disables MKI).
 *
 * mki_len must be <= SRTP_MAX_MKI_LEN.
 * Call this with mki_len > 0 before adding MKI-tagged keys via
 * srtp_policy_add_key(). Call this with mki_len == 0 to disable MKI.
 *
 * @return
 *    - srtp_err_status_ok if MKI settings were applied.
 *    - srtp_err_status_bad_param if policy is NULL or mki_len is invalid.
 */
srtp_err_status_t srtp_policy_use_mki(srtp_policy_t policy, size_t mki_len);

/**
 * @brief Read the configured MKI length.
 *
 * @param policy policy handle.
 * @param mki_len output pointer that receives MKI length in octets.
 *
 * @return
 *    - srtp_err_status_ok if MKI length was returned.
 *    - srtp_err_status_bad_param if any argument is NULL.
 */
srtp_err_status_t srtp_policy_get_mki_length(srtp_policy_t policy,
                                             size_t *mki_len);

/**
 * @brief Enable RFC 4771 Roll-over Counter Carrying (RCC) for this policy.
 *
 * @param policy policy handle.
 * @param rcc_mode RCC integrity-transform mode (see srtp_rcc_mode_t). Pass
 *        srtp_rcc_mode_none to disable RCC and use the default RFC 3711
 *        transform.
 * @param roc_tx_rate ROC transmission rate R: the sender embeds its ROC in
 *        every packet whose RTP sequence number is congruent to 0 modulo R
 *        (R == 1 carries the ROC in every packet). Ignored when rcc_mode is
 *        srtp_rcc_mode_none; must be >= 1 otherwise.
 *
 * Modes 1 and 2 are defined only for the AES-CM ciphers; mode 3 (NULL-MAC) is
 * supported only with AES-GCM. The mode must be consistent with the policy's
 * profile or srtp_create()/srtp_policy_validate() rejects it. Both peers must
 * derive the same mode and rate so they agree on the packet layout.
 *
 * @return
 *    - srtp_err_status_ok if the RCC settings were applied.
 *    - srtp_err_status_bad_param if policy is NULL or the rate is invalid.
 */
srtp_err_status_t srtp_policy_set_rcc_mode_tx_rate(srtp_policy_t policy,
                                                   srtp_rcc_mode_t rcc_mode,
                                                   uint16_t roc_tx_rate);

/**
 * @brief Add a master key and salt to a policy handle.
 *
 * @param policy policy handle.
 * @param key pointer to key bytes.
 * @param key_len key length in octets.
 * @param salt pointer to salt bytes.
 * @param salt_len salt length in octets.
 * @param mki pointer to MKI bytes for this key.
 * @param mki_len MKI length in octets for this key.
 *
 * key_len + salt_len must be <= SRTP_MAX_KEY_LEN.
 * key and salt must not be NULL.
 * mki must not be NULL when mki_len > 0.
 * If MKI is enabled, mki_len must match the configured MKI length.
 * If MKI is disabled, mki_len must be 0 and only one key can be configured. A
 * policy can hold at most SRTP_MAX_NUM_MASTER_KEYS keys.
 *
 * The key and salt are stored separately in the policy. Validation requires
 * their lengths to exactly match the configured profile. The null/null profile
 * is valid only without keys and without MKI.
 *
 * @return
 *    - srtp_err_status_ok if key was added.
 *    - srtp_err_status_bad_param if policy is NULL, key/salt/MKI arguments are
 *      invalid, MKI state does not match mki_len, the non-MKI single-key limit
 *      or key limit is exceeded, or key/salt/MKI sizes exceed supported limits.
 */
srtp_err_status_t srtp_policy_add_key(srtp_policy_t policy,
                                      const uint8_t *key,
                                      size_t key_len,
                                      const uint8_t *salt,
                                      size_t salt_len,
                                      const uint8_t *mki,
                                      size_t mki_len);

/**
 * @brief Remove all configured master keys from a policy.
 *
 * @param policy policy handle.
 *
 * This clears the configured key material and resets key count to zero.
 * Other policy settings (for example, profile, SSRC, and MKI mode) are
 * unchanged.
 *
 * @return
 *    - srtp_err_status_ok if keys were removed.
 *    - srtp_err_status_bad_param if policy is NULL.
 */
srtp_err_status_t srtp_policy_remove_keys(srtp_policy_t policy);

/**
 * @brief Set replay-window size.
 *
 * @param policy policy handle.
 * @param window_size replay window size in packets.
 *
 * window_size must be 0 or in [64, 0x7fff].
 *
 * @return
 *    - srtp_err_status_ok if value was accepted.
 *    - srtp_err_status_bad_param if policy is NULL or value is invalid.
 */
srtp_err_status_t srtp_policy_set_window_size(srtp_policy_t policy,
                                              size_t window_size);

/**
 * @brief Enable or disable repeat transmission for RTP.
 *
 * @param policy policy handle.
 * @param allow true to allow repeat transmissions, false otherwise.
 *
 * @return
 *    - srtp_err_status_ok if value was applied.
 *    - srtp_err_status_bad_param if policy is NULL.
 */
srtp_err_status_t srtp_policy_set_allow_repeat_tx(srtp_policy_t policy,
                                                  bool allow);

/**
 * @brief Enable or disable cryptex for this policy.
 *
 * @param policy policy handle.
 * @param use_cryptex true to enable cryptex, false to disable.
 *
 * @return
 *    - srtp_err_status_ok if value was applied.
 *    - srtp_err_status_bad_param if policy is NULL.
 */
srtp_err_status_t srtp_policy_set_cryptex(srtp_policy_t policy,
                                          bool use_cryptex);

/**
 * @brief Add an encrypted header extension ID.
 *
 * @param policy policy handle.
 * @param hdr_xtnd_id header extension ID to encrypt.
 *
 * Duplicate IDs are rejected.
 * The number of configured IDs must be < SRTP_MAX_NUM_ENC_HDR_XTND_IDS.
 * Policies with both cryptex and encrypted header extensions are rejected by
 * srtp_policy_validate().
 *
 * @return
 *    - srtp_err_status_ok if ID was added.
 *    - srtp_err_status_bad_param if policy is NULL, the ID already exists, or
 *      the list is full.
 */
srtp_err_status_t srtp_policy_add_enc_hdr_xtnd_id(srtp_policy_t policy,
                                                  uint8_t hdr_xtnd_id);

/**
 * @brief Remove all encrypted header extension IDs from a policy.
 *
 * @param policy policy handle.
 *
 * This clears the configured encrypted header extension IDs and resets the
 * count to zero.
 *
 * @return
 *    - srtp_err_status_ok if IDs were removed.
 *    - srtp_err_status_bad_param if policy is NULL.
 */
srtp_err_status_t srtp_policy_remove_enc_hdr_xtnd_ids(srtp_policy_t policy);

/**
 * @brief Destroy a policy handle.
 *
 * @param policy policy handle. NULL is ignored.
 */
void srtp_policy_destroy(srtp_policy_t policy);

/**
 * @brief Validate that policy contains a usable configuration.
 *
 * @param policy policy handle.
 *
 * Validation checks include profile, SSRC selector, key/MKI consistency,
 * key count, profile key/salt lengths, replay-window constraints, and invalid
 * cryptex/encrypted-header-extension combinations. The null/null profile is
 * valid without keys and invalid with configured keys or MKI.
 *
 * @return
 *    - srtp_err_status_ok if policy is valid.
 *    - srtp_err_status_bad_param if policy is NULL or configuration is invalid.
 */
srtp_err_status_t srtp_policy_validate(srtp_policy_t policy);

/**
 * @brief An srtp_t points to an SRTP session structure.
 *
 * The typedef srtp_t is a pointer to a structure that represents
 * an SRTP session.  This datatype is intentionally opaque in
 * order to separate the interface from the implementation.
 *
 * An SRTP session consists of all of the traffic sent to the RTP and
 * RTCP destination transport addresses, using the RTP/SAVP (Secure
 * Audio/Video Profile).  A session can be viewed as a set of SRTP
 * streams, each of which originates with a different participant.
 */
typedef srtp_ctx_t *srtp_t;

/**
 * @brief srtp_init() initializes the srtp library.
 *
 * @warning This function @b must be called before any other srtp
 * functions.
 */
srtp_err_status_t srtp_init(void);

/**
 * @brief srtp_shutdown() de-initializes the srtp library.
 *
 * @warning No srtp functions may be called after calling this function.
 */
srtp_err_status_t srtp_shutdown(void);

/**
 * @brief srtp_protect() is the Secure RTP sender-side packet processing
 * function.
 *
 * The function call srtp_protect(ctx, rtp, rtp_len, srtp, srtp_len, mki_index)
 * applies SRTP protection to the RTP packet rtp (which has length rtp_len)
 * using the SRTP context ctx.  If srtp_err_status_ok is returned, then srtp
 * points to the resulting SRTP packet and *srtp_len is the number of
 * octets in that packet; otherwise, no assumptions should be made
 * about the value of either data elements.
 *
 * The sequence numbers of the RTP packets presented to this function
 * need not be consecutive, but they @b must be out of order by less
 * than 2^15 = 32,768 packets.
 *
 * @warning This function assumes that the RTP packet is aligned on a 32-bit
 * boundary.
 *
 * @param ctx is the SRTP context to use in processing the packet.
 *
 * @param rtp is a pointer to the RTP packet.
 *
 * @param rtp_len is the length in octets of the complete RTP
 * packet (header and body).
 *
 * @param srtp is a pointer to a buffer that after the function returns will
 * contain the complete SRTP packet. The value of srtp can be the same as rtp to
 * support in-place io.
 *
 * @param srtp_len is a pointer to the length in octets of the srtp buffer
 * before the function call, and of the complete SRTP packet after the call, if
 * srtp_err_status_ok was returned. Otherwise, the value of the data to which it
 * points is undefined.
 *
 * @param mki_index integer value specifying which set of session keys should be
 * used if use_mki in the policy was set to true. Otherwise ignored.
 *
 * @return
 *    - srtp_err_status_ok            no problems
 *    - srtp_err_status_replay_fail   rtp sequence number was non-increasing
 *    - srtp_err_status_buffer_small  the srtp buffer is too small for the SRTP
 * packet
 *    - srtp_err_status_direction_mismatch the stream is not a sender stream
 *    - @e other                 failure in cryptographic mechanisms
 */
srtp_err_status_t srtp_protect(srtp_t ctx,
                               const uint8_t *rtp,
                               size_t rtp_len,
                               uint8_t *srtp,
                               size_t *srtp_len,
                               size_t mki_index);

/**
 * @brief srtp_unprotect() is the Secure RTP receiver-side packet
 * processing function.
 *
 * The function call srtp_unprotect(ctx, srtp, srtp_len, rtp, rtp_len) verifies
 * the Secure RTP protection of the SRTP packet pointed to by srtp
 * (which has length srtp_len), using the SRTP context ctx.  If
 * srtp_err_status_ok is returned, then rtp points to the resulting
 * RTP packet and *rtp_len is the number of octets in that packet;
 * otherwise, no assumptions should be made about the value of either
 * data elements.
 *
 * The sequence numbers of the RTP packets presented to this function
 * need not be consecutive, but they @b must be out of order by less
 * than 2^15 = 32,768 packets.
 *
 * @warning This function assumes that the SRTP packet is aligned on a
 * 32-bit boundary.
 *
 * @param ctx is the SRTP session which applies to the particular packet.
 *
 * @param srtp is a pointer to the header of the SRTP packet.
 *
 * @param srtp_len is the length in octets of the complete
 * srtp packet (header and body).
 *
 * @param rtp is a pointer to a buffer that after the function returns will
 * contain the complete RTP packet. The value of rtp can be the same as srtp
 * to support in-place io.
 *
 * @param srtp_len is a pointer to the length of the rtp buffer before the
 * function call, and of the complete RTP packet after the call, if
 * srtp_err_status_ok was returned. Otherwise, the value of the data to which
 * it points is undefined.
 *
 * @return
 *    - srtp_err_status_ok          if the RTP packet is valid.
 *    - srtp_err_status_auth_fail   if the SRTP packet failed the message
 *                                  authentication check.
 *    - srtp_err_status_replay_fail if the SRTP packet is a replay (e.g. packet
 *                                  has already been processed and accepted).
 *    - srtp_err_status_bad_mki if the MKI in the packet is not a known MKI id
 *    - srtp_err_status_direction_mismatch if the stream is not a receiver
 *                                         stream
 *    - [other]  if there has been an error in the cryptographic mechanisms.
 *
 */
srtp_err_status_t srtp_unprotect(srtp_t ctx,
                                 const uint8_t *srtp,
                                 size_t srtp_len,
                                 uint8_t *rtp,
                                 size_t *rtp_len);

/**
 * @brief srtp_create() allocates and initializes an SRTP session.
 *
 * The function call srtp_create(session, policy) allocates and
 * initializes an SRTP session context, applying the given policy.
 *
 * @param session is a pointer to the SRTP session to which the policy is
 * to be added.
 *
 * @param policy is an srtp_policy_t handle that describes one stream policy.
 * It may be NULL, in which case streams can be added later using
 * srtp_stream_add().
 *
 * @return
 *    - srtp_err_status_ok           if creation succeeded.
 *    - srtp_err_status_alloc_fail   if allocation failed.
 *    - srtp_err_status_init_fail    if initialization failed.
 */
srtp_err_status_t srtp_create(srtp_t *session, const srtp_policy_t policy);

/**
 * @brief srtp_stream_add() allocates and initializes an SRTP stream
 * within a given SRTP session.
 *
 * The function call srtp_stream_add(session, policy) allocates and
 * initializes a new SRTP stream within a given, previously created
 * session, applying the policy given as the other argument to that
 * stream.
 *
 * @return values:
 *    - srtp_err_status_ok           if stream creation succeeded.
 *    - srtp_err_status_alloc_fail   if stream allocation failed
 *    - srtp_err_status_init_fail    if stream initialization failed.
 */
srtp_err_status_t srtp_stream_add(srtp_t session, const srtp_policy_t policy);

/**
 * @brief srtp_stream_remove() deallocates an SRTP stream.
 *
 * The function call srtp_stream_remove(session, ssrc) removes
 * the SRTP stream with the SSRC value ssrc from the SRTP session
 * context given by the argument session.
 *
 * @param session is the SRTP session from which the stream
 * will be removed.
 *
 * @param ssrc is the SSRC value of the stream to be removed
 * in host byte order.
 *
 * @attention In libSRTP version before 3.0.0 the SSRC param was in network
 * byte order, this was changed in 3.0.0 to host byte order to be
 * consistant with the rest of the api.
 *
 * @warning Wildcard SSRC values cannot be removed from a
 * session.
 *
 * @return
 *    - srtp_err_status_ok     if the stream deallocation succeeded.
 *    - [other]           otherwise.
 *
 */
srtp_err_status_t srtp_stream_remove(srtp_t session, uint32_t ssrc);

/**
 * @brief srtp_update() updates all streams in the session.
 *
 * The function call srtp_update(session, policy) updates
 * all the streams in the session applying the given policy
 * and key. The existing ROC value of all streams will be
 * preserved.
 *
 * @param session is the SRTP session that contains the streams
 *        to be updated.
 *
 * @param policy is an srtp_policy_t handle that describes the update policy
 * to apply to matching stream(s).
 *
 * @return
 *    - srtp_err_status_ok           if stream creation succeed.
 *    - srtp_err_status_alloc_fail   if stream allocation failed
 *    - srtp_err_status_init_fail    if stream initialization failed.
 *    - [other]                 otherwise.
 *
 */
srtp_err_status_t srtp_update(srtp_t session, const srtp_policy_t policy);

/**
 * @brief srtp_stream_update() updates a SRTP stream.
 *
 * The function call srtp_stream_update(session, policy) updates
 * the stream(s) in the session that match applying the given
 * policy and key. The existing ROC value of all stream(s) will
 * be preserved.
 *
 * @param session is the SRTP session that contains the streams
 *        to be updated.
 *
 * @param policy is an srtp_policy_t handle that describes the update policy
 * to apply to matching stream(s).
 *
 * @return
 *    - srtp_err_status_ok           if stream creation succeeded.
 *    - srtp_err_status_alloc_fail   if stream allocation failed
 *    - srtp_err_status_init_fail    if stream initialization failed.
 *    - [other]                      otherwise.
 *
 */
srtp_err_status_t srtp_stream_update(srtp_t session,
                                     const srtp_policy_t policy);

/**
 * @brief srtp_dealloc() deallocates storage for an SRTP session
 * context.
 *
 * The function call srtp_dealloc(s) deallocates storage for the
 * SRTP session context s.  This function should be called no more
 * than one time for each of the contexts allocated by the function
 * srtp_create().
 *
 * @param s is the srtp_t for the session to be deallocated.
 *
 * @return
 *    - srtp_err_status_ok             if there no problems.
 *    - srtp_err_status_dealloc_fail   a memory deallocation failure occurred.
 */
srtp_err_status_t srtp_dealloc(srtp_t s);

/**
 * @brief returns the master key length for a given SRTP profile
 */
size_t srtp_profile_get_master_key_length(srtp_profile_t profile);

/**
 * @brief returns the master salt length for a given SRTP profile
 */
size_t srtp_profile_get_master_salt_length(srtp_profile_t profile);

/**
 * @brief appends the salt to the key
 *
 * The function call srtp_append_salt_to_key(k, klen, s, slen)
 * copies the string s to the location at klen bytes following
 * the location k.
 *
 * @warning There must be at least bytes_in_salt + bytes_in_key bytes
 *          available at the location pointed to by key.
 *
 *
 */
void srtp_append_salt_to_key(uint8_t *key,
                             size_t bytes_in_key,
                             uint8_t *salt,
                             size_t bytes_in_salt);

/**
 * @}
 */

/**
 * @defgroup SRTCP Secure RTCP
 * @ingroup  SRTP
 *
 * @brief Secure RTCP functions are used to protect RTCP traffic.
 *
 * RTCP is the control protocol for RTP.  libSRTP protects RTCP
 * traffic in much the same way as it does RTP traffic.  The function
 * srtp_protect_rtcp() applies cryptographic protections to outbound
 * RTCP packets, and srtp_unprotect_rtcp() verifies the protections on
 * inbound RTCP packets.
 *
 * A note on the naming convention: srtp_protect_rtcp() has an srtp_t
 * as its first argument, and thus has `srtp_' as its prefix.  The
 * trailing `_rtcp' indicates the protocol on which it acts.
 *
 * @{
 */

/**
 * @brief srtp_protect_rtcp() is the Secure RTCP sender-side packet
 * processing function.
 *
 * The function call srtp_protect_rtcp(ctx, rtcp, rtcp_len, srtcp, srtcp_len,
 * mki_index) applies SRTCP protection to the RTCP packet rtcp (which has length
 * rtcp_len) using the SRTP session context ctx. If srtp_err_status_ok is
 * returned, then srtcp points to the resulting SRTCP packet and
 * *srtcp_len is the number of octets in that packet; otherwise, no
 * assumptions should be made about the value of either data elements.
 *
 * @warning This function assumes that the RTCP packet is aligned on a 32-bit
 * boundary.
 *
 * @param ctx is the SRTP context to use in processing the packet.
 *
 * @param rtcp is a pointer to the RTCP packet (before the call).
 *
 * @param rtcp_len is the length in octets of the complete RTCP packet (header
 * and body).
 *
 * @param srtcp is a pointer to a buffer that after the function returns will
 * contain the complete SRTCP packet. The value of srtcp can be the same as rtcp
 * to support in-place io.
 *
 * @param srtcp_len is a pointer to the length in octets of the srtcp buffer
 * before the function call, and of the complete SRTCP packet after the call, if
 * srtp_err_status_ok was returned. Otherwise, the value of the data to which it
 * points is undefined.
 *
 * @param mki_index integer value specifying which set of session keys should be
 * used if use_mki was set to true. Otherwise ignored.
 *
 * @return
 *    - srtp_err_status_ok            if there were no problems.
 *    - srtp_err_status_buffer_small  the srtcp buffer is too small for the
 * SRTCP packet
 *    - srtp_err_status_direction_mismatch the stream is not a sender stream
 *    - [other]                  if there was a failure in
 *                               the cryptographic mechanisms.
 */
srtp_err_status_t srtp_protect_rtcp(srtp_t ctx,
                                    const uint8_t *rtcp,
                                    size_t rtcp_len,
                                    uint8_t *srtcp,
                                    size_t *srtcp_len,
                                    size_t mki_index);

/**
 * @brief srtp_unprotect_rtcp() is the Secure RTCP receiver-side packet
 * processing function.
 *
 * The function call srtp_unprotect_rtcp(ctx, srtcp, srtcp_len, rtcp, rtcp_len)
 * verifies the Secure RTCP protection of the SRTCP packet pointed to
 * by srtcp (which has length srtcp_len), using the SRTP session
 * context ctx.  If srtp_err_status_ok is returned, then rtcp points
 * to the resulting RTCP packet and *rtcp_len is the number of octets
 * in that packet; otherwise, no assumptions should be made about the
 * value of either data elements.
 *
 * @warning This function assumes that the SRTCP packet is aligned on a
 * 32-bit boundary.
 *
 * @param ctx is a pointer to the srtp_t which applies to the
 * particular packet.
 *
 * @param srtcp is a pointer to the header of the SRTCP packet.
 *
 * @param srtcp_len is the length in octets of the complete SRTCP packet (header
 * and body).
 *
 * @param rtcp is a pointer to a buffer that after the function returns will
 * contain the complete RTCP packet. The value of rtcp can be the same as srtcp
 * to support in-place io.
 *
 * @param rtcp_len is a pointer to the length of the rtcp buffer before the
 * function call, and of the complete RTCP packet after the call, if
 * srtp_err_status_ok was returned. Otherwise, the value of the data to which
 * it points is undefined.
 *
 * @return
 *    - srtp_err_status_ok          if the RTCP packet is valid.
 *    - srtp_err_status_auth_fail   if the SRTCP packet failed the message
 *                             authentication check.
 *    - srtp_err_status_replay_fail if the SRTCP packet is a replay (e.g. has
 *                             already been processed and accepted).
 *    - srtp_err_status_bad_mki     if the MKI in the packet is not a known MKI
 *                                  id
 *    - srtp_err_status_direction_mismatch if the stream is not a receiver
 *                                         stream
 *    - [other]  if there has been an error in the cryptographic mechanisms.
 *
 */
srtp_err_status_t srtp_unprotect_rtcp(srtp_t ctx,
                                      const uint8_t *srtcp,
                                      size_t srtcp_len,
                                      uint8_t *rtcp,
                                      size_t *rtcp_len);

/**
 * @defgroup User data associated to a SRTP session.
 * @ingroup  SRTP
 *
 * @brief Store custom user data within a SRTP session.
 *
 * @{
 */

/**
 * @brief srtp_set_user_data() stores the given pointer into the SRTP
 * session for later retrieval.
 *
 * @param ctx is the srtp_t context in which the given data pointer is
 * stored.
 *
 * @param data is a pointer to the custom information (struct, function,
 * etc) associated with the SRTP session.
 *
 * @return void.
 *
 */
void srtp_set_user_data(srtp_t ctx, void *data);

/**
 * @brief srtp_get_user_data() retrieves the pointer to the custom data
 * previously stored with srtp_set_user_data().
 *
 * This function is mostly useful for retrieving data associated to a
 * SRTP session when an event fires. The user can then get such a custom
 * data by calling this function with the session field of the
 * srtp_event_data_t struct as argument.
 *
 * @param ctx is the srtp_t context in which the given data pointer was
 * stored.
 *
 * @return void* pointer to the user data.
 *
 */
void *srtp_get_user_data(srtp_t ctx);

/**
 * @}
 */

/**
 * @defgroup SRTPevents SRTP events and callbacks
 * @ingroup  SRTP
 *
 * @brief libSRTP can use a user-provided callback function to
 * handle events.
 *
 *
 * libSRTP allows a user to provide a callback function to handle
 * events that need to be dealt with outside of the data plane (see
 * the enum srtp_event_t for a description of these events).  Dealing
 * with these events is not a strict necessity; they are not
 * security-critical, but the application may suffer if they are not
 * handled.  The function srtp_set_event_handler() is used to provide
 * the callback function.
 *
 * A default event handler that merely reports on the events as they
 * happen is included.  It is also possible to set the event handler
 * function to NULL, in which case all events will just be silently
 * ignored.
 *
 * @{
 */

/**
 * @brief srtp_event_t defines events that need to be handled
 *
 * The enum srtp_event_t defines events that need to be handled
 * outside the `data plane', such as SSRC collisions and
 * key expirations.
 *
 * When a key expires or the maximum number of packets has been
 * reached, an SRTP stream will enter an `expired' state in which no
 * more packets can be protected or unprotected.  When this happens,
 * it is likely that you will want to either deallocate the stream
 * (using srtp_stream_remove()), and possibly allocate a new one.
 *
 * When an SRTP stream expires, the other streams in the same session
 * are unaffected, unless key sharing is used by that stream.  In the
 * latter case, all of the streams in the session will expire.
 */
typedef enum {
    event_ssrc_collision,    /**< An SSRC collision occurred.           */
    event_key_soft_limit,    /**< An SRTP stream reached the soft key   */
                             /**< usage limit and will expire soon.     */
    event_key_hard_limit,    /**< An SRTP stream reached the hard       */
                             /**< key usage limit and has expired.      */
    event_packet_index_limit /**< An SRTP stream reached the hard       */
                             /**< packet limit (2^48 packets).          */
} srtp_event_t;

/**
 * @brief srtp_event_data_t is the structure passed as a callback to
 * the event handler function
 *
 * The struct srtp_event_data_t holds the data passed to the event
 * handler function.
 */
typedef struct srtp_event_data_t {
    srtp_t session;     /**< The session in which the event happened.       */
    uint32_t ssrc;      /**< The ssrc in host order of the stream in which  */
                        /**< the event happened                             */
    srtp_event_t event; /**< An enum indicating the type of event.          */
} srtp_event_data_t;

/**
 * @brief srtp_event_handler_func_t is the function prototype for
 * the event handler.
 *
 * The typedef srtp_event_handler_func_t is the prototype for the
 * event handler function.  It has as its only argument an
 * srtp_event_data_t which describes the event that needs to be handled.
 * There can only be a single, global handler for all events in
 * libSRTP.
 */
typedef void(srtp_event_handler_func_t)(srtp_event_data_t *data);

/**
 * @brief sets the event handler to the function supplied by the caller.
 *
 * The function call srtp_install_event_handler(func) sets the event
 * handler function to the value func.  The value NULL is acceptable
 * as an argument; in this case, events will be ignored rather than
 * handled.
 *
 * @param func is a pointer to a function that takes an srtp_event_data_t
 *             pointer as an argument and returns void.  This function
 *             will be used by libSRTP to handle events.
 */
srtp_err_status_t srtp_install_event_handler(srtp_event_handler_func_t func);

/**
 * @brief Returns the version string of the library.
 *
 */
const char *srtp_get_version_string(void);

/**
 * @brief Returns the numeric representation of the library version.
 *
 */
unsigned int srtp_get_version(void);

/**
 * @brief srtp_set_debug_module(mod_name, v)
 *
 * sets dynamic debugging to the value v (false for off, true for on) for the
 * debug module with the name mod_name
 *
 * returns err_status_ok on success, err_status_fail otherwise
 */
srtp_err_status_t srtp_set_debug_module(const char *mod_name, bool v);

/**
 * @brief srtp_list_debug_modules() outputs a list of debugging modules
 *
 */
srtp_err_status_t srtp_list_debug_modules(void);

/**
 * @brief srtp_log_level_t defines log levels.
 *
 * The enumeration srtp_log_level_t defines log levels reported
 * in the srtp_log_handler_func_t.
 *
 */
typedef enum {
    srtp_log_level_error,   /**< log level is reporting an error message  */
    srtp_log_level_warning, /**< log level is reporting a warning message */
    srtp_log_level_info,    /**< log level is reporting an info message   */
    srtp_log_level_debug    /**< log level is reporting a debug message   */
} srtp_log_level_t;

/**
 * @brief srtp_log_handler_func_t is the function prototype for
 * the log handler.
 *
 * The typedef srtp_event_handler_func_t is the prototype for the
 * event handler function.  It has as srtp_log_level_t, log
 * message and data as arguments.
 * There can only be a single, global handler for all log messages in
 * libSRTP.
 */
typedef void(srtp_log_handler_func_t)(srtp_log_level_t level,
                                      const char *msg,
                                      void *data);

/**
 * @brief sets the log handler to the function supplied by the caller.
 *
 * The function call srtp_install_log_handler(func) sets the log
 * handler function to the value func.  The value NULL is acceptable
 * as an argument; in this case, log messages will be ignored.
 * This function can be called before srtp_init() in order to capture
 * any logging during start up.
 *
 * @param func is a pointer to a function of type srtp_log_handler_func_t.
 *             This function will be used by libSRTP to output log messages.
 * @param data is a user pointer that will be returned as the data argument in
 * func.
 */
srtp_err_status_t srtp_install_log_handler(srtp_log_handler_func_t func,
                                           void *data);

/**
 * @brief srtp_get_protect_trailer_length(session, use_mki, mki_index, length)
 *
 * Determines the length of the amount of data Lib SRTP will add to the
 * packet during the protect process. The length is returned in the length
 * parameter
 *
 * returns err_status_ok on success, err_status_bad_mki if the MKI index is
 * invalid
 *
 */
srtp_err_status_t srtp_get_protect_trailer_length(srtp_t session,
                                                  size_t mki_index,
                                                  size_t *length);

/**
 * @brief srtp_get_protect_rtcp_trailer_length(session, use_mki, mki_index,
 * length)
 *
 * Determines the length of the amount of data Lib SRTP will add to the
 * packet during the protect process. The length is returned in the length
 * parameter
 *
 * returns err_status_ok on success, err_status_bad_mki if the MKI index is
 * invalid
 *
 */
srtp_err_status_t srtp_get_protect_rtcp_trailer_length(srtp_t session,
                                                       size_t mki_index,
                                                       size_t *length);

/**
 * @brief srtp_stream_set_roc(session, ssrc, roc)
 *
 * Set the roll-over-counter on a session for a given SSRC
 *
 * returns err_status_ok on success, srtp_err_status_bad_param if there is no
 * stream found
 *
 */
srtp_err_status_t srtp_stream_set_roc(srtp_t session,
                                      uint32_t ssrc,
                                      uint32_t roc);

/**
 * @brief srtp_stream_get_roc(session, ssrc, roc)
 *
 * Get the roll-over-counter on a session for a given SSRC
 *
 * returns err_status_ok on success, srtp_err_status_bad_param if there is no
 * stream found
 *
 */
srtp_err_status_t srtp_stream_get_roc(srtp_t session,
                                      uint32_t ssrc,
                                      uint32_t *roc);

/**
 * @}
 */

/* in host order, so outside the #if */
#define SRTCP_E_BIT 0x80000000

/* for byte-access */
#define SRTCP_E_BYTE_BIT 0x80
#define SRTCP_INDEX_MASK 0x7fffffff

#ifdef __cplusplus
}
#endif

#endif /* SRTP_SRTP_H */
