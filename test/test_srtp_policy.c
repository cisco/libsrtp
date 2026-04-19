/*
 * test_srtp_policy.c
 *
 * Unit tests for srtp_policy API
 *
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

#include "cutest.h"

#include "srtp.h"
#include "util.h"

static const uint8_t base_master_key[16] = {
    0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0,
    0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39,
};
static const uint8_t base_master_salt[14] = {
    0xc3, 0x17, 0xf2, 0xda, 0xbe, 0x35, 0x77,
    0x93, 0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6,
};
static const uint8_t alt_master_key[16] = {
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
    0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00,
};
static const uint8_t alt_master_salt[14] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
    0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
};
static const uint8_t mki4[4] = { 0x01, 0x02, 0x03, 0x04 };
static const uint8_t mki3[3] = { 0x09, 0x08, 0x07 };

static void create_valid_policy(srtp_policy_t *policy)
{
    CHECK_OK(srtp_policy_create(policy));
    CHECK_OK(
        srtp_policy_set_ssrc(*policy, (srtp_ssrc_t){ ssrc_any_outbound, 0 }));
    CHECK_OK(srtp_policy_set_profile(*policy, srtp_profile_aes128_cm_sha1_80));
    CHECK_OK(srtp_policy_add_key(*policy, base_master_key,
                                 sizeof(base_master_key), base_master_salt,
                                 sizeof(base_master_salt), NULL, 0));
}

static void assert_policy_creates_session(srtp_policy_t policy)
{
    srtp_t srtp;
    CHECK_OK(srtp_init());
    CHECK_OK(srtp_create(&srtp, policy));
    CHECK_OK(srtp_dealloc(srtp));
    CHECK_OK(srtp_shutdown());
}

static void srtp_policy_create_destroy_ok(void)
{
    srtp_policy_t policy;
    CHECK_OK(srtp_policy_create(&policy));
    CHECK(policy != NULL);
    srtp_policy_destroy(policy);
}

static void srtp_policy_create_null_fails(void)
{
    CHECK_RETURN(srtp_policy_create(NULL), srtp_err_status_bad_param);
}

static void srtp_policy_empty_not_valid(void)
{
    srtp_policy_t policy;
    CHECK_OK(srtp_policy_create(&policy));
    CHECK_RETURN(srtp_policy_validate(policy), srtp_err_status_bad_param);
    srtp_policy_destroy(policy);
}

static void srtp_policy_minimal(void)
{
    srtp_policy_t policy;
    create_valid_policy(&policy);
    CHECK_OK(srtp_policy_validate(policy));
    assert_policy_creates_session(policy);
    srtp_policy_destroy(policy);
}

static void srtp_policy_clone_success_and_independent(void)
{
    srtp_policy_t policy;
    srtp_policy_t cloned = NULL;

    create_valid_policy(&policy);
    CHECK_OK(srtp_policy_clone(policy, &cloned));
    CHECK(cloned != NULL);
    CHECK_OK(srtp_policy_validate(cloned));

    /* mutating original to invalid state must not affect clone */
    CHECK_OK(srtp_policy_use_mki(policy, sizeof(mki4)));
    CHECK_RETURN(srtp_policy_validate(policy), srtp_err_status_bad_param);
    CHECK_OK(srtp_policy_validate(cloned));

    assert_policy_creates_session(cloned);
    srtp_policy_destroy(cloned);
    srtp_policy_destroy(policy);
}

static void srtp_policy_clone_null_output_fails(void)
{
    srtp_policy_t policy;
    create_valid_policy(&policy);
    CHECK_RETURN(srtp_policy_clone(policy, NULL), srtp_err_status_bad_param);
    srtp_policy_destroy(policy);
}

static void srtp_policy_set_ssrc_invalid_type_fails(void)
{
    srtp_policy_t policy;
    create_valid_policy(&policy);
    CHECK_RETURN(
        srtp_policy_set_ssrc(policy, (srtp_ssrc_t){ ssrc_undefined, 0 }),
        srtp_err_status_bad_param);
    srtp_policy_destroy(policy);
}

static void srtp_policy_set_get_profile_roundtrip(void)
{
    srtp_policy_t policy;
    srtp_profile_t profile = srtp_profile_reserved;
    CHECK_OK(srtp_policy_create(&policy));
    CHECK_OK(
        srtp_policy_set_ssrc(policy, (srtp_ssrc_t){ ssrc_any_outbound, 0 }));

    CHECK_OK(srtp_policy_set_profile(policy, srtp_profile_aes256_cm_sha1_80));
    CHECK_OK(srtp_policy_get_profile(policy, &profile));
    CHECK(profile == srtp_profile_aes256_cm_sha1_80);

    srtp_policy_destroy(policy);
}

static void srtp_policy_set_profile_reserved_fails(void)
{
    srtp_policy_t policy;
    CHECK_OK(srtp_policy_create(&policy));
    CHECK_RETURN(srtp_policy_set_profile(policy, srtp_profile_reserved),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_validate(policy), srtp_err_status_bad_param);
    srtp_policy_destroy(policy);
}

static void srtp_policy_set_sec_serv_requires_profile(void)
{
    srtp_policy_t policy;
    CHECK_OK(srtp_policy_create(&policy));
    CHECK_OK(
        srtp_policy_set_ssrc(policy, (srtp_ssrc_t){ ssrc_any_outbound, 0 }));
    CHECK_RETURN(srtp_policy_set_sec_serv(policy, sec_serv_conf_and_auth,
                                          sec_serv_conf_and_auth),
                 srtp_err_status_bad_param);

    CHECK_OK(srtp_policy_set_profile(policy, srtp_profile_aes128_cm_sha1_80));
    CHECK_OK(srtp_policy_add_key(policy, base_master_key,
                                 sizeof(base_master_key), base_master_salt,
                                 sizeof(base_master_salt), NULL, 0));
    CHECK_OK(srtp_policy_set_sec_serv(policy, sec_serv_auth, sec_serv_none));
    CHECK_OK(srtp_policy_validate(policy));
    assert_policy_creates_session(policy);
    srtp_policy_destroy(policy);
}

static void srtp_policy_add_key_oversize_fails(void)
{
    uint8_t long_key[SRTP_MAX_KEY_LEN];
    uint8_t salt[1] = { 0 };
    srtp_policy_t policy;

    CHECK_OK(srtp_policy_create(&policy));
    CHECK_RETURN(srtp_policy_add_key(policy, long_key, sizeof(long_key), salt,
                                     sizeof(salt), NULL, 0),
                 srtp_err_status_bad_param);
    srtp_policy_destroy(policy);
}

static void srtp_policy_mki_length_transitions_and_limits(void)
{
    srtp_policy_t policy;
    size_t mki_len = 99;
    create_valid_policy(&policy);

    CHECK_OK(srtp_policy_get_mki_length(policy, &mki_len));
    CHECK(mki_len == 0);

    CHECK_OK(srtp_policy_use_mki(policy, sizeof(mki4)));
    CHECK_OK(srtp_policy_get_mki_length(policy, &mki_len));
    CHECK(mki_len == sizeof(mki4));

    CHECK_OK(srtp_policy_use_mki(policy, 0));
    CHECK_OK(srtp_policy_get_mki_length(policy, &mki_len));
    CHECK(mki_len == 0);

    CHECK_RETURN(srtp_policy_use_mki(policy, SRTP_MAX_MKI_LEN + 1),
                 srtp_err_status_bad_param);

    srtp_policy_destroy(policy);
}

static void srtp_policy_add_key_edges(void)
{
    uint8_t too_long_key[SRTP_MAX_KEY_LEN];
    uint8_t one_byte_salt[1] = { 0 };
    srtp_policy_t policy;

    CHECK_OK(srtp_policy_create(&policy));
    CHECK_OK(
        srtp_policy_set_ssrc(policy, (srtp_ssrc_t){ ssrc_any_outbound, 0 }));
    CHECK_OK(srtp_policy_set_profile(policy, srtp_profile_aes128_cm_sha1_80));

    /* non-MKI mode supports exactly one key via add_key */
    CHECK_OK(srtp_policy_add_key(policy, base_master_key,
                                 sizeof(base_master_key), base_master_salt,
                                 sizeof(base_master_salt), mki4, 0));
    CHECK_RETURN(srtp_policy_add_key(policy, alt_master_key,
                                     sizeof(alt_master_key), alt_master_salt,
                                     sizeof(alt_master_salt), mki4, 0),
                 srtp_err_status_bad_param);
    CHECK_OK(srtp_policy_validate(policy));

    /* MKI key requires explicit MKI mode first */
    CHECK_RETURN(srtp_policy_add_key(policy, alt_master_key,
                                     sizeof(alt_master_key), alt_master_salt,
                                     sizeof(alt_master_salt), mki4,
                                     sizeof(mki4)),
                 srtp_err_status_bad_param);
    srtp_policy_destroy(policy);
    create_valid_policy(&policy);
    CHECK_OK(srtp_policy_use_mki(policy, sizeof(mki4)));
    CHECK_RETURN(srtp_policy_add_key(policy, too_long_key, sizeof(too_long_key),
                                     one_byte_salt, sizeof(one_byte_salt), mki4,
                                     sizeof(mki4)),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_add_key(policy, alt_master_key,
                                     sizeof(alt_master_key), alt_master_salt,
                                     sizeof(alt_master_salt), mki4, 0),
                 srtp_err_status_bad_param);

    srtp_policy_destroy(policy);
}

static void srtp_policy_add_key_mki_mismatch_fails(void)
{
    srtp_policy_t policy;

    create_valid_policy(&policy);
    CHECK_OK(srtp_policy_use_mki(policy, sizeof(mki4)));
    CHECK_RETURN(srtp_policy_add_key(policy, alt_master_key,
                                     sizeof(alt_master_key), alt_master_salt,
                                     sizeof(alt_master_salt), mki3,
                                     sizeof(mki3)),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_add_key(policy, alt_master_key,
                                     sizeof(alt_master_key), alt_master_salt,
                                     sizeof(alt_master_salt), mki4, 0),
                 srtp_err_status_bad_param);

    srtp_policy_destroy(policy);
}

static void srtp_policy_add_key_strict_null_checks(void)
{
    srtp_policy_t policy;
    uint8_t key[1] = { 0x01 };
    uint8_t salt[1] = { 0x02 };
    uint8_t mki[1] = { 0x03 };

    CHECK_OK(srtp_policy_create(&policy));
    CHECK_OK(
        srtp_policy_set_ssrc(policy, (srtp_ssrc_t){ ssrc_any_outbound, 0 }));
    CHECK_OK(srtp_policy_set_profile(policy, srtp_profile_aes128_cm_sha1_80));
    CHECK_RETURN(srtp_policy_add_key(policy, NULL, sizeof(key), salt,
                                     sizeof(salt), NULL, 0),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_add_key(policy, key, sizeof(key), NULL,
                                     sizeof(salt), NULL, 0),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_add_key(policy, key, sizeof(key), salt,
                                     sizeof(salt), NULL, sizeof(mki)),
                 srtp_err_status_bad_param);
    CHECK_OK(srtp_policy_use_mki(policy, sizeof(mki)));
    CHECK_RETURN(srtp_policy_add_key(policy, key, sizeof(key), salt,
                                     sizeof(salt), NULL, sizeof(mki)),
                 srtp_err_status_bad_param);
    CHECK_OK(srtp_policy_add_key(policy, key, sizeof(key), salt, sizeof(salt),
                                 mki, sizeof(mki)));
    CHECK_OK(srtp_policy_validate(policy));

    srtp_policy_destroy(policy);
}

static void srtp_policy_add_key_max_master_keys_limit(void)
{
    srtp_policy_t policy;
    uint8_t key[sizeof(base_master_key)];
    uint8_t salt[sizeof(base_master_salt)];
    uint8_t mki;

    CHECK_OK(srtp_policy_create(&policy));
    CHECK_OK(
        srtp_policy_set_ssrc(policy, (srtp_ssrc_t){ ssrc_any_outbound, 0 }));
    CHECK_OK(srtp_policy_set_profile(policy, srtp_profile_aes128_cm_sha1_80));
    CHECK_OK(srtp_policy_use_mki(policy, 1));

    for (size_t i = 0; i < SRTP_MAX_NUM_MASTER_KEYS; i++) {
        memcpy(key, base_master_key, sizeof(key));
        memcpy(salt, base_master_salt, sizeof(salt));
        key[0] ^= (uint8_t)i;
        salt[0] ^= (uint8_t)i;
        mki = (uint8_t)i;

        CHECK_OK(srtp_policy_add_key(policy, key, sizeof(key), salt,
                                     sizeof(salt), &mki, sizeof(mki)));
    }

    CHECK_OK(srtp_policy_validate(policy));

    memcpy(key, base_master_key, sizeof(key));
    memcpy(salt, base_master_salt, sizeof(salt));
    key[0] ^= 0xA5;
    salt[0] ^= 0x5A;
    mki = 0xFF;
    CHECK_RETURN(srtp_policy_add_key(policy, key, sizeof(key), salt,
                                     sizeof(salt), &mki, sizeof(mki)),
                 srtp_err_status_bad_param);

    CHECK_OK(srtp_policy_validate(policy));
    srtp_policy_destroy(policy);
}

static void srtp_policy_remove_keys_simple(void)
{
    srtp_policy_t policy;

    create_valid_policy(&policy);
    CHECK_OK(srtp_policy_validate(policy));

    CHECK_OK(srtp_policy_remove_keys(policy));
    CHECK_RETURN(srtp_policy_validate(policy), srtp_err_status_bad_param);

    CHECK_OK(srtp_policy_add_key(policy, base_master_key,
                                 sizeof(base_master_key), base_master_salt,
                                 sizeof(base_master_salt), NULL, 0));
    CHECK_OK(srtp_policy_validate(policy));

    srtp_policy_destroy(policy);
}

static void srtp_policy_set_window_size_invalid_values_fail(void)
{
    srtp_policy_t policy;
    CHECK_OK(srtp_policy_create(&policy));
    CHECK_RETURN(srtp_policy_set_window_size(policy, 1),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_set_window_size(policy, 63),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_set_window_size(policy, 0x8000),
                 srtp_err_status_bad_param);
    srtp_policy_destroy(policy);
}

static void srtp_policy_set_window_size_valid_values_ok(void)
{
    srtp_policy_t policy;
    create_valid_policy(&policy);

    CHECK_OK(srtp_policy_set_window_size(policy, 0));
    CHECK_OK(srtp_policy_validate(policy));
    CHECK_OK(srtp_policy_set_window_size(policy, 64));
    CHECK_OK(srtp_policy_validate(policy));
    CHECK_OK(srtp_policy_set_window_size(policy, 0x7fff));
    CHECK_OK(srtp_policy_validate(policy));

    assert_policy_creates_session(policy);
    srtp_policy_destroy(policy);
}

static void srtp_policy_set_allow_repeat_tx_values_ok(void)
{
    srtp_policy_t policy;
    create_valid_policy(&policy);

    CHECK_OK(srtp_policy_set_allow_repeat_tx(policy, true));
    CHECK_OK(srtp_policy_validate(policy));
    CHECK_OK(srtp_policy_set_allow_repeat_tx(policy, false));
    CHECK_OK(srtp_policy_validate(policy));

    assert_policy_creates_session(policy);
    srtp_policy_destroy(policy);
}

static void srtp_policy_set_cryptex_values_ok(void)
{
    srtp_policy_t policy;
    create_valid_policy(&policy);

    CHECK_OK(srtp_policy_set_cryptex(policy, true));
    CHECK_OK(srtp_policy_validate(policy));
    CHECK_OK(srtp_policy_set_cryptex(policy, false));
    CHECK_OK(srtp_policy_validate(policy));

    assert_policy_creates_session(policy);
    srtp_policy_destroy(policy);
}

static void srtp_policy_set_enc_hdr_xtnd_ids_boundaries(void)
{
    srtp_policy_t policy;
    uint8_t hdr_ids[SRTP_MAX_NUM_ENC_HDR_XTND_IDS] = { 0 };

    create_valid_policy(&policy);

    CHECK_OK(srtp_policy_set_enc_hdr_xtnd_ids(policy, hdr_ids, 0));
    CHECK_OK(srtp_policy_set_enc_hdr_xtnd_ids(policy, NULL, 0));
    CHECK_RETURN(srtp_policy_set_enc_hdr_xtnd_ids(policy, NULL, 1),
                 srtp_err_status_bad_param);
    CHECK_OK(srtp_policy_set_enc_hdr_xtnd_ids(policy, hdr_ids,
                                              SRTP_MAX_NUM_ENC_HDR_XTND_IDS));
    CHECK_RETURN(srtp_policy_set_enc_hdr_xtnd_ids(
                     policy, hdr_ids, SRTP_MAX_NUM_ENC_HDR_XTND_IDS + 1),
                 srtp_err_status_bad_param);
    CHECK_OK(srtp_policy_validate(policy));
    assert_policy_creates_session(policy);

    srtp_policy_destroy(policy);
}

static void srtp_policy_all_functions_null_policy(void)
{
    srtp_policy_t cloned;
    srtp_ssrc_t ssrc = { 0, 0 };
    srtp_profile_t profile;
    uint8_t key[1] = { 0x01 };
    uint8_t salt[1] = { 0x02 };
    uint8_t mki[1] = { 0x03 };
    size_t mki_len;
    uint8_t hdr_id = 1;

    CHECK_RETURN(srtp_policy_clone(NULL, &cloned), srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_validate(NULL), srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_set_ssrc(NULL, ssrc), srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_set_profile(NULL, srtp_profile_aes128_cm_sha1_80),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_get_profile(NULL, &profile),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_get_profile((srtp_policy_t)1, NULL),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_set_sec_serv(NULL, sec_serv_conf_and_auth,
                                          sec_serv_conf_and_auth),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_use_mki(NULL, sizeof(mki)),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_get_mki_length(NULL, &mki_len),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_get_mki_length((srtp_policy_t)1, NULL),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_add_key(NULL, key, sizeof(key), salt, sizeof(salt),
                                     mki, sizeof(mki)),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_add_key((srtp_policy_t)1, NULL, sizeof(key), salt,
                                     sizeof(salt), NULL, 0),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_add_key((srtp_policy_t)1, key, sizeof(key), NULL,
                                     sizeof(salt), NULL, 0),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_add_key((srtp_policy_t)1, key, sizeof(key), salt,
                                     sizeof(salt), NULL, sizeof(mki)),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_remove_keys(NULL), srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_set_window_size(NULL, 128),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_set_allow_repeat_tx(NULL, true),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_set_cryptex(NULL, true),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_set_enc_hdr_xtnd_ids(NULL, &hdr_id, 1),
                 srtp_err_status_bad_param);

    /* void API should be no-op on NULL */
    srtp_policy_destroy(NULL);
}

TEST_LIST = {
    { "srtp_policy_create_destroy_ok()", srtp_policy_create_destroy_ok },
    { "srtp_policy_create_null_fails()", srtp_policy_create_null_fails },
    { "srtp_policy_empty_not_valid()", srtp_policy_empty_not_valid },
    { "srtp_policy_minimal()", srtp_policy_minimal },
    { "srtp_policy_clone_success_and_independent()",
      srtp_policy_clone_success_and_independent },
    { "srtp_policy_clone_null_output_fails()",
      srtp_policy_clone_null_output_fails },
    { "srtp_policy_set_ssrc_invalid_type_fails()",
      srtp_policy_set_ssrc_invalid_type_fails },
    { "srtp_policy_set_get_profile_roundtrip()",
      srtp_policy_set_get_profile_roundtrip },
    { "srtp_policy_set_profile_reserved_fails()",
      srtp_policy_set_profile_reserved_fails },
    { "srtp_policy_set_sec_serv_requires_profile()",
      srtp_policy_set_sec_serv_requires_profile },
    { "srtp_policy_add_key_oversize_fails()",
      srtp_policy_add_key_oversize_fails },
    { "srtp_policy_mki_length_transitions_and_limits()",
      srtp_policy_mki_length_transitions_and_limits },
    { "srtp_policy_add_key_edges()", srtp_policy_add_key_edges },
    { "srtp_policy_add_key_mki_mismatch_fails()",
      srtp_policy_add_key_mki_mismatch_fails },
    { "srtp_policy_add_key_strict_null_checks()",
      srtp_policy_add_key_strict_null_checks },
    { "srtp_policy_add_key_max_master_keys_limit()",
      srtp_policy_add_key_max_master_keys_limit },
    { "srtp_policy_remove_keys_simple()", srtp_policy_remove_keys_simple },
    { "srtp_policy_set_window_size_invalid_values_fail()",
      srtp_policy_set_window_size_invalid_values_fail },
    { "srtp_policy_set_window_size_valid_values_ok()",
      srtp_policy_set_window_size_valid_values_ok },
    { "srtp_policy_set_allow_repeat_tx_values_ok()",
      srtp_policy_set_allow_repeat_tx_values_ok },
    { "srtp_policy_set_cryptex_values_ok()",
      srtp_policy_set_cryptex_values_ok },
    { "srtp_policy_set_enc_hdr_xtnd_ids_boundaries()",
      srtp_policy_set_enc_hdr_xtnd_ids_boundaries },
    { "srtp_policy_all_functions_null_policy()",
      srtp_policy_all_functions_null_policy },
    { 0 }
};
