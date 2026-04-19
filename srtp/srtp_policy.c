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

    if (policy->ssrc.type != ssrc_any_inbound &&
        policy->ssrc.type != ssrc_any_outbound &&
        policy->ssrc.type != ssrc_specific) {
        return srtp_err_status_bad_param;
    }

    // TODO: special case , no key required for null cipher and null auth
    // this currently short cuts the rest of validate, is that ok ?
    if (policy->rtp.cipher_type == SRTP_NULL_CIPHER &&
        policy->rtp.auth_type == SRTP_NULL_AUTH &&
        policy->rtcp.cipher_type == SRTP_NULL_CIPHER &&
        policy->rtcp.auth_type == SRTP_NULL_AUTH) {
        return srtp_err_status_ok;
    }

    if (policy->num_master_keys == 0) {
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

    for (size_t i = 0; i < policy->num_master_keys; i++) {
        if (policy->master_keys[i].key_len == 0) {
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

    if (policy->window_size != 0 &&
        (policy->window_size < 64 || policy->window_size >= 0x8000)) {
        return srtp_err_status_bad_param;
    }

    // TODO: cryptex and encrypted hdr extensions can not both be enabled

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

    // TODO: currently requires profile to be set first, is that ok ? if not,
    // how to handle ? it ges overwritten when profile is set, but that is not
    // ideal
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
    policy->master_keys[key_index].key_len += salt_len;
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

    if (window_size != 0 && (window_size < 64 || window_size >= 0x8000)) {
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

srtp_err_status_t srtp_policy_set_enc_hdr_xtnd_ids(srtp_policy_t policy,
                                                   const uint8_t *hdr_xtnd_ids,
                                                   size_t num_xtnd_ids)
{
    if (policy == NULL) {
        return srtp_err_status_bad_param;
    }

    if (num_xtnd_ids > SRTP_MAX_NUM_ENC_HDR_XTND_IDS) {
        return srtp_err_status_bad_param;
    }

    if (num_xtnd_ids > 0 && hdr_xtnd_ids == NULL) {
        return srtp_err_status_bad_param;
    }

    if (num_xtnd_ids > 0) {
        memcpy(policy->enc_xtn_hdr, hdr_xtnd_ids, num_xtnd_ids);
    }
    policy->enc_xtn_hdr_count = num_xtnd_ids;

    return srtp_err_status_ok;
}
