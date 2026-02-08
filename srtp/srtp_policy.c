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

srtp_err_status_t srtp_policy2_create(srtp_policy2_t *policy)
{
    srtp_policy2_t p;

    if (policy == NULL) {
        return srtp_err_status_bad_param;
    }

    p = (srtp_policy2_t)srtp_crypto_alloc(sizeof(*p));
    if (p == NULL) {
        *policy = NULL;
        return srtp_err_status_alloc_fail;
    }

    memset(p, 0, sizeof(*p));

    // set up key store
    for (size_t i = 0; i < SRTP_MAX_NUM_MASTER_KEYS; i++) {
        p->master_keys[i].key = p->master_key_store[i].key;
        p->master_keys[i].mki_id = p->master_key_store[i].mki_id;
        p->keys[i] = &p->master_keys[i];
    }
    p->legacy.keys = p->keys;

    // setup hdr xtnd id's
    p->legacy.enc_xtn_hdr = p->enc_hdr_xtnd_ids;

    *policy = p;

    return srtp_err_status_ok;
}

void srtp_policy2_destroy(srtp_policy2_t policy)
{
    if (policy == NULL) {
        return;
    }

    octet_string_set_to_zero(policy->keys, sizeof(policy->keys));
    srtp_crypto_free(policy);
}

srtp_err_status_t srtp_policy2_validate(srtp_policy2_t policy)
{
    if (policy == NULL) {
        return srtp_err_status_bad_param;
    }

    if (policy->legacy.ssrc.type != ssrc_any_inbound &&
        policy->legacy.ssrc.type != ssrc_any_outbound &&
        policy->legacy.ssrc.type != ssrc_specific) {
        return srtp_err_status_bad_param;
    }

    if (policy->profile == srtp_profile_reserved) {
        return srtp_err_status_bad_param;
    }

    return srtp_valid_policy(&policy->legacy);
}

srtp_err_status_t srtp_policy2_set_ssrc(srtp_policy2_t policy, srtp_ssrc_t ssrc)
{
    if (policy == NULL) {
        return srtp_err_status_bad_param;
    }

    if (ssrc.type != ssrc_any_inbound && ssrc.type != ssrc_any_outbound &&
        ssrc.type != ssrc_specific) {
        return srtp_err_status_bad_param;
    }

    policy->legacy.ssrc = ssrc;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_policy2_set_profile(srtp_policy2_t policy,
                                           srtp_profile_t profile)
{
    if (policy == NULL) {
        return srtp_err_status_bad_param;
    }

    srtp_err_status_t status;
    status = srtp_crypto_policy_set_from_profile_for_rtp(&policy->legacy.rtp,
                                                         profile);
    if (status != srtp_err_status_ok) {
        return status;
    }
    status = srtp_crypto_policy_set_from_profile_for_rtcp(&policy->legacy.rtcp,
                                                          profile);
    if (status != srtp_err_status_ok) {
        return status;
    }

    policy->profile = profile;

    return srtp_err_status_ok;
}

static srtp_err_status_t policy2_add_key(srtp_policy2_t policy,
                                         const uint8_t *key,
                                         size_t key_len,
                                         const uint8_t *salt,
                                         size_t salt_len,
                                         const uint8_t *mki,
                                         size_t mki_len)
{
    if (policy->legacy.num_master_keys >= SRTP_MAX_NUM_MASTER_KEYS) {
        return srtp_err_status_bad_param;
    }

    if (key_len + salt_len > SRTP_MAX_KEY_LEN) {
        return srtp_err_status_bad_param;
    }

    size_t key_index = policy->legacy.num_master_keys;
    memcpy(policy->master_key_store[key_index].key, key, key_len);
    memcpy(policy->master_key_store[key_index].key + key_len, salt, salt_len);
    policy->master_key_store[key_index].key_len = key_len + salt_len;
    memcpy(policy->master_key_store[key_index].mki_id, mki, mki_len);
    policy->master_key_store[key_index].mki_id_len = mki_len;

    policy->legacy.num_master_keys++;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_policy2_set_key(srtp_policy2_t policy,
                                       const uint8_t *key,
                                       size_t key_len,
                                       const uint8_t *salt,
                                       size_t salt_len)
{
    if (policy == NULL) {
        return srtp_err_status_bad_param;
    }

    if (policy->legacy.num_master_keys != 0) {
        return srtp_err_status_bad_param;
    }

    if (key_len + salt_len > SRTP_MAX_KEY_LEN) {
        return srtp_err_status_bad_param;
    }

    policy->legacy.use_mki = false;
    policy->legacy.mki_size = 0;

    return policy2_add_key(policy, key, key_len, salt, salt_len, NULL, 0);
}

srtp_err_status_t srtp_policy2_use_mki(srtp_policy2_t policy, size_t mki_len)
{
    if (policy == NULL) {
        return srtp_err_status_bad_param;
    }

    if (mki_len > SRTP_MAX_MKI_LEN) {
        return srtp_err_status_bad_param;
    }

    policy->legacy.use_mki = true;
    policy->legacy.mki_size = mki_len;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_policy2_add_key(srtp_policy2_t policy,
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

    if (!policy->legacy.use_mki) {
        return srtp_err_status_bad_param;
    }

    return policy2_add_key(policy, key, key_len, salt, salt_len, mki, mki_len);
}

srtp_err_status_t srtp_create2(srtp_t *session, const srtp_policy2_t policy)
{
    return srtp_create(session, policy ? &policy->legacy : NULL);
}
