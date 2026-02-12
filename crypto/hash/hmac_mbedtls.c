/*
 * hmac_mbedtls.c
 *
 * Implementation of hmac srtp_auth_type_t that leverages Mbedtls
 *
 * YongCheng Yang
 */
/*
 *
 * Copyright(c) 2013-2017, Cisco Systems, Inc.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "auth.h"
#include "alloc.h"
#include "err.h" /* for srtp_debug */
#include "auth_test_cases.h"
#include <psa/crypto.h>

typedef struct {
    psa_mac_operation_t op;
    psa_key_id_t key_id;
    size_t key_len;
} psa_hmac_ctx_t;

#define SHA1_DIGEST_SIZE 20

/* the debug module for authentiation */

srtp_debug_module_t srtp_mod_hmac = {
    false,               /* debugging is off by default */
    "hmac sha-1 mbedtls" /* printable name for module   */
};

static srtp_err_status_t srtp_hmac_mbedtls_alloc(srtp_auth_t **a,
                                                 size_t key_len,
                                                 size_t out_len)
{
    extern const srtp_auth_type_t srtp_hmac;

    debug_print(srtp_mod_hmac, "allocating auth func with key length %zu",
                key_len);
    debug_print(srtp_mod_hmac, "                          tag length %zu",
                out_len);

    /* check output length - should be less than 20 bytes */
    if (out_len > SHA1_DIGEST_SIZE) {
        return srtp_err_status_bad_param;
    }

    *a = (srtp_auth_t *)srtp_crypto_alloc(sizeof(srtp_auth_t));
    if (*a == NULL) {
        return srtp_err_status_alloc_fail;
    }
    // allocate the buffer of mbedtls context.
    (*a)->state = srtp_crypto_alloc(sizeof(psa_hmac_ctx_t));

    if ((*a)->state == NULL) {
        srtp_crypto_free(*a);
        *a = NULL;
        return srtp_err_status_alloc_fail;
    }

    (((psa_hmac_ctx_t *)((*a)->state))->op) = psa_mac_operation_init();

    /* set pointers */
    (*a)->type = &srtp_hmac;
    (*a)->out_len = out_len;
    (*a)->key_len = key_len;
    (*a)->prefix_len = 0;

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_mbedtls_dealloc(srtp_auth_t *a)
{
    psa_hmac_ctx_t *hmac_ctx;
    hmac_ctx = (psa_hmac_ctx_t *)a->state;

    psa_destroy_key(hmac_ctx->key_id);
    srtp_crypto_free(hmac_ctx);
    /* zeroize entire state*/
    octet_string_set_to_zero(a, sizeof(srtp_auth_t));

    /* free memory */
    srtp_crypto_free(a);

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_mbedtls_start(void *statev)
{
    psa_hmac_ctx_t *state = (psa_hmac_ctx_t *)statev;

    if (psa_mac_abort(&state->op) != 0) {
        return srtp_err_status_auth_fail;
    }

    if (psa_mac_sign_setup(&state->op, state->key_id,
                           PSA_ALG_HMAC(PSA_ALG_SHA_1)) != 0) {
        psa_mac_abort(&state->op);
        return srtp_err_status_auth_fail;
    }

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_mbedtls_init(void *statev,
                                                const uint8_t *key,
                                                size_t key_len)
{
    psa_hmac_ctx_t *state = (psa_hmac_ctx_t *)statev;
    psa_status_t status = PSA_SUCCESS;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_1));

    status = psa_import_key(&attr, key, key_len, &state->key_id);
    state->key_len = key_len;
    if (status != PSA_SUCCESS) {
        psa_destroy_key(state->key_id);
        debug_print(srtp_mod_hmac, "mbedtls error code:  %d", status);
        return status;
    }

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_mbedtls_update(void *statev,
                                                  const uint8_t *message,
                                                  size_t msg_octets)
{
    psa_hmac_ctx_t *state = (psa_hmac_ctx_t *)statev;

    debug_print(srtp_mod_hmac, "input: %s",
                srtp_octet_string_hex_string(message, msg_octets));

    if (psa_mac_update(&state->op, message, msg_octets) != 0) {
        psa_mac_abort(&state->op);
        return srtp_err_status_auth_fail;
    }

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_mbedtls_compute(void *statev,
                                                   const uint8_t *message,
                                                   size_t msg_octets,
                                                   size_t tag_len,
                                                   uint8_t *result)
{
    psa_hmac_ctx_t *state = (psa_hmac_ctx_t *)statev;

    uint8_t hash_value[SHA1_DIGEST_SIZE];
    size_t i;

    /* check tag length, return error if we can't provide the value expected */
    if (tag_len > SHA1_DIGEST_SIZE) {
        return srtp_err_status_bad_param;
    }

    /* hash message, copy output into H */
    if (psa_mac_update(&state->op, message, msg_octets) != 0) {
        return srtp_err_status_auth_fail;
    }

    /* The `psa_mac_sign_finish` function can provide output length. I'm not
    sure if it's usable or not now I just assigne it to a local variable named
    `out_len`. I think the `out_len` must be equal to `tag_len`*/

    size_t out_len = 0;

    if (psa_mac_sign_finish(&state->op, hash_value, sizeof(hash_value),
                            &out_len) != 0) {
        psa_mac_abort(&state->op);
        return srtp_err_status_auth_fail;
    }

    /* copy hash_value to *result */
    for (i = 0; i < tag_len; i++) {
        result[i] = hash_value[i];
    }

    debug_print(srtp_mod_hmac, "output: %s",
                srtp_octet_string_hex_string(hash_value, tag_len));

    return srtp_err_status_ok;
}

/* end test case 0 */

static const char srtp_hmac_mbedtls_description[] =
    "hmac sha-1 authentication function using mbedtls";

/*
 * srtp_auth_type_t hmac is the hmac metaobject
 */

const srtp_auth_type_t srtp_hmac = {
    srtp_hmac_mbedtls_alloc,       /* */
    srtp_hmac_mbedtls_dealloc,     /* */
    srtp_hmac_mbedtls_init,        /* */
    srtp_hmac_mbedtls_compute,     /* */
    srtp_hmac_mbedtls_update,      /* */
    srtp_hmac_mbedtls_start,       /* */
    srtp_hmac_mbedtls_description, /* */
    &srtp_hmac_test_case_0,        /* */
    SRTP_HMAC_SHA1                 /* */
};
