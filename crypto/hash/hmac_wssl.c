/*
 * hmac_wssl.c
 *
 * Implementation of hmac srtp_auth_type_t that uses wolfSSL
 *
 * Sean Parkinson, wolfSSL
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
#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include "auth.h"
#include "alloc.h"
#include "err.h" /* for srtp_debug */
#include "auth_test_cases.h"

#define SHA1_DIGEST_SIZE 20

/* the debug module for authentiation */

srtp_debug_module_t srtp_mod_hmac = {
    0,                /* debugging is off by default */
    "hmac sha-1 wssl" /* printable name for module   */
};

static srtp_err_status_t srtp_hmac_wolfssl_alloc(srtp_auth_t **a,
                                                 size_t key_len,
                                                 size_t out_len)
{
    extern const srtp_auth_type_t srtp_hmac;
    int err;

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
    // allocate the buffer of wolfssl context.
    (*a)->state = srtp_crypto_alloc(sizeof(Hmac));
    if ((*a)->state == NULL) {
        srtp_crypto_free(*a);
        *a = NULL;
        return srtp_err_status_alloc_fail;
    }
    err = wc_HmacInit((Hmac *)(*a)->state, NULL, INVALID_DEVID);
    if (err < 0) {
        srtp_crypto_free((*a)->state);
        srtp_crypto_free(*a);
        *a = NULL;
        debug_print(srtp_mod_hmac, "wolfSSL error code: %d", err);
        return srtp_err_status_init_fail;
    }

    /* set pointers */
    (*a)->type = &srtp_hmac;
    (*a)->out_len = out_len;
    (*a)->key_len = key_len;
    (*a)->prefix_len = 0;

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_wolfssl_dealloc(srtp_auth_t *a)
{
    wc_HmacFree((Hmac *)a->state);
    srtp_crypto_free(a->state);
    /* zeroize entire state*/
    octet_string_set_to_zero(a, sizeof(srtp_auth_t));

    /* free memory */
    srtp_crypto_free(a);

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_wolfssl_start(void *statev)
{
    (void)statev;
    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_wolfssl_init(void *statev,
                                                const uint8_t *key,
                                                size_t key_len)
{
    Hmac *state = (Hmac *)statev;
    int err;

    err = wc_HmacSetKey(state, WC_SHA, key, key_len);
    if (err < 0) {
        debug_print(srtp_mod_hmac, "wolfSSL error code: %d", err);
        return srtp_err_status_auth_fail;
    }

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_wolfssl_update(void *statev,
                                                  const uint8_t *message,
                                                  size_t msg_octets)
{
    Hmac *state = (Hmac *)statev;
    int err;

    debug_print(srtp_mod_hmac, "input: %s",
                srtp_octet_string_hex_string(message, msg_octets));

    err = wc_HmacUpdate(state, message, msg_octets);
    if (err < 0) {
        debug_print(srtp_mod_hmac, "wolfSSL error code: %d", err);
        return srtp_err_status_auth_fail;
    }

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_wolfssl_compute(void *statev,
                                                   const uint8_t *message,
                                                   size_t msg_octets,
                                                   size_t tag_len,
                                                   uint8_t *result)
{
    Hmac *state = (Hmac *)statev;
    uint8_t hash_value[WC_SHA_DIGEST_SIZE];
    int err;
    int i;

    debug_print(srtp_mod_hmac, "input: %s",
                srtp_octet_string_hex_string(message, msg_octets));

    /* check tag length, return error if we can't provide the value expected */
    if (tag_len > WC_SHA_DIGEST_SIZE) {
        return srtp_err_status_bad_param;
    }

    /* hash message, copy output into H */
    err = wc_HmacUpdate(state, message, msg_octets);
    if (err < 0) {
        debug_print(srtp_mod_hmac, "wolfSSL error code: %d", err);
        return srtp_err_status_auth_fail;
    }

    err = wc_HmacFinal(state, hash_value);
    if (err < 0) {
        debug_print(srtp_mod_hmac, "wolfSSL error code: %d", err);
        return srtp_err_status_auth_fail;
    }

    /* copy hash_value to *result */
    for (i = 0; i < (int)tag_len; i++) {
        result[i] = hash_value[i];
    }

    debug_print(srtp_mod_hmac, "output: %s",
                srtp_octet_string_hex_string(hash_value, tag_len));

    return srtp_err_status_ok;
}

/* end test case 0 */

static const char srtp_hmac_wolfssl_description[] =
    "hmac sha-1 authentication function using wolfSSL";

/*
 * srtp_auth_type_t hmac is the hmac metaobject
 */

const srtp_auth_type_t srtp_hmac = {
    srtp_hmac_wolfssl_alloc,       /* */
    srtp_hmac_wolfssl_dealloc,     /* */
    srtp_hmac_wolfssl_init,        /* */
    srtp_hmac_wolfssl_compute,     /* */
    srtp_hmac_wolfssl_update,      /* */
    srtp_hmac_wolfssl_start,       /* */
    srtp_hmac_wolfssl_description, /* */
    &srtp_hmac_test_case_0,        /* */
    SRTP_HMAC_SHA1                 /* */
};
