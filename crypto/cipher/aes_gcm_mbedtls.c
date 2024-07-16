/*
 * aes_gcm_mbedtls.c
 *
 * AES Galois Counter Mode
 *
 * YongCheng Yang
 *
 */

/*
 *
 * Copyright (c) 2013-2017, Cisco Systems, Inc.
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
#include <mbedtls/gcm.h>
#include "aes_gcm.h"
#include "alloc.h"
#include "err.h" /* for srtp_debug */
#include "crypto_types.h"
#include "cipher_types.h"
#include "cipher_test_cases.h"

srtp_debug_module_t srtp_mod_aes_gcm = {
    false,            /* debugging is off by default */
    "aes gcm mbedtls" /* printable module name       */
};

/**
 * SRTP IV Formation for AES-GCM
 * https://tools.ietf.org/html/rfc7714#section-8.1
 *   0  0  0  0  0  0  0  0  0  0  1  1
 *   0  1  2  3  4  5  6  7  8  9  0  1
 *  +--+--+--+--+--+--+--+--+--+--+--+--+
 *  |00|00| SSRC      | ROC       | SEQ |---+
 *  +--+--+--+--+--+--+--+--+--+--+--+--+   |
 *  |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+   |
 *  | Encryption Salt                   |->(+)
 *  +--+--+--+--+--+--+--+--+--+--+--+--+   |
 *                                          |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+   |
 *  | Initialization Vector             |<--+
 *  +--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * SRTCP IV Formation for AES-GCM
 * https://tools.ietf.org/html/rfc7714#section-9.1
 *
 */

/*
 * For now we only support 8 and 16 octet tags.  The spec allows for
 * optional 12 byte tag, which may be supported in the future.
 */
#define GCM_IV_LEN 12
#define GCM_AUTH_TAG_LEN 16
#define GCM_AUTH_TAG_LEN_8 8

#define FUNC_ENTRY() debug_print(srtp_mod_aes_gcm, "%s entry", __func__);

/*
 * static function declarations.
 */
static srtp_err_status_t srtp_aes_gcm_mbedtls_alloc(srtp_cipher_t **c,
                                                    size_t key_len,
                                                    size_t tlen);

static srtp_err_status_t srtp_aes_gcm_mbedtls_dealloc(srtp_cipher_t *c);

static srtp_err_status_t srtp_aes_gcm_mbedtls_context_init(void *cv,
                                                           const uint8_t *key);

static srtp_err_status_t srtp_aes_gcm_mbedtls_set_iv(
    void *cv,
    uint8_t *iv,
    srtp_cipher_direction_t direction);

static srtp_err_status_t srtp_aes_gcm_mbedtls_set_aad(void *cv,
                                                      const uint8_t *aad,
                                                      size_t aad_len);

static srtp_err_status_t srtp_aes_gcm_mbedtls_encrypt(void *cv,
                                                      const uint8_t *src,
                                                      size_t src_len,
                                                      uint8_t *dst,
                                                      size_t *dst_len);

static srtp_err_status_t srtp_aes_gcm_mbedtls_decrypt(void *cv,
                                                      const uint8_t *src,
                                                      size_t src_len,
                                                      uint8_t *dst,
                                                      size_t *dst_len);

/*
 * Name of this crypto engine
 */
static const char srtp_aes_gcm_128_mbedtls_description[] =
    "AES-128 GCM using mbedtls";
static const char srtp_aes_gcm_256_mbedtls_description[] =
    "AES-256 GCM using mbedtls";

/*
 * This is the vector function table for this crypto engine.
 */
/* clang-format off */
const srtp_cipher_type_t srtp_aes_gcm_128 = {
    srtp_aes_gcm_mbedtls_alloc,
    srtp_aes_gcm_mbedtls_dealloc,
    srtp_aes_gcm_mbedtls_context_init,
    srtp_aes_gcm_mbedtls_set_aad,
    srtp_aes_gcm_mbedtls_encrypt,
    srtp_aes_gcm_mbedtls_decrypt,
    srtp_aes_gcm_mbedtls_set_iv,
    srtp_aes_gcm_128_mbedtls_description,
    &srtp_aes_gcm_128_test_case_0,
    SRTP_AES_GCM_128
};
/* clang-format on */

/*
 * This is the vector function table for this crypto engine.
 */
/* clang-format off */
const srtp_cipher_type_t srtp_aes_gcm_256 = {
    srtp_aes_gcm_mbedtls_alloc,
    srtp_aes_gcm_mbedtls_dealloc,
    srtp_aes_gcm_mbedtls_context_init,
    srtp_aes_gcm_mbedtls_set_aad,
    srtp_aes_gcm_mbedtls_encrypt,
    srtp_aes_gcm_mbedtls_decrypt,
    srtp_aes_gcm_mbedtls_set_iv,
    srtp_aes_gcm_256_mbedtls_description,
    &srtp_aes_gcm_256_test_case_0,
    SRTP_AES_GCM_256
};
/* clang-format on */

/*
 * This function allocates a new instance of this crypto engine.
 * The key_len parameter should be one of 28 or 44 for
 * AES-128-GCM or AES-256-GCM respectively.  Note that the
 * key length includes the 14 byte salt value that is used when
 * initializing the KDF.
 */
static srtp_err_status_t srtp_aes_gcm_mbedtls_alloc(srtp_cipher_t **c,
                                                    size_t key_len,
                                                    size_t tlen)
{
    FUNC_ENTRY();
    srtp_aes_gcm_ctx_t *gcm;

    debug_print(srtp_mod_aes_gcm, "allocating cipher with key length %zu",
                key_len);
    debug_print(srtp_mod_aes_gcm, "allocating cipher with tag length %zu",
                tlen);

    /*
     * Verify the key_len is valid for one of: AES-128/256
     */
    if (key_len != SRTP_AES_GCM_128_KEY_LEN_WSALT &&
        key_len != SRTP_AES_GCM_256_KEY_LEN_WSALT) {
        return (srtp_err_status_bad_param);
    }

    if (tlen != GCM_AUTH_TAG_LEN && tlen != GCM_AUTH_TAG_LEN_8) {
        return (srtp_err_status_bad_param);
    }

    /* allocate memory a cipher of type aes_gcm */
    *c = (srtp_cipher_t *)srtp_crypto_alloc(sizeof(srtp_cipher_t));
    if (*c == NULL) {
        return (srtp_err_status_alloc_fail);
    }

    gcm = (srtp_aes_gcm_ctx_t *)srtp_crypto_alloc(sizeof(srtp_aes_gcm_ctx_t));
    if (gcm == NULL) {
        srtp_crypto_free(*c);
        *c = NULL;
        return (srtp_err_status_alloc_fail);
    }

    gcm->ctx =
        (mbedtls_gcm_context *)srtp_crypto_alloc(sizeof(mbedtls_gcm_context));
    if (gcm->ctx == NULL) {
        srtp_crypto_free(gcm);
        srtp_crypto_free(*c);
        *c = NULL;
        return srtp_err_status_alloc_fail;
    }
    mbedtls_gcm_init(gcm->ctx);

    /* set pointers */
    (*c)->state = gcm;

    /* setup cipher attributes */
    switch (key_len) {
    case SRTP_AES_GCM_128_KEY_LEN_WSALT:
        (*c)->type = &srtp_aes_gcm_128;
        (*c)->algorithm = SRTP_AES_GCM_128;
        gcm->key_size = SRTP_AES_128_KEY_LEN;
        gcm->tag_len = tlen;
        break;
    case SRTP_AES_GCM_256_KEY_LEN_WSALT:
        (*c)->type = &srtp_aes_gcm_256;
        (*c)->algorithm = SRTP_AES_GCM_256;
        gcm->key_size = SRTP_AES_256_KEY_LEN;
        gcm->tag_len = tlen;
        break;
    }

    /* set key size        */
    (*c)->key_len = key_len;

    return (srtp_err_status_ok);
}

/*
 * This function deallocates a GCM session
 */
static srtp_err_status_t srtp_aes_gcm_mbedtls_dealloc(srtp_cipher_t *c)
{
    srtp_aes_gcm_ctx_t *ctx;
    FUNC_ENTRY();
    ctx = (srtp_aes_gcm_ctx_t *)c->state;
    if (ctx) {
        mbedtls_gcm_free(ctx->ctx);
        srtp_crypto_free(ctx->ctx);
        /* zeroize the key material */
        octet_string_set_to_zero(ctx, sizeof(srtp_aes_gcm_ctx_t));
        srtp_crypto_free(ctx);
    }

    /* free memory */
    srtp_crypto_free(c);

    return (srtp_err_status_ok);
}

static srtp_err_status_t srtp_aes_gcm_mbedtls_context_init(void *cv,
                                                           const uint8_t *key)
{
    FUNC_ENTRY();
    srtp_aes_gcm_ctx_t *c = (srtp_aes_gcm_ctx_t *)cv;
    uint32_t key_len_in_bits;
    int errCode = 0;
    c->dir = srtp_direction_any;
    c->aad_size = 0;

    debug_print(srtp_mod_aes_gcm, "key:  %s",
                srtp_octet_string_hex_string(key, c->key_size));
    key_len_in_bits = (c->key_size << 3);
    switch (c->key_size) {
    case SRTP_AES_256_KEY_LEN:
    case SRTP_AES_128_KEY_LEN:
        break;
    default:
        return (srtp_err_status_bad_param);
        break;
    }

    errCode =
        mbedtls_gcm_setkey(c->ctx, MBEDTLS_CIPHER_ID_AES, key, key_len_in_bits);
    if (errCode != 0) {
        debug_print(srtp_mod_aes_gcm, "mbedtls error code:  %d", errCode);
        return srtp_err_status_init_fail;
    }

    return (srtp_err_status_ok);
}

static srtp_err_status_t srtp_aes_gcm_mbedtls_set_iv(
    void *cv,
    uint8_t *iv,
    srtp_cipher_direction_t direction)
{
    FUNC_ENTRY();
    srtp_aes_gcm_ctx_t *c = (srtp_aes_gcm_ctx_t *)cv;

    if (direction != srtp_direction_encrypt &&
        direction != srtp_direction_decrypt) {
        return (srtp_err_status_bad_param);
    }
    c->dir = direction;

    debug_print(srtp_mod_aes_gcm, "setting iv: %s",
                srtp_octet_string_hex_string(iv, GCM_IV_LEN));
    c->iv_len = GCM_IV_LEN;
    memcpy(c->iv, iv, c->iv_len);
    return (srtp_err_status_ok);
}

/*
 * This function processes the AAD
 *
 * Parameters:
 *	c	Crypto context
 *	aad	Additional data to process for AEAD cipher suites
 *	aad_len	length of aad buffer
 */
static srtp_err_status_t srtp_aes_gcm_mbedtls_set_aad(void *cv,
                                                      const uint8_t *aad,
                                                      size_t aad_len)
{
    FUNC_ENTRY();
    srtp_aes_gcm_ctx_t *c = (srtp_aes_gcm_ctx_t *)cv;

    debug_print(srtp_mod_aes_gcm, "setting AAD: %s",
                srtp_octet_string_hex_string(aad, aad_len));

    if (aad_len + c->aad_size > MAX_AD_SIZE) {
        return srtp_err_status_bad_param;
    }

    memcpy(c->aad + c->aad_size, aad, aad_len);
    c->aad_size += aad_len;

    return (srtp_err_status_ok);
}

/*
 * This function encrypts a buffer using AES GCM mode
 *
 * Parameters:
 *	c	Crypto context
 *	buf	data to encrypt
 *	enc_len	length of encrypt buffer
 */
static srtp_err_status_t srtp_aes_gcm_mbedtls_encrypt(void *cv,
                                                      const uint8_t *src,
                                                      size_t src_len,
                                                      uint8_t *dst,
                                                      size_t *dst_len)
{
    FUNC_ENTRY();
    srtp_aes_gcm_ctx_t *c = (srtp_aes_gcm_ctx_t *)cv;
    int errCode = 0;

    if (c->dir != srtp_direction_encrypt) {
        return srtp_err_status_bad_param;
    }

    if (*dst_len < src_len + c->tag_len) {
        return srtp_err_status_buffer_small;
    }

    errCode = mbedtls_gcm_crypt_and_tag(c->ctx, MBEDTLS_GCM_ENCRYPT, src_len,
                                        c->iv, c->iv_len, c->aad, c->aad_size,
                                        src, dst, c->tag_len, dst + src_len);

    c->aad_size = 0;
    if (errCode != 0) {
        debug_print(srtp_mod_aes_gcm, "mbedtls error code:  %d", errCode);
        return srtp_err_status_bad_param;
    }

    *dst_len = src_len + c->tag_len;

    return srtp_err_status_ok;
}

/*
 * This function decrypts a buffer using AES GCM mode
 *
 * Parameters:
 *	c	Crypto context
 *	buf	data to encrypt
 *	enc_len	length of encrypt buffer
 */
static srtp_err_status_t srtp_aes_gcm_mbedtls_decrypt(void *cv,
                                                      const uint8_t *src,
                                                      size_t src_len,
                                                      uint8_t *dst,
                                                      size_t *dst_len)
{
    FUNC_ENTRY();
    srtp_aes_gcm_ctx_t *c = (srtp_aes_gcm_ctx_t *)cv;
    int errCode = 0;

    if (c->dir != srtp_direction_decrypt) {
        return srtp_err_status_bad_param;
    }

    if (src_len < c->tag_len) {
        return srtp_err_status_bad_param;
    }

    if (*dst_len < (src_len - c->tag_len)) {
        return srtp_err_status_buffer_small;
    }

    debug_print(srtp_mod_aes_gcm, "AAD: %s",
                srtp_octet_string_hex_string(c->aad, c->aad_size));

    errCode = mbedtls_gcm_auth_decrypt(
        c->ctx, (src_len - c->tag_len), c->iv, c->iv_len, c->aad, c->aad_size,
        src + (src_len - c->tag_len), c->tag_len, src, dst);
    c->aad_size = 0;
    if (errCode != 0) {
        return srtp_err_status_auth_fail;
    }

    /*
     * Reduce the buffer size by the tag length since the tag
     * is not part of the original payload
     */
    *dst_len = (src_len - c->tag_len);

    return srtp_err_status_ok;
}
