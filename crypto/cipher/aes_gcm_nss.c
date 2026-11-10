/*
 * aes_gcm_nss.c
 *
 * AES Galois Counter Mode
 *
 * Richard L. Barnes
 * Cisco Systems, Inc.
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

#include "aes_gcm.h"
#include "alloc.h"
#include "err.h" /* for srtp_debug */
#include "crypto_types.h"
#include "cipher_types.h"
#include "cipher_test_cases.h"
#include <secerr.h>
#include <nspr.h>
#include "nss_fips.h"
#include <limits.h>

srtp_debug_module_t srtp_mod_aes_gcm = {
    false,        /* debugging is off by default */
    "aes gcm nss" /* printable module name       */
};

/*
 * For now we only support 8 and 16 octet tags.  The spec allows for
 * optional 12 byte tag, which may be supported in the future.
 */
#define GCM_IV_LEN 12
#define GCM_AUTH_TAG_LEN 16
#define GCM_AUTH_TAG_LEN_8 8

/*
 * This function allocates a new instance of this crypto engine.
 * The key_len parameter should be one of 28 or 44 for
 * AES-128-GCM or AES-256-GCM respectively.  Note that the
 * key length includes the 14 byte salt value that is used when
 * initializing the KDF.
 */
static srtp_err_status_t srtp_aes_gcm_nss_alloc(srtp_cipher_t **c,
                                                size_t key_len,
                                                size_t tlen)
{
    srtp_aes_gcm_ctx_t *gcm;
    NSSInitContext *nss;

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

    /* Initialize NSS equiv of NSS_NoDB_Init(NULL) */
    nss = NSS_InitContext("", "", "", "", NULL,
                          NSS_INIT_READONLY | NSS_INIT_NOCERTDB |
                              NSS_INIT_NOMODDB | NSS_INIT_FORCEOPEN |
                              NSS_INIT_OPTIMIZESPACE);
    if (!nss) {
        return (srtp_err_status_cipher_fail);
    }

    /* allocate memory a cipher of type aes_gcm */
    *c = (srtp_cipher_t *)srtp_crypto_alloc(sizeof(srtp_cipher_t));
    if (*c == NULL) {
        NSS_ShutdownContext(nss);
        return (srtp_err_status_alloc_fail);
    }

    gcm = (srtp_aes_gcm_ctx_t *)srtp_crypto_alloc(sizeof(srtp_aes_gcm_ctx_t));
    if (gcm == NULL) {
        NSS_ShutdownContext(nss);
        srtp_crypto_free(*c);
        *c = NULL;
        return (srtp_err_status_alloc_fail);
    }

    gcm->nss = nss;

    /* set pointers */
    (*c)->state = gcm;

    /* setup cipher attributes */
    switch (key_len) {
    case SRTP_AES_GCM_128_KEY_LEN_WSALT:
        (*c)->type = &srtp_aes_gcm_128;
        (*c)->algorithm = SRTP_AES_GCM_128;
        gcm->key_size = SRTP_AES_128_KEY_LEN;
        gcm->tag_size = tlen;
        break;
    case SRTP_AES_GCM_256_KEY_LEN_WSALT:
        (*c)->type = &srtp_aes_gcm_256;
        (*c)->algorithm = SRTP_AES_GCM_256;
        gcm->key_size = SRTP_AES_256_KEY_LEN;
        gcm->tag_size = tlen;
        break;
    default:
        /* this should never hit, but to be sure... */
        return (srtp_err_status_bad_param);
    }

    /* set key size and tag size*/
    (*c)->key_len = key_len;

    return (srtp_err_status_ok);
}

/*
 * This function deallocates a GCM session
 */
static srtp_err_status_t srtp_aes_gcm_nss_dealloc(srtp_cipher_t *c)
{
    srtp_aes_gcm_ctx_t *ctx;

    ctx = (srtp_aes_gcm_ctx_t *)c->state;
    if (ctx) {
        /* release NSS resources */
        if (ctx->key) {
            PK11_FreeSymKey(ctx->key);
        }

        if (ctx->nss) {
            NSS_ShutdownContext(ctx->nss);
            ctx->nss = NULL;
        }

        /* zeroize the key material */
        octet_string_set_to_zero(ctx, sizeof(srtp_aes_gcm_ctx_t));
        srtp_crypto_free(ctx);
    }

    /* free memory */
    srtp_crypto_free(c);

    return (srtp_err_status_ok);
}

/*
 * aes_gcm_nss_context_init(...) initializes the aes_gcm_context
 * using the value in key[].
 *
 * the key is the secret key
 */
static srtp_err_status_t srtp_aes_gcm_nss_context_init(void *cv,
                                                       const uint8_t *key)
{
    srtp_aes_gcm_ctx_t *c = (srtp_aes_gcm_ctx_t *)cv;

    c->dir = srtp_direction_any;

    debug_print(srtp_mod_aes_gcm, "key:  %s",
                srtp_octet_string_hex_string(key, c->key_size));

    if (c->key) {
        PK11_FreeSymKey(c->key);
        c->key = NULL;
    }

    PK11SlotInfo *slot = PK11_GetBestSlot(CKM_AES_GCM, NULL);
    if (!slot) {
        return (srtp_err_status_cipher_fail);
    }

    /* explicitly cast away const of key */
    SECItem key_item = { siBuffer, (unsigned char *)(uintptr_t)key,
                         (unsigned)c->key_size };
    if (PK11_IsFIPS()) {
        /*
         * Note: the caller is now responsible for the proper FIPS usage of the
         * key material!
         */
        c->key = import_sym_key_in_FIPS(slot, CKM_AES_GCM, CKA_ENCRYPT,
                                        &key_item, CKF_ENCRYPT | CKF_DECRYPT);
    } else {
        c->key = PK11_ImportSymKeyWithFlags(
            slot, CKM_AES_GCM, PK11_OriginUnwrap, CKA_ENCRYPT, &key_item,
            CKF_ENCRYPT | CKF_DECRYPT, PR_FALSE, NULL);
    }
    PK11_FreeSlot(slot);

    if (!c->key) {
        return (srtp_err_status_cipher_fail);
    }

    return (srtp_err_status_ok);
}

/*
 * aes_gcm_nss_set_iv(c, iv) sets the counter value to the exor of iv with
 * the offset
 */
static srtp_err_status_t srtp_aes_gcm_nss_set_iv(
    void *cv,
    uint8_t *iv,
    srtp_cipher_direction_t direction)
{
    srtp_aes_gcm_ctx_t *c = (srtp_aes_gcm_ctx_t *)cv;

    if (direction != srtp_direction_encrypt &&
        direction != srtp_direction_decrypt) {
        return (srtp_err_status_bad_param);
    }
    c->dir = direction;

    debug_print(srtp_mod_aes_gcm, "setting iv: %s",
                srtp_octet_string_hex_string(iv, GCM_IV_LEN));

    memcpy(c->iv, iv, GCM_IV_LEN);

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
static srtp_err_status_t srtp_aes_gcm_nss_set_aad(void *cv,
                                                  const uint8_t *aad,
                                                  size_t aad_len)
{
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

static srtp_err_status_t srtp_aes_gcm_nss_do_crypto(void *cv,
                                                    bool encrypt,
                                                    const uint8_t *src,
                                                    size_t src_len,
                                                    uint8_t *dst,
                                                    size_t *dst_len)
{
    srtp_aes_gcm_ctx_t *c = (srtp_aes_gcm_ctx_t *)cv;
    size_t aad_size = c->aad_size;

    /* The length is copied into the AEAD call below. */
    c->aad_size = 0;

    if (src_len > INT_MAX || *dst_len > INT_MAX || aad_size > INT_MAX) {
        return srtp_err_status_bad_param;
    }

    unsigned char *tag;
    int in_len;
    int maxout;
    CK_ATTRIBUTE_TYPE op;

    if (encrypt) {
        if (c->dir != srtp_direction_encrypt) {
            return srtp_err_status_bad_param;
        }

        if (*dst_len < src_len + c->tag_size) {
            return srtp_err_status_buffer_small;
        }

        tag = dst + src_len;
        in_len = (int)src_len;
        maxout = (int)src_len;
        op = CKA_NSS_MESSAGE | CKA_ENCRYPT;
    } else {
        if (c->dir != srtp_direction_decrypt) {
            return srtp_err_status_bad_param;
        }

        if (src_len < c->tag_size) {
            return srtp_err_status_bad_param;
        }

        if (*dst_len < src_len - c->tag_size) {
            return srtp_err_status_buffer_small;
        }

        in_len = (int)(src_len - c->tag_size);
        /* PK11_AEADOp writes the tag only when encrypting. */
        tag = (unsigned char *)(uintptr_t)(src + in_len);
        maxout = (int)*dst_len;
        op = CKA_NSS_MESSAGE | CKA_DECRYPT;
    }

    SECItem empty = { siBuffer, NULL, 0 };
    PK11Context *ctx =
        PK11_CreateContextBySymKey(CKM_AES_GCM, op, c->key, &empty);
    if (!ctx) {
        return srtp_err_status_cipher_fail;
    }

    int out_len = 0;
    const unsigned char *aad = aad_size > 0 ? c->aad : NULL;
    SECStatus rv = PK11_AEADOp(ctx, CKG_NO_GENERATE, 0, c->iv, GCM_IV_LEN, aad,
                               (int)aad_size, dst, &out_len, maxout, tag,
                               (int)c->tag_size, src, in_len);
    PRErrorCode saved_error = 0;
    if (rv != SECSuccess) {
        saved_error = PR_GetError();
    }
    PK11_DestroyContext(ctx, PR_TRUE);
    if (rv != SECSuccess) {
        PR_SetError(saved_error, 0);
        return srtp_err_status_cipher_fail;
    }

    if (encrypt) {
        *dst_len = (size_t)out_len + c->tag_size;
    } else {
        *dst_len = (size_t)out_len;
    }

    return srtp_err_status_ok;
}

/*
 * This function encrypts a buffer using AES GCM mode
 *
 * Parameters:
 *	c	Crypto context
 *	buf	data to encrypt
 *	enc_len	length of encrypt buffer
 */
static srtp_err_status_t srtp_aes_gcm_nss_encrypt(void *cv,
                                                  const uint8_t *src,
                                                  size_t src_len,
                                                  uint8_t *dst,
                                                  size_t *dst_len)
{
    return srtp_aes_gcm_nss_do_crypto(cv, true, src, src_len, dst, dst_len);
}

/*
 * This function decrypts a buffer using AES GCM mode
 *
 * Parameters:
 *	c	Crypto context
 *	buf	data to encrypt
 *	enc_len	length of encrypt buffer
 */
static srtp_err_status_t srtp_aes_gcm_nss_decrypt(void *cv,
                                                  const uint8_t *src,
                                                  size_t src_len,
                                                  uint8_t *dst,
                                                  size_t *dst_len)
{
    uint8_t tagbuf[16];
    uint8_t *non_null_dst_buf = dst;
    if (!non_null_dst_buf && (*dst_len == 0)) {
        non_null_dst_buf = tagbuf;
        *dst_len = sizeof(tagbuf);
    } else if (!non_null_dst_buf) {
        return srtp_err_status_bad_param;
    }

    srtp_err_status_t status = srtp_aes_gcm_nss_do_crypto(
        cv, false, src, src_len, non_null_dst_buf, dst_len);
    if (status != srtp_err_status_ok) {
        int err = PR_GetError();
        if (err == SEC_ERROR_BAD_DATA) {
            status = srtp_err_status_auth_fail;
        }
    }

    return status;
}

/*
 * Name of this crypto engine
 */
static const char srtp_aes_gcm_128_nss_description[] = "AES-128 GCM using NSS";
static const char srtp_aes_gcm_256_nss_description[] = "AES-256 GCM using NSS";

/*
 * This is the vector function table for this crypto engine.
 */
/* clang-format off */
const srtp_cipher_type_t srtp_aes_gcm_128 = {
    srtp_aes_gcm_nss_alloc,
    srtp_aes_gcm_nss_dealloc,
    srtp_aes_gcm_nss_context_init,
    srtp_aes_gcm_nss_set_aad,
    srtp_aes_gcm_nss_encrypt,
    srtp_aes_gcm_nss_decrypt,
    srtp_aes_gcm_nss_set_iv,
    srtp_aes_gcm_128_nss_description,
    &srtp_aes_gcm_128_test_case_0,
    SRTP_AES_GCM_128
};
/* clang-format on */

/*
 * This is the vector function table for this crypto engine.
 */
/* clang-format off */
const srtp_cipher_type_t srtp_aes_gcm_256 = {
    srtp_aes_gcm_nss_alloc,
    srtp_aes_gcm_nss_dealloc,
    srtp_aes_gcm_nss_context_init,
    srtp_aes_gcm_nss_set_aad,
    srtp_aes_gcm_nss_encrypt,
    srtp_aes_gcm_nss_decrypt,
    srtp_aes_gcm_nss_set_iv,
    srtp_aes_gcm_256_nss_description,
    &srtp_aes_gcm_256_test_case_0,
    SRTP_AES_GCM_256
};
/* clang-format on */
