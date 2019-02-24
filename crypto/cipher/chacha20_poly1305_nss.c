/*
 * chacha20_poly1305_nss.c
 *
 * CHACHA20 POLY1305
 *
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

#include "chacha20_poly1305.h"
#include "alloc.h"
#include "err.h" /* for srtp_debug */
#include "crypto_types.h"
#include "cipher_types.h"
#include <secerr.h>
#include <nspr.h>

srtp_debug_module_t srtp_mod_chacha20_poly1305 = {
    0,                      /* debugging is off by default */
    "chacha20 poly1305 nss" /* printable module name       */
};

/*
 * For now we only support 8 and 16 octet tags.  The spec allows for
 * optional 12 byte tag, which may be supported in the future.
 */
#define AEAD_IV_LEN 12
#define AEAD_AUTH_TAG_LEN 16
#define AEAD_AUTH_TAG_LEN_8 8

/*
 * This function allocates a new instance of this crypto engine.
 * The key_len parameter should be 44 for
 * CHACHA20 POLY1305 respectively.  Note that the
 * key length includes the 14 byte salt value that is used when
 * initializing the KDF.
 */
static srtp_err_status_t srtp_chacha20_poly1305_nss_alloc(srtp_cipher_t **c,
                                                          int key_len,
                                                          int tlen)
{
    srtp_chacha20_poly1305_ctx_t *gcm;
    NSSInitContext *nss;

    debug_print(srtp_mod_chacha20_poly1305,
                "allocating cipher with key length %d", key_len);
    debug_print(srtp_mod_chacha20_poly1305,
                "allocating cipher with tag length %d", tlen);

    /*
     * Verify the key_len is valid for one of: CHACHA20 POLY1305
     */
    if (key_len != SRTP_CHACHA20_POLY1305_KEY_LEN_WSALT) {
        return (srtp_err_status_bad_param);
    }

    if (tlen != AEAD_AUTH_TAG_LEN && tlen != AEAD_AUTH_TAG_LEN_8) {
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

    /* allocate memory a cipher of type chacha20_poly1305 */
    *c = (srtp_cipher_t *)srtp_crypto_alloc(sizeof(srtp_cipher_t));
    if (*c == NULL) {
        NSS_ShutdownContext(nss);
        return (srtp_err_status_alloc_fail);
    }

    gcm = (srtp_chacha20_poly1305_ctx_t *)srtp_crypto_alloc(
        sizeof(srtp_chacha20_poly1305_ctx_t));
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
    case SRTP_CHACHA20_POLY1305_KEY_LEN_WSALT:
        (*c)->type = &srtp_chacha20_poly1305;
        (*c)->algorithm = SRTP_CHACHA20_POLY1305;
        gcm->key_size = SRTP_CHACHA20_POLY1305_KEY_LEN;
        gcm->tag_size = tlen;
        gcm->params.ulTagLen = tlen;
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
 * This function deallocates a CHACHA20 POLY1305 session
 */
static srtp_err_status_t srtp_chacha20_poly1305_nss_dealloc(srtp_cipher_t *c)
{
    srtp_chacha20_poly1305_ctx_t *ctx;

    ctx = (srtp_chacha20_poly1305_ctx_t *)c->state;
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
        octet_string_set_to_zero(ctx, sizeof(srtp_chacha20_poly1305_ctx_t));
        srtp_crypto_free(ctx);
    }

    /* free memory */
    srtp_crypto_free(c);

    return (srtp_err_status_ok);
}

/*
 * chacha20_poly1305_nss_context_init(...) initializes the
 * chacha20_poly1305_context
 * using the value in key[].
 *
 * the key is the secret key
 */
static srtp_err_status_t srtp_chacha20_poly1305_nss_context_init(
    void *cv,
    const uint8_t *key)
{
    srtp_chacha20_poly1305_ctx_t *c = (srtp_chacha20_poly1305_ctx_t *)cv;

    c->dir = srtp_direction_any;

    debug_print(srtp_mod_chacha20_poly1305, "key:  %s",
                srtp_octet_string_hex_string(key, c->key_size));

    if (c->key) {
        PK11_FreeSymKey(c->key);
        c->key = NULL;
    }

    PK11SlotInfo *slot = PK11_GetBestSlot(CKM_NSS_CHACHA20_POLY1305, NULL);
    if (!slot) {
        return (srtp_err_status_cipher_fail);
    }

    SECItem key_item = { siBuffer, (unsigned char *)key, c->key_size };
    c->key = PK11_ImportSymKey(slot, CKM_NSS_CHACHA20_POLY1305,
                               PK11_OriginUnwrap, CKA_ENCRYPT, &key_item, NULL);
    PK11_FreeSlot(slot);

    if (!c->key) {
        return (srtp_err_status_cipher_fail);
    }

    return (srtp_err_status_ok);
}

/*
 * chacha20_poly1305_nss_set_iv(c, iv) sets the counter value to the exor of iv
 * with
 * the offset
 */
static srtp_err_status_t srtp_chacha20_poly1305_nss_set_iv(
    void *cv,
    uint8_t *iv,
    srtp_cipher_direction_t direction)
{
    srtp_chacha20_poly1305_ctx_t *c = (srtp_chacha20_poly1305_ctx_t *)cv;

    if (direction != srtp_direction_encrypt &&
        direction != srtp_direction_decrypt) {
        return (srtp_err_status_bad_param);
    }
    c->dir = direction;

    debug_print(srtp_mod_chacha20_poly1305, "setting iv: %s",
                srtp_octet_string_hex_string(iv, AEAD_IV_LEN));

    memcpy(c->iv, iv, AEAD_IV_LEN);

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
static srtp_err_status_t srtp_chacha20_poly1305_nss_set_aad(void *cv,
                                                            const uint8_t *aad,
                                                            uint32_t aad_len)
{
    srtp_chacha20_poly1305_ctx_t *c = (srtp_chacha20_poly1305_ctx_t *)cv;

    debug_print(srtp_mod_chacha20_poly1305, "setting AAD: %s",
                srtp_octet_string_hex_string(aad, aad_len));

    if (aad_len + c->aad_size > MAX_AD_SIZE) {
        return srtp_err_status_bad_param;
    }

    memcpy(c->aad + c->aad_size, aad, aad_len);
    c->aad_size += aad_len;

    return (srtp_err_status_ok);
}

static srtp_err_status_t srtp_chacha20_poly1305_nss_do_crypto(
    void *cv,
    int encrypt,
    unsigned char *buf,
    unsigned int *enc_len)
{
    srtp_chacha20_poly1305_ctx_t *c = (srtp_chacha20_poly1305_ctx_t *)cv;

    c->params.pNonce = c->iv;
    c->params.ulNonceLen = AEAD_IV_LEN;
    c->params.pAAD = c->aad;
    c->params.ulAADLen = c->aad_size;

    // Reset AAD
    c->aad_size = 0;

    int rv;
    SECItem param = { siBuffer, (unsigned char *)&c->params,
                      sizeof(CK_NSS_AEAD_PARAMS) };
    if (encrypt) {
        rv = PK11_Encrypt(c->key, CKM_NSS_CHACHA20_POLY1305, &param, buf,
                          enc_len, *enc_len + 16, buf, *enc_len);
    } else {
        rv = PK11_Decrypt(c->key, CKM_NSS_CHACHA20_POLY1305, &param, buf,
                          enc_len, *enc_len, buf, *enc_len);
    }

    srtp_err_status_t status = (srtp_err_status_ok);
    if (rv != SECSuccess) {
        status = (srtp_err_status_cipher_fail);
    }

    return status;
}

/*
 * This function encrypts a buffer using CHACHA20 POLY1305 mode
 *
 * XXX(rlb@ipv.sx): We're required to break off and cache the tag
 * here, because the get_tag() method is separate and the tests expect
 * encrypt() not to change the size of the plaintext.  It might be
 * good to update the calling API so that this is cleaner.
 *
 * Parameters:
 *	c	Crypto context
 *	buf	data to encrypt
 *	enc_len	length of encrypt buffer
 */
static srtp_err_status_t srtp_chacha20_poly1305_nss_encrypt(
    void *cv,
    unsigned char *buf,
    unsigned int *enc_len)
{
    srtp_chacha20_poly1305_ctx_t *c = (srtp_chacha20_poly1305_ctx_t *)cv;

    // When we get a non-NULL buffer, we know that the caller is
    // prepared to also take the tag.  When we get a NULL buffer,
    // even though there's no data, we need to give NSS a buffer
    // where it can write the tag.  We can't just use c->tag because
    // memcpy has undefined behavior on overlapping ranges.
    unsigned char tagbuf[16];
    unsigned char *non_null_buf = buf;
    if (!non_null_buf && (*enc_len == 0)) {
        non_null_buf = tagbuf;
    } else if (!non_null_buf) {
        return srtp_err_status_bad_param;
    }

    srtp_err_status_t status =
        srtp_chacha20_poly1305_nss_do_crypto(cv, 1, non_null_buf, enc_len);
    if (status != srtp_err_status_ok) {
        return status;
    }

    memcpy(c->tag, non_null_buf + (*enc_len - c->tag_size), c->tag_size);
    *enc_len -= c->tag_size;
    return srtp_err_status_ok;
}

/*
 * This function calculates and returns the AEAD tag for a given context.
 * This should be called after encrypting the data.  The *len value
 * is increased by the tag size.  The caller must ensure that *buf has
 * enough room to accept the appended tag.
 *
 * Parameters:
 *	c	Crypto context
 *	buf	data to encrypt
 *	len	length of encrypt buffer
 */
static srtp_err_status_t srtp_chacha20_poly1305_nss_get_tag(void *cv,
                                                            uint8_t *buf,
                                                            uint32_t *len)
{
    srtp_chacha20_poly1305_ctx_t *c = (srtp_chacha20_poly1305_ctx_t *)cv;
    *len = c->tag_size;
    memcpy(buf, c->tag, c->tag_size);
    return (srtp_err_status_ok);
}

/*
 * This function decrypts a buffer using CHACHA20 POLY1305 mode
 *
 * Parameters:
 *	c	Crypto context
 *	buf	data to encrypt
 *	enc_len	length of encrypt buffer
 */
static srtp_err_status_t srtp_chacha20_poly1305_nss_decrypt(
    void *cv,
    unsigned char *buf,
    unsigned int *enc_len)
{
    srtp_err_status_t status =
        srtp_chacha20_poly1305_nss_do_crypto(cv, 0, buf, enc_len);
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
static const char srtp_chacha20_poly1305_nss_description[] =
    "CHACHA20 POLY1305 using NSS";

/*
 * KAT values for CHACHA20 POLY1305 self-test.  These
 * values we're derived from independent test code
 * using OpenSSL.
 */

/* clang-format off */
static const uint8_t srtp_chacha20_poly1305_test_case_1_key[SRTP_CHACHA20_POLY1305_KEY_LEN_WSALT] = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0xa5, 0x59, 0x09, 0xc5, 0x54, 0x66, 0x93, 0x1c,
    0xaf, 0xf5, 0x26, 0x9a, 0x21, 0xd5, 0x14, 0xb2,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c,
};
/* clang-format on */

/* clang-format off */
static uint8_t srtp_chacha20_poly1305_test_case_1_iv[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
    0xde, 0xca, 0xf8, 0x88
};
/* clang-format on */

/* clang-format off */
static const uint8_t srtp_chacha20_poly1305_test_case_1_plaintext[60] =  {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
    0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
    0xba, 0x63, 0x7b, 0x39
};
/* clang-format on */

/* clang-format off */
static const uint8_t srtp_chacha20_poly1305_test_case_1_aad[20] = {
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xab, 0xad, 0xda, 0xd2
};
/* clang-format on */

/* clang-format off */
static const uint8_t srtp_chacha20_poly1305_test_case_1_ciphertext[76] = {
      0xf1, 0xe9, 0x8f, 0xa5, 0x30, 0xce, 0x2c, 0x53,
      0x3c, 0x54, 0x31, 0xdb, 0x1f, 0xe4, 0x5b, 0xcb,
      0x88, 0xfd, 0x48, 0x7c, 0xd2, 0x28, 0xab, 0x0b,
      0x2f, 0x62, 0xd6, 0xc8, 0xaa, 0xc4, 0x6f, 0xd1,
      0x7f, 0xbf, 0xca, 0x17, 0xf9, 0x0d, 0x2c, 0x86,
      0x85, 0x1d, 0xf1, 0x7a, 0xfc, 0x10, 0xef, 0xa7,
      0x87, 0x92, 0x41, 0x66, 0x79, 0x63, 0xde, 0x6f,
      0x15, 0xc3, 0x39, 0x9b,
    /* the last 16 bytes are the tag */
      0x55, 0xc9, 0xa5, 0x8e, 0xe4, 0x4a, 0xc3, 0xfe,
      0x86, 0x5c, 0xb5, 0xe3, 0x2e, 0x25, 0x16, 0xf9,
};
/* clang-format on */

static const srtp_cipher_test_case_t srtp_chacha20_poly1305_test_case_1a = {
    SRTP_CHACHA20_POLY1305_KEY_LEN_WSALT,         /* octets in key            */
    srtp_chacha20_poly1305_test_case_1_key,       /* key                      */
    srtp_chacha20_poly1305_test_case_1_iv,        /* packet index             */
    60,                                           /* octets in plaintext      */
    srtp_chacha20_poly1305_test_case_1_plaintext, /* plaintext                */
    68,                                           /* octets in ciphertext     */
    srtp_chacha20_poly1305_test_case_1_ciphertext, /* ciphertext  + tag */
    20,                                     /* octets in AAD            */
    srtp_chacha20_poly1305_test_case_1_aad, /* AAD                      */
    AEAD_AUTH_TAG_LEN_8,                    /* */
    NULL                                    /* pointer to next testcase */
};

static const srtp_cipher_test_case_t srtp_chacha20_poly1305_test_case_1 = {
    SRTP_CHACHA20_POLY1305_KEY_LEN_WSALT,         /* octets in key            */
    srtp_chacha20_poly1305_test_case_1_key,       /* key                      */
    srtp_chacha20_poly1305_test_case_1_iv,        /* packet index             */
    60,                                           /* octets in plaintext      */
    srtp_chacha20_poly1305_test_case_1_plaintext, /* plaintext                */
    76,                                           /* octets in ciphertext     */
    srtp_chacha20_poly1305_test_case_1_ciphertext, /* ciphertext  + tag */
    20,                                     /* octets in AAD            */
    srtp_chacha20_poly1305_test_case_1_aad, /* AAD                      */
    AEAD_AUTH_TAG_LEN,                      /* */
    &srtp_chacha20_poly1305_test_case_1a    /* pointer to next testcase */
};

/*
 * This is the vector function table for this crypto engine.
 */
/* clang-format off */
const srtp_cipher_type_t srtp_chacha20_poly1305 = {
    srtp_chacha20_poly1305_nss_alloc,
    srtp_chacha20_poly1305_nss_dealloc,
    srtp_chacha20_poly1305_nss_context_init,
    srtp_chacha20_poly1305_nss_set_aad,
    srtp_chacha20_poly1305_nss_encrypt,
    srtp_chacha20_poly1305_nss_decrypt,
    srtp_chacha20_poly1305_nss_set_iv,
    srtp_chacha20_poly1305_nss_get_tag,
    srtp_chacha20_poly1305_nss_description,
    &srtp_chacha20_poly1305_test_case_1,
    SRTP_CHACHA20_POLY1305
};
/* clang-format on */
