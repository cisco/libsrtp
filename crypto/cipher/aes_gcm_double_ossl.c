/*
 * aes_gcm_double_ossl.c
 *
 * AES Galois Counter Mode
 *
 * Richard L. Barnes
 * Cisco
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

#include <openssl/evp.h>
#include "aes_icm_ossl.h"
#include "aes_gcm_ossl.h"
#include "alloc.h"
#include "err.h"                /* for srtp_debug */
#include "crypto_types.h"


srtp_debug_module_t srtp_mod_aes_gcm_double = {
    0,               /* debugging is off by default */
    "aes gcm double" /* printable module name       */
};

/*
 * The following are the global singleton instances for the
 * 128-bit and 256-bit GCM ciphers.
 */
extern const srtp_cipher_type_t srtp_aes_gcm_128_double_openssl;
extern const srtp_cipher_type_t srtp_aes_gcm_256_double_openssl;

/*
 * The auth tag for the doubled GCM mode consists of two
 * full-size GCM auth tags.
 */
#define GCM_AUTH_TAG_LEN           16
#define GCM_DOUBLE_AUTH_TAG_LEN    (GCM_AUTH_TAG_LEN + GCM_AUTH_TAG_LEN)
#define MAX_AAD_LEN                512

typedef struct {
    int key_size;
    int tag_len;
    int do_inner;
    uint8_t inner_aad[MAX_AAD_LEN];
    uint8_t inner_tag[GCM_AUTH_TAG_LEN];
    EVP_CIPHER_CTX* inner_ctx;
    EVP_CIPHER_CTX* outer_ctx;
    srtp_cipher_direction_t dir;
} srtp_aes_gcm_double_ctx_t;

/* XXX: srtp_hdr_t borrowed from srtp_priv.h */
#ifndef WORDS_BIGENDIAN

typedef struct {
    uint8_t len : 4;
    uint8_t type : 4;
    uint8_t pt : 7;
    uint8_t r : 1;
    uint16_t seq;
    uint16_t ext_len;
} ohb_t;

typedef struct {
    unsigned char cc : 4;      /* CSRC count             */
    unsigned char x : 1;       /* header extension flag  */
    unsigned char p : 1;       /* padding flag           */
    unsigned char version : 2; /* protocol version       */
    unsigned char pt : 7;      /* payload type           */
    unsigned char m : 1;       /* marker bit             */
    uint16_t seq;              /* sequence number        */
    uint32_t ts;               /* timestamp              */
    uint32_t ssrc;             /* synchronization source */
} srtp_hdr_t;

#else /*  BIG_ENDIAN */

typedef struct {
    uint8_t type : 4;
    uint8_t len : 4;
    uint8_t r : 1;
    uint8_t pt : 7;
    uint16_t seq;
    uint16_t ext_len;
} ohb_t;

typedef struct {
    unsigned char version : 2; /* protocol version       */
    unsigned char p : 1;       /* padding flag           */
    unsigned char x : 1;       /* header extension flag  */
    unsigned char cc : 4;      /* CSRC count             */
    unsigned char m : 1;       /* marker bit             */
    unsigned char pt : 7;      /* payload type           */
    uint16_t seq;              /* sequence number        */
    uint32_t ts;               /* timestamp              */
    uint32_t ssrc;             /* synchronization source */
} srtp_hdr_t;

#endif

/* XXX: borrowed from srtp_priv.h */
typedef struct {
  uint16_t profile_specific;   /* profile-specific info               */
  uint16_t length;             /* number of 32-bit words in extension */
} srtp_hdr_xtnd_t;

#define RTP_HDR_LEN       12
#define RTP_EXT_HDR_LEN   4
#define OHB_LEN           6

/*
 * This function allocates a new instance of this crypto engine.
 * The key_len parameter should be the length of two AES keys plus
 * the 12-byte salt used by SRTP with AEAD modes:
 *
 *   * 44 = 16 + 16 + 12
 *   * 76 = 32 + 32 + 12
 */
static srtp_err_status_t srtp_aes_gcm_double_openssl_alloc (srtp_cipher_t **c, int key_len, int tlen)
{
    srtp_aes_gcm_double_ctx_t *dbl;

    debug_print(srtp_mod_aes_gcm_double, "allocating cipher with key length %d", key_len);
    debug_print(srtp_mod_aes_gcm_double, "allocating cipher with tag length %d", tlen);

    /*
     * Verify the key_len is valid for one of: AES-128/256
     */
    if (key_len != SRTP_AES_GCM_128_DOUBLE_KEY_LEN_WSALT &&
        key_len != SRTP_AES_GCM_256_DOUBLE_KEY_LEN_WSALT) {
        return (srtp_err_status_bad_param);
    }

    if (tlen != GCM_DOUBLE_AUTH_TAG_LEN) {
        return (srtp_err_status_bad_param);
    }

    /* Allocate inner and outer GCM contexts */
    *c = (srtp_cipher_t *)srtp_crypto_alloc(sizeof(srtp_cipher_t));
    if (*c == NULL) {
        return (srtp_err_status_alloc_fail);
    }
    memset(*c, 0x0, sizeof(srtp_cipher_t));

    dbl = (srtp_aes_gcm_double_ctx_t *)srtp_crypto_alloc(sizeof(srtp_aes_gcm_double_ctx_t));
    if (dbl == NULL) {
        srtp_crypto_free(*c);
        *c = NULL;
        return (srtp_err_status_alloc_fail);
    }
    memset(dbl, 0x0, sizeof(srtp_aes_gcm_double_ctx_t));

    dbl->inner_ctx = EVP_CIPHER_CTX_new();
    if (dbl->inner_ctx == NULL) {
        srtp_crypto_free(dbl);
        srtp_crypto_free(*c);
        *c = NULL;
        return srtp_err_status_alloc_fail;
    }

    dbl->outer_ctx = EVP_CIPHER_CTX_new();
    if (dbl->outer_ctx == NULL) {
        srtp_crypto_free(dbl);
        srtp_crypto_free(*c);
        *c = NULL;
        return srtp_err_status_alloc_fail;
    }

    /* set pointers */
    (*c)->state = dbl;

    /* setup cipher attributes */
    switch (key_len) {
    case SRTP_AES_GCM_128_DOUBLE_KEY_LEN_WSALT:
        (*c)->type = &srtp_aes_gcm_128_double_openssl;
        (*c)->algorithm = SRTP_AES_GCM_128_DOUBLE;
        dbl->key_size = SRTP_AES_128_DOUBLE_KEY_LEN;
        dbl->tag_len = tlen;
        break;
    case SRTP_AES_GCM_256_DOUBLE_KEY_LEN_WSALT:
        (*c)->type = &srtp_aes_gcm_256_double_openssl;
        (*c)->algorithm = SRTP_AES_GCM_256_DOUBLE;
        dbl->key_size = SRTP_AES_256_DOUBLE_KEY_LEN;
        dbl->tag_len = tlen;
        break;
    }

    /* set key size        */
    (*c)->key_len = key_len;

    return (srtp_err_status_ok);
}


/*
 * This function deallocates a GCM session
 */
static srtp_err_status_t srtp_aes_gcm_double_openssl_dealloc (srtp_cipher_t *c)
{
    srtp_aes_gcm_double_ctx_t *ctx;

    ctx = (srtp_aes_gcm_double_ctx_t*)c->state;
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx->inner_ctx);
        EVP_CIPHER_CTX_free(ctx->outer_ctx);
        /* zeroize the key material */
        octet_string_set_to_zero(ctx, sizeof(srtp_aes_gcm_double_ctx_t));
        srtp_crypto_free(ctx);
    }

    /* free memory */
    srtp_crypto_free(c);

    return (srtp_err_status_ok);
}

/*
 * aes_gcm_openssl_context_init(...) initializes the aes_gcm_double_context
 * using the value in key[].
 *
 * The key countains two AES keys of the same size, inner || outer.
 */
static srtp_err_status_t srtp_aes_gcm_double_openssl_context_init (void* cv, const uint8_t *key)
{
    srtp_aes_gcm_double_ctx_t *c = (srtp_aes_gcm_double_ctx_t *)cv;
    const EVP_CIPHER *inner_evp;
    const EVP_CIPHER *outer_evp;
    int subkey_size;
    uint8_t inner_non_zero;

    c->dir = srtp_direction_any;

    debug_print(srtp_mod_aes_gcm_double, "key:  %s", srtp_octet_string_hex_string(key, c->key_size));

    switch (c->key_size) {
    case SRTP_AES_128_DOUBLE_KEY_LEN:
        inner_evp = EVP_aes_128_gcm();
        outer_evp = EVP_aes_128_gcm();
        subkey_size = SRTP_AES_128_KEY_LEN;
        break;
    case SRTP_AES_256_DOUBLE_KEY_LEN:
        inner_evp = EVP_aes_256_gcm();
        outer_evp = EVP_aes_256_gcm();
        subkey_size = SRTP_AES_256_KEY_LEN;
        break;
    default:
        return (srtp_err_status_bad_param);
        break;
    }

    /* This context performs the inner transform iff the inner key is not all zero */
    inner_non_zero = 0;
    for (int i=0; i < subkey_size; i++) {
        inner_non_zero |= key[i];
    }

    c->do_inner = 0;
    if (inner_non_zero != 0) {
        c->do_inner = 1;
    }

    if (c->do_inner) {
        if (!EVP_CipherInit_ex(c->inner_ctx, inner_evp, NULL, key, NULL, 0)) {
            return (srtp_err_status_init_fail);
        }
    }

    if (!EVP_CipherInit_ex(c->outer_ctx, outer_evp, NULL, key + subkey_size, NULL, 0)) {
        return (srtp_err_status_init_fail);
    }

    return (srtp_err_status_ok);
}


/*
 * aes_gcm_openssl_set_iv(c, iv) sets the counter value to the exor of iv with
 * the offset
 *
 * XXX: We use the same IV for both inner and outer contexts.  This should be
 * safe because the keys should be different.
 */
static srtp_err_status_t srtp_aes_gcm_double_openssl_set_iv (void *cv, uint8_t *iv, srtp_cipher_direction_t direction)
{
    srtp_aes_gcm_double_ctx_t *c = (srtp_aes_gcm_double_ctx_t *)cv;

    if (direction != srtp_direction_encrypt && direction != srtp_direction_decrypt) {
        return (srtp_err_status_bad_param);
    }
    c->dir = direction;

    debug_print(srtp_mod_aes_gcm_double, "setting iv: %s", v128_hex_string((v128_t*)iv));

    /* initialize the contexts with a direction */
    if (!EVP_CipherInit_ex(c->outer_ctx, NULL, NULL, NULL,
                           NULL, (c->dir == srtp_direction_encrypt ? 1 : 0))) {
        return (srtp_err_status_init_fail);
    }

    /* set IV len  and the IV value, the followiong 3 calls are required */
    if (!EVP_CIPHER_CTX_ctrl(c->outer_ctx, EVP_CTRL_GCM_SET_IVLEN, 12, 0)) {
        return (srtp_err_status_init_fail);
    }
    if (!EVP_CIPHER_CTX_ctrl(c->outer_ctx, EVP_CTRL_GCM_SET_IV_FIXED, -1, (void*)iv)) {
        return (srtp_err_status_init_fail);
    }
    if (!EVP_CIPHER_CTX_ctrl(c->outer_ctx, EVP_CTRL_GCM_IV_GEN, 0, (void*)iv)) {
        return (srtp_err_status_init_fail);
    }

    if (c->do_inner) {
        if (!EVP_CipherInit_ex(c->inner_ctx, NULL, NULL, NULL,
                               NULL, (c->dir == srtp_direction_encrypt ? 1 : 0))) {
            return (srtp_err_status_init_fail);
        }

        if (!EVP_CIPHER_CTX_ctrl(c->inner_ctx, EVP_CTRL_GCM_SET_IVLEN, 12, 0)) {
            return (srtp_err_status_init_fail);
        }
        if (!EVP_CIPHER_CTX_ctrl(c->inner_ctx, EVP_CTRL_GCM_SET_IV_FIXED, -1, (void*)iv)) {
            return (srtp_err_status_init_fail);
        }
        if (!EVP_CIPHER_CTX_ctrl(c->inner_ctx, EVP_CTRL_GCM_IV_GEN, 0, (void*)iv)) {
            return (srtp_err_status_init_fail);
        }
    }

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
static srtp_err_status_t srtp_aes_gcm_double_openssl_set_aad (void *cv, const uint8_t *aad, uint32_t aad_len)
{
    srtp_aes_gcm_double_ctx_t *c = (srtp_aes_gcm_double_ctx_t *)cv;
    ohb_t *ohb;
    srtp_hdr_t *hdr;
    srtp_hdr_xtnd_t *ext_hdr;
    int original_ext_len;
    int inner_aad_len;
    int rv;

    debug_print(srtp_mod_aes_gcm_double, "setting aad(outer): %s",
                srtp_octet_string_hex_string(aad, aad_len));

    /*
     * This tranform is RTP-specific, and all inputs are requried to have an
     * Original Headers Block (OHB) extension as their first extension.
     */
    if (aad_len < RTP_HDR_LEN) {
        return (srtp_err_status_bad_param);
    }

    hdr = (srtp_hdr_t *)aad;
    if ((hdr->x != 1) ||
        (aad_len < RTP_HDR_LEN + (4 * (int) hdr->cc) + RTP_EXT_HDR_LEN + OHB_LEN)) {
        return (srtp_err_status_bad_param);
    }

    ext_hdr = (srtp_hdr_xtnd_t *)(aad + RTP_HDR_LEN + (4 * (int) hdr->cc));
    if ((ntohs(ext_hdr->profile_specific) != 0xbede) || (4 * ntohs(ext_hdr->length) < OHB_LEN)) {
        return (srtp_err_status_bad_param);
    }

    ohb = (ohb_t *)(aad + RTP_HDR_LEN + (4 * (int) hdr->cc) + RTP_EXT_HDR_LEN);
    if (ohb->len != OHB_LEN - 2) {
        return (srtp_err_status_bad_param);
    }

    original_ext_len = ntohs(ohb->ext_len);
    if (aad_len < RTP_HDR_LEN + (4 * (int) hdr->cc) + RTP_EXT_HDR_LEN + original_ext_len) {
        return (srtp_err_status_bad_param);
    }

    inner_aad_len = RTP_HDR_LEN + (4 * (int) hdr->cc) +
                    RTP_EXT_HDR_LEN + original_ext_len;

    /*
     * Set dummy tag, OpenSSL requires the Tag to be set before
     * processing AAD
     */

    /*
     * OpenSSL never write to address pointed by the last parameter of
     * EVP_CIPHER_CTX_ctrl while EVP_CTRL_GCM_SET_TAG (in reality,
     * OpenSSL copy its content to the context), so we can make
     * aad read-only in this function and all its wrappers.
     */
    unsigned char dummy_tag[GCM_AUTH_TAG_LEN];
    memset(dummy_tag, 0x0, GCM_AUTH_TAG_LEN);
    EVP_CIPHER_CTX_ctrl(c->inner_ctx, EVP_CTRL_GCM_SET_TAG, GCM_AUTH_TAG_LEN, &dummy_tag);
    EVP_CIPHER_CTX_ctrl(c->outer_ctx, EVP_CTRL_GCM_SET_TAG, GCM_AUTH_TAG_LEN, &dummy_tag);

    rv = EVP_Cipher(c->outer_ctx, NULL, aad, aad_len);
    if (rv != aad_len) {
        return (srtp_err_status_algo_fail);
    }

    if (c->do_inner) {
        /* Make the changes specified in the OHB */
        if (inner_aad_len > MAX_AAD_LEN) {
            return (srtp_err_status_bad_param);
        }

        memcpy(c->inner_aad, aad, inner_aad_len);

        debug_print(srtp_mod_aes_gcm_double, "setting aad(inner): %s",
                    srtp_octet_string_hex_string(c->inner_aad, inner_aad_len));

        hdr = (srtp_hdr_t *) (c->inner_aad);
        hdr->pt = ohb->pt;
        hdr->seq = ohb->seq;

        ext_hdr = (srtp_hdr_xtnd_t *)(c->inner_aad + RTP_HDR_LEN + (4 * (int) hdr->cc));
        ext_hdr->length = htons(original_ext_len);

        /*
         * Set the AAD for the inner transform based on the revised packet.
         */
        rv = EVP_Cipher(c->inner_ctx, NULL, c->inner_aad, inner_aad_len);
        if (rv != inner_aad_len) {
            return (srtp_err_status_algo_fail);
        }
    }

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
static srtp_err_status_t srtp_aes_gcm_double_openssl_encrypt (void *cv, unsigned char *buf, unsigned int *enc_len)
{
    srtp_aes_gcm_double_ctx_t *c = (srtp_aes_gcm_double_ctx_t *)cv;
    if (c->dir != srtp_direction_encrypt && c->dir != srtp_direction_decrypt) {
        return (srtp_err_status_bad_param);
    }

    /*
     * Encrypt the data with the inner transform, if applicable.  If
     * we are not applying the inner transform, then the input is required
     * to be a GCM-protected payload+tag.  So we need to truncate it and
     * cache the tag.
     *
     * XXX: Decreasing enc_len is probably going to cause problems.
     */
    if (c->do_inner) {
        EVP_Cipher(c->inner_ctx, buf, buf, *enc_len);
    } else {
        *enc_len -= GCM_AUTH_TAG_LEN;
        memcpy(c->inner_tag, buf + *enc_len, GCM_AUTH_TAG_LEN);
    }

    /*
     * Encrypt the data with the inner transform, if applicable
     */
    EVP_Cipher(c->outer_ctx, buf, buf, *enc_len);

    return (srtp_err_status_ok);
}

/*
 * This function calculates and returns the GCM tag for a given context.
 * This should be called after encrypting the data.  The *len value
 * is increased by the tag size.  The caller must ensure that *buf has
 * enough room to accept the appended tag.
 *
 * Parameters:
 *	c	Crypto context
 *	buf	data to encrypt
 *	len	length of encrypt buffer
 */
static srtp_err_status_t srtp_aes_gcm_double_openssl_get_tag (void *cv, uint8_t *buf, uint32_t *len)
{
    srtp_aes_gcm_double_ctx_t *c = (srtp_aes_gcm_double_ctx_t *)cv;

    /*
     * The first part of the tag is the tag from the inner transform,
     * encrypted with the outer transform.
     */
    if (c->do_inner) {
        EVP_Cipher(c->inner_ctx, NULL, NULL, 0);
        EVP_CIPHER_CTX_ctrl(c->inner_ctx, EVP_CTRL_GCM_GET_TAG, GCM_AUTH_TAG_LEN, buf);
    } else {
        memcpy(buf, c->inner_tag, GCM_AUTH_TAG_LEN);
    }
    EVP_Cipher(c->outer_ctx, buf, buf, GCM_AUTH_TAG_LEN);

    /*
     * The second part of the tag is the tag from the outer tranform
     */
    EVP_Cipher(c->outer_ctx, NULL, NULL, 0);
    EVP_CIPHER_CTX_ctrl(c->outer_ctx, EVP_CTRL_GCM_GET_TAG, GCM_AUTH_TAG_LEN, buf + GCM_AUTH_TAG_LEN);

    /*
     * Increase encryption length by desired tag size
     */
    *len = c->tag_len;

    return (srtp_err_status_ok);
}


/*
 * This function decrypts a buffer using AES GCM mode
 *
 * Parameters:
 *	c	Crypto context
 *	buf	data to encrypt
 *	enc_len	length of encrypt buffer
 */
static srtp_err_status_t srtp_aes_gcm_double_openssl_decrypt (void *cv, unsigned char *buf, unsigned int *enc_len)
{
    srtp_aes_gcm_double_ctx_t *c = (srtp_aes_gcm_double_ctx_t *)cv;
    if (c->dir != srtp_direction_encrypt && c->dir != srtp_direction_decrypt) {
        return (srtp_err_status_bad_param);
    }

    /*
     * Undo the outer transform
     */

    /*
     * Set the tag before decrypting
     */
    EVP_CIPHER_CTX_ctrl(c->outer_ctx, EVP_CTRL_GCM_SET_TAG, GCM_AUTH_TAG_LEN,
                        buf + (*enc_len - GCM_AUTH_TAG_LEN));
    EVP_Cipher(c->outer_ctx, buf, buf, *enc_len - GCM_AUTH_TAG_LEN);

    /*
     * Check the tag
     */
    if (EVP_Cipher(c->outer_ctx, NULL, NULL, 0)) {
        return (srtp_err_status_auth_fail);
    }

    /*
     * Undo the inner transform
     */
    if (c->do_inner) {
        /*
         * Set the tag before decrypting
         */
        EVP_CIPHER_CTX_ctrl(c->inner_ctx, EVP_CTRL_GCM_SET_TAG, GCM_AUTH_TAG_LEN,
                            buf + (*enc_len - c->tag_len));
        EVP_Cipher(c->inner_ctx, buf, buf, *enc_len - c->tag_len);

        /*
         * Check the tag
         */
        if (EVP_Cipher(c->inner_ctx, NULL, NULL, 0)) {
            return (srtp_err_status_auth_fail);
        }

        /*
         * Reduce the buffer size by the tag length since the tag
         * is not part of the original payload
         */
        *enc_len -= c->tag_len;
    } else {
        *enc_len -= GCM_AUTH_TAG_LEN;
    }

    return (srtp_err_status_ok);
}



/*
 * Name of this crypto engine
 */
static const char srtp_aes_gcm_128_double_openssl_description[] = "Double AES-128 GCM using openssl";
static const char srtp_aes_gcm_256_double_openssl_description[] = "Double AES-256 GCM using openssl";


/*
 * KAT values for AES self-test.  These
 * values we're derived from independent test code
 * using OpenSSL.
 */
static const uint8_t srtp_aes_gcm_double_test_case_0_key[44] = {
    0x48, 0x23, 0x83, 0xca, 0x8e, 0x4e, 0xb2, 0xeb,
    0x86, 0xe0, 0x3e, 0xd1, 0x4c, 0x65, 0xbb, 0x81,
    0x1e, 0xf8, 0x06, 0xb0, 0x1c, 0x41, 0x2b, 0x2f,
    0x69, 0xb2, 0xec, 0x8c, 0x8d, 0xa6, 0xde, 0x22,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c,
};

static const uint8_t srtp_aes_gcm_double_test_case_0_key_0[44] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x1e, 0xf8, 0x06, 0xb0, 0x1c, 0x41, 0x2b, 0x2f,
    0x69, 0xb2, 0xec, 0x8c, 0x8d, 0xa6, 0xde, 0x22,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c,
};

static uint8_t srtp_aes_gcm_double_test_case_0_iv[12] = {
    0x1d, 0x2b, 0x97, 0x10, 0x54, 0x0a, 0x78, 0x00,
    0x9c, 0x84, 0xd2, 0xd9,
};

static const uint8_t srtp_aes_gcm_double_test_case_0_aad[27] = {
    0xf0, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xfe, 0xed, 0xfa, 0xce,
    /* extension header and OHB */
    0xbe, 0xde, 0x00, 0x0b, 0x04, 0x01, 0x02, 0x03,
    0x00, 0x08, 0x01, 0x00, 0x02, 0xff, 0xff,
};

static const uint8_t srtp_aes_gcm_double_test_case_0_plaintext[60] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
    0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
    0xba, 0x63, 0x7b, 0x39,
};

static const uint8_t srtp_aes_gcm_double_test_case_0_plaintext_0[76] = {
    0x6b, 0xac, 0xe3, 0x31, 0x8c, 0xd7, 0x96, 0xe8,
    0x78, 0x0b, 0xc1, 0xbd, 0x70, 0x7a, 0x98, 0x6e,
    0x0f, 0x9e, 0xb7, 0x98, 0x8e, 0x28, 0xa0, 0xc8,
    0xf1, 0xca, 0xfe, 0xc3, 0xce, 0xc6, 0x19, 0xcb,
    0x18, 0x2a, 0xda, 0xeb, 0xe8, 0x6d, 0x6b, 0xb9,
    0x06, 0xc4, 0xde, 0xc5, 0x7a, 0x43, 0xa6, 0x51,
    0x50, 0x37, 0x68, 0x4a, 0x96, 0x35, 0x62, 0xb3,
    0x9e, 0x24, 0x5d, 0xec, 0x86, 0xee, 0x9a, 0xfb,
    0xbd, 0xc6, 0x2d, 0x24, 0x7a, 0x10, 0xc3, 0xc5,
    0xcd, 0x51, 0x61, 0x6a,
};

static const uint8_t srtp_aes_gcm_double_test_case_0_ciphertext[92] = {
    0x14, 0x9d, 0xc0, 0xb9, 0x2a, 0xa0, 0x36, 0x91,
    0x52, 0x53, 0xc4, 0x22, 0x82, 0x4e, 0xec, 0x4a,
    0x14, 0x2d, 0xc9, 0x40, 0xa5, 0x0f, 0xcd, 0x8e,
    0x5d, 0x2e, 0x9c, 0x61, 0x9f, 0x13, 0x3c, 0x02,
    0xd8, 0x5f, 0x9e, 0x54, 0xbb, 0xc0, 0xec, 0xd5,
    0xb3, 0xe5, 0x22, 0xde, 0xd0, 0xdf, 0x51, 0xe1,
    0x1c, 0xda, 0x6e, 0x5b, 0xca, 0x54, 0xf8, 0x77,
    0x1a, 0x7d, 0xbf, 0xb7, 0xf9, 0x3d, 0xf4, 0x24,
    0x44, 0x6e, 0x9f, 0x69, 0x4c, 0xa6, 0x7d, 0xe4,
    0x60, 0x6e, 0x83, 0xc7, 0x88, 0x1c, 0xd5, 0x5f,
    0xc9, 0xd0, 0x32, 0x9e, 0x60, 0x0e, 0xef, 0x3f,
    0xa6, 0xb9, 0x42, 0x9a,
};

static const srtp_cipher_test_case_t srtp_aes_gcm_double_test_case_0_0 = {
    SRTP_AES_GCM_128_DOUBLE_KEY_LEN_WSALT,       /* octets in key            */
    srtp_aes_gcm_double_test_case_0_key_0,       /* key                      */
    srtp_aes_gcm_double_test_case_0_iv,          /* packet index             */
    76,                                          /* octets in plaintext      */
    srtp_aes_gcm_double_test_case_0_plaintext_0, /* plaintext                */
    92,                                          /* octets in ciphertext     */
    srtp_aes_gcm_double_test_case_0_ciphertext,  /* ciphertext  + tag        */
    27,                                          /* octets in AAD            */
    srtp_aes_gcm_double_test_case_0_aad,         /* AAD                      */
    GCM_DOUBLE_AUTH_TAG_LEN,
    NULL                                         /* pointer to next testcase */
};

static const srtp_cipher_test_case_t srtp_aes_gcm_double_test_case_0 = {
    SRTP_AES_GCM_128_DOUBLE_KEY_LEN_WSALT,      /* octets in key            */
    srtp_aes_gcm_double_test_case_0_key,        /* key                      */
    srtp_aes_gcm_double_test_case_0_iv,         /* packet index             */
    60,                                         /* octets in plaintext      */
    srtp_aes_gcm_double_test_case_0_plaintext,  /* plaintext                */
    92,                                         /* octets in ciphertext     */
    srtp_aes_gcm_double_test_case_0_ciphertext, /* ciphertext  + tag        */
    27,                                         /* octets in AAD            */
    srtp_aes_gcm_double_test_case_0_aad,        /* AAD                      */
    GCM_DOUBLE_AUTH_TAG_LEN,
    &srtp_aes_gcm_double_test_case_0_0          /* pointer to next testcase */
};

static const uint8_t srtp_aes_gcm_double_test_case_1_key[76] = {
    0x91, 0x48, 0x08, 0xdc, 0xf7, 0xde, 0x74, 0x75,
    0xd5, 0x67, 0x14, 0xde, 0xea, 0x6a, 0x67, 0xd1,
    0xf8, 0x34, 0x9a, 0x84, 0xb3, 0x0e, 0xbe, 0x82,
    0x9b, 0xb5, 0xe0, 0x6a, 0x42, 0x69, 0x43, 0x53,
    0x01, 0xed, 0xae, 0xa4, 0xa1, 0x38, 0x01, 0xfa,
    0x5e, 0x7d, 0x63, 0x9c, 0xc1, 0x67, 0x71, 0xa3,
    0xc2, 0xda, 0x09, 0xd5, 0xc2, 0x7a, 0xf7, 0x05,
    0xe1, 0xa2, 0xd6, 0xad, 0xab, 0x2c, 0x71, 0x32,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c,
};

static const uint8_t srtp_aes_gcm_double_test_case_1_key_0[76] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0xed, 0xae, 0xa4, 0xa1, 0x38, 0x01, 0xfa,
    0x5e, 0x7d, 0x63, 0x9c, 0xc1, 0x67, 0x71, 0xa3,
    0xc2, 0xda, 0x09, 0xd5, 0xc2, 0x7a, 0xf7, 0x05,
    0xe1, 0xa2, 0xd6, 0xad, 0xab, 0x2c, 0x71, 0x32,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c,
};

static uint8_t srtp_aes_gcm_double_test_case_1_iv[12] = {
    0x1d, 0x2b, 0x97, 0x10, 0x54, 0x0a, 0x78, 0x00,
    0x9c, 0x84, 0xd2, 0xd9,
};

static const uint8_t srtp_aes_gcm_double_test_case_1_aad[27] = {
    0xf0, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xfe, 0xed, 0xfa, 0xce,
    /* extension header and OHB */
    0xbe, 0xde, 0x00, 0x0b, 0x04, 0x01, 0x02, 0x03,
    0x00, 0x08, 0x01, 0x00, 0x02, 0xff, 0xff,
};

static const uint8_t srtp_aes_gcm_double_test_case_1_plaintext[60] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
    0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
    0xba, 0x63, 0x7b, 0x39,
};

static const uint8_t srtp_aes_gcm_double_test_case_1_plaintext_0[76] = {
    0x87, 0x33, 0xf4, 0x52, 0x1c, 0xb3, 0xe2, 0x0f,
    0xa2, 0x56, 0xc8, 0x99, 0x0b, 0xd2, 0xfa, 0x55,
    0x8f, 0x47, 0x62, 0xc2, 0x4a, 0x3a, 0x5b, 0x06,
    0x17, 0xd9, 0x99, 0x8d, 0xe7, 0x72, 0xce, 0xb8,
    0xdb, 0x2f, 0x99, 0xc6, 0x35, 0x6b, 0x47, 0x26,
    0x87, 0xc4, 0xf1, 0x08, 0xeb, 0x41, 0xd0, 0x4d,
    0xbe, 0xcc, 0x3a, 0x3b, 0x07, 0xe8, 0x7a, 0xbf,
    0xee, 0xc2, 0xdc, 0x4f, 0xc4, 0x1a, 0x64, 0x8a,
    0xf8, 0x13, 0x1d, 0xfe, 0x23, 0x2a, 0xe6, 0xbb,
    0xdc, 0x1a, 0x1e, 0xa7,
};

static const uint8_t srtp_aes_gcm_double_test_case_1_ciphertext[92] = {
    0x55, 0x45, 0xf2, 0xe7, 0xcf, 0x9c, 0x5d, 0x3c,
    0x0b, 0x85, 0x31, 0x81, 0x5e, 0x34, 0x38, 0x4d,
    0x6d, 0x90, 0x39, 0xb7, 0x49, 0x84, 0x5e, 0xb4,
    0xa2, 0xb1, 0x02, 0x4f, 0xd6, 0xeb, 0x89, 0x07,
    0x7d, 0xe1, 0x36, 0x59, 0x9b, 0x1c, 0xe8, 0xa9,
    0x1d, 0xda, 0xa8, 0x78, 0xfb, 0x0f, 0x2e, 0x3c,
    0x80, 0x30, 0x33, 0x81, 0x86, 0x65, 0x2e, 0x67,
    0x81, 0xc3, 0xf0, 0xbd, 0x9d, 0x62, 0x35, 0xc8,
    0xd8, 0xf7, 0xa6, 0x19, 0xe4, 0x4a, 0x26, 0x6b,
    0x7f, 0x91, 0xcf, 0x84, 0x99, 0xdb, 0x84, 0xd8,
    0xab, 0xb7, 0x15, 0xe3, 0xea, 0x4e, 0xfb, 0x29,
    0x1b, 0x34, 0x8e, 0x03,
};

static const srtp_cipher_test_case_t srtp_aes_gcm_double_test_case_1_0 = {
    SRTP_AES_GCM_256_DOUBLE_KEY_LEN_WSALT,       /* octets in key            */
    srtp_aes_gcm_double_test_case_1_key_0,       /* key                      */
    srtp_aes_gcm_double_test_case_1_iv,          /* packet index             */
    76,                                          /* octets in plaintext      */
    srtp_aes_gcm_double_test_case_1_plaintext_0, /* plaintext                */
    92,                                          /* octets in ciphertext     */
    srtp_aes_gcm_double_test_case_1_ciphertext,  /* ciphertext  + tag        */
    27,                                          /* octets in AAD            */
    srtp_aes_gcm_double_test_case_1_aad,         /* AAD                      */
    GCM_DOUBLE_AUTH_TAG_LEN,
    NULL                                         /* pointer to next testcase */
};

static const srtp_cipher_test_case_t srtp_aes_gcm_double_test_case_1 = {
    SRTP_AES_GCM_256_DOUBLE_KEY_LEN_WSALT,      /* octets in key            */
    srtp_aes_gcm_double_test_case_1_key,        /* key                      */
    srtp_aes_gcm_double_test_case_1_iv,         /* packet index             */
    60,                                         /* octets in plaintext      */
    srtp_aes_gcm_double_test_case_1_plaintext,  /* plaintext                */
    92,                                         /* octets in ciphertext     */
    srtp_aes_gcm_double_test_case_1_ciphertext, /* ciphertext  + tag        */
    27,                                         /* octets in AAD            */
    srtp_aes_gcm_double_test_case_1_aad,        /* AAD                      */
    GCM_DOUBLE_AUTH_TAG_LEN,
    &srtp_aes_gcm_double_test_case_1_0          /* pointer to next testcase */
};

/*
 * This is the vector function table for this crypto engine.
 */
const srtp_cipher_type_t srtp_aes_gcm_128_double_openssl = {
    srtp_aes_gcm_double_openssl_alloc,
    srtp_aes_gcm_double_openssl_dealloc,
    srtp_aes_gcm_double_openssl_context_init,
    srtp_aes_gcm_double_openssl_set_aad,
    srtp_aes_gcm_double_openssl_encrypt,
    srtp_aes_gcm_double_openssl_decrypt,
    srtp_aes_gcm_double_openssl_set_iv,
    srtp_aes_gcm_double_openssl_get_tag,
    srtp_aes_gcm_128_double_openssl_description,
    &srtp_aes_gcm_double_test_case_0,
    SRTP_AES_GCM_128_DOUBLE
};

/*
 * This is the vector function table for this crypto engine.
 */
const srtp_cipher_type_t srtp_aes_gcm_256_double_openssl = {
    srtp_aes_gcm_double_openssl_alloc,
    srtp_aes_gcm_double_openssl_dealloc,
    srtp_aes_gcm_double_openssl_context_init,
    srtp_aes_gcm_double_openssl_set_aad,
    srtp_aes_gcm_double_openssl_encrypt,
    srtp_aes_gcm_double_openssl_decrypt,
    srtp_aes_gcm_double_openssl_set_iv,
    srtp_aes_gcm_double_openssl_get_tag,
    srtp_aes_gcm_256_double_openssl_description,
    &srtp_aes_gcm_double_test_case_1,
    SRTP_AES_GCM_256_DOUBLE
};

