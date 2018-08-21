/*
 * aes_gcm_double.c
 *
 * Double AES Galois Counter Mode
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

#include "aes_gcm_double.h"
#include "alloc.h"
#include "err.h" /* for srtp_debug */
#include "crypto_types.h"
#include "cipher_types.h"

srtp_debug_module_t srtp_mod_aes_gcm_double = {
    0,               /* debugging is off by default */
    "aes gcm double" /* printable module name       */
};

/*
 * For now, we only support a full-length auth tag
 */
#define GCM_IV_LEN 12
#define GCM_AUTH_TAG_LEN 16

#define SRTP_AES_128_DOUBLE_KEY_LEN                                            \
    (SRTP_AES_128_KEY_LEN + SRTP_AES_128_KEY_LEN)
#define SRTP_AES_256_DOUBLE_KEY_LEN                                            \
    (SRTP_AES_256_KEY_LEN + SRTP_AES_256_KEY_LEN)

// +-+-+-+-+-+-+-+-+
// |R R R R B M P Q|
// +-+-+-+-+-+-+-+-+
#define OHB_MODIFIED_SEQ 0x01
#define OHB_MODIFIED_PT 0x02
#define OHB_MODIFIED_M 0x04

#define RTP_HEADER_SIZE 12

/*
 * This function allocates a new instance of this crypto engine.
 * The key_size parameter should be one of 56 or 88 for
 * AES-128-GCM-DOUBLE or AES-256-GCM-DOUBLE respectively.  Note
 * that the key length includes the 14 byte salt value that is
 * used when initializing the KDF.
 */
static srtp_err_status_t srtp_aes_gcm_double_alloc(srtp_cipher_t **c,
                                                   int key_size,
                                                   int tlen)
{
    srtp_err_status_t err;
    srtp_aes_gcm_double_ctx_t *dbl;

    debug_print(srtp_mod_aes_gcm_double, "allocating cipher with key length %d",
                key_size);
    debug_print(srtp_mod_aes_gcm_double, "allocating cipher with tag length %d",
                tlen);

    /*
     * Verify the key_size is valid for one of: AES-128/256
     */
    if (key_size != SRTP_AES_GCM_128_DOUBLE_KEY_LEN_WSALT &&
        key_size != SRTP_AES_GCM_256_DOUBLE_KEY_LEN_WSALT) {
        return (srtp_err_status_bad_param);
    }

    if (tlen > GCM_DOUBLE_MAX_AUTH_TAG_LEN) {
        return (srtp_err_status_bad_param);
    }

    /* allocate the base structs */
    *c = (srtp_cipher_t *)srtp_crypto_alloc(sizeof(srtp_cipher_t));
    if (*c == NULL) {
        return (srtp_err_status_alloc_fail);
    }

    dbl = (srtp_aes_gcm_double_ctx_t *)srtp_crypto_alloc(
        sizeof(srtp_aes_gcm_double_ctx_t));
    if (dbl == NULL) {
        srtp_crypto_free(*c);
        *c = NULL;
        return (srtp_err_status_alloc_fail);
    }

    /* configure the base state */
    (*c)->state = dbl;
    (*c)->key_len = key_size;

    /* setup cipher attributes */
    const srtp_cipher_type_t *base_type = NULL;
    int base_key_size_wsalt = 0;
    switch (key_size) {
    case SRTP_AES_GCM_128_DOUBLE_KEY_LEN_WSALT:
        (*c)->type = &srtp_aes_gcm_128_double;
        (*c)->algorithm = SRTP_AES_GCM_128_DOUBLE;
        dbl->key_size = SRTP_AES_128_DOUBLE_KEY_LEN;
        base_type = &srtp_aes_gcm_128;
        base_key_size_wsalt = SRTP_AES_GCM_128_KEY_LEN_WSALT;
        break;
    case SRTP_AES_GCM_256_DOUBLE_KEY_LEN_WSALT:
        (*c)->type = &srtp_aes_gcm_256_double;
        (*c)->algorithm = SRTP_AES_GCM_256_DOUBLE;
        dbl->key_size = SRTP_AES_256_DOUBLE_KEY_LEN;
        base_type = &srtp_aes_gcm_256;
        base_key_size_wsalt = SRTP_AES_GCM_256_KEY_LEN_WSALT;
        break;
    }

    /* allocate inner and outer contexts */
    err = base_type->alloc(&dbl->inner, base_key_size_wsalt, GCM_AUTH_TAG_LEN);
    if (err != srtp_err_status_ok) {
        debug_print(srtp_mod_aes_gcm_double, "error alloc inner: %d", err);
        srtp_crypto_free(*c);
        *c = NULL;
        return err;
    }

    err = base_type->alloc(&dbl->outer, base_key_size_wsalt, GCM_AUTH_TAG_LEN);
    if (err != srtp_err_status_ok) {
        debug_print(srtp_mod_aes_gcm_double, "error alloc outer: %d", err);
        srtp_crypto_free(*c);
        *c = NULL;
        return err;
    }

    return (srtp_err_status_ok);
}

/*
 * This function deallocates a double GCM session
 */
static srtp_err_status_t srtp_aes_gcm_double_dealloc(srtp_cipher_t *c)
{
    srtp_err_status_t err;
    srtp_aes_gcm_double_ctx_t *ctx;

    debug_print(srtp_mod_aes_gcm_double, "dealloc", NULL);

    ctx = (srtp_aes_gcm_double_ctx_t *)c->state;
    if (ctx) {
        /* free the undelying contexts */
        err = ctx->inner->type->dealloc(ctx->inner);
        if (err != srtp_err_status_ok) {
            return err;
        }

        err = ctx->outer->type->dealloc(ctx->outer);
        if (err != srtp_err_status_ok) {
            return err;
        }

        /* zeroize everything else */
        octet_string_set_to_zero(ctx, sizeof(srtp_aes_gcm_double_ctx_t));
        srtp_crypto_free(ctx);
    }

    /* free memory */
    srtp_crypto_free(c);

    return (srtp_err_status_ok);
}

/*
 * aes_gcm_double_context_init(...) initializes the aes_gcm_double_context
 * using the value in key[].  The first half is assigned to the
 * inner transform, and the second half is assigned to the outer
 * transform.
 */
static srtp_err_status_t srtp_aes_gcm_double_context_init(void *cv,
                                                          const uint8_t *key)
{
    srtp_err_status_t err;
    srtp_aes_gcm_double_ctx_t *c = (srtp_aes_gcm_double_ctx_t *)cv;
    int base_key_size = c->key_size / 2;

    debug_print(srtp_mod_aes_gcm_double, "init with key %s",
                srtp_octet_string_hex_string(key, c->key_size));

    /* Initialize the inner context */
    debug_print(srtp_mod_aes_gcm_double, "inner key: %s",
                srtp_octet_string_hex_string(key, base_key_size));

    err = c->inner->type->init(c->inner->state, key);
    if (err != srtp_err_status_ok) {
        return err;
    }

    /* Initialize the outer context */
    debug_print(
        srtp_mod_aes_gcm_double, "outer key: %s",
        srtp_octet_string_hex_string(key + base_key_size, base_key_size));

    err = c->outer->type->init(c->outer->state, key + base_key_size);
    if (err != srtp_err_status_ok) {
        return err;
    }

    return (srtp_err_status_ok);
}

/*
 * aes_gcm_double_set_iv(c, iv) splits the IV in two equal halves.
 * The first half is set as the IV for the inner transform, and the
 * second half as the IV for the outer transform.
 */
static srtp_err_status_t srtp_aes_gcm_double_set_iv(
    void *cv,
    uint8_t *iv,
    srtp_cipher_direction_t direction)
{
    // XXX(rlb@ipv.sx): Spec probably needs updating here to
    // generate a double-length IV

    srtp_err_status_t err;
    srtp_aes_gcm_double_ctx_t *c = (srtp_aes_gcm_double_ctx_t *)cv;
    int iv_size = GCM_IV_LEN;

    if (direction != srtp_direction_encrypt &&
        direction != srtp_direction_decrypt) {
        return (srtp_err_status_bad_param);
    }
    c->dir = direction;

    debug_print(srtp_mod_aes_gcm_double, "set_iv: %s",
                srtp_octet_string_hex_string(iv, GCM_IV_LEN + GCM_IV_LEN));

    /* Initialize the inner context */
    debug_print(srtp_mod_aes_gcm_double, "inner iv: %s",
                srtp_octet_string_hex_string(iv, iv_size));

    err = c->inner->type->set_iv(c->inner->state, iv, direction);
    if (err != srtp_err_status_ok) {
        debug_print(srtp_mod_aes_gcm_double, "error setting inner IV: %d", err);
        return err;
    }

    /* Initialize the outer context */
    debug_print(srtp_mod_aes_gcm_double, "outer iv: %s",
                srtp_octet_string_hex_string(iv + iv_size, iv_size));

    err = c->outer->type->set_iv(c->outer->state, iv + iv_size, direction);
    if (err != srtp_err_status_ok) {
        debug_print(srtp_mod_aes_gcm_double, "error setting outer IV: %d", err);
        return err;
    }

    return (srtp_err_status_ok);
}

/*
 * aes_gcm_double_set_aad(c, aad) sets the AAD for this tranform.
 * Because the AAD requires processing between the inner and outer
 * transforms, at this stage we just buffer it.
 */
static srtp_err_status_t srtp_aes_gcm_double_set_aad(void *cv,
                                                     const uint8_t *aad,
                                                     uint32_t aad_size)
{
    srtp_aes_gcm_double_ctx_t *c = (srtp_aes_gcm_double_ctx_t *)cv;

    debug_print(srtp_mod_aes_gcm_double, "setting AAD: %s",
                srtp_octet_string_hex_string(aad, aad_size));

    if (aad_size + c->aad_size > GCM_DOUBLE_MAX_AD_LEN) {
        return srtp_err_status_bad_param;
    }

    memcpy(c->aad + c->aad_size, aad, aad_size);
    c->aad_size += aad_size;

    return (srtp_err_status_ok);
}

/*
 * This function encrypts a buffer using AES GCM mode
 *
 * XXX(rlb@ipv.sx): This method MUST only be called once, with the
 * whole packet.  It is not compatible with the streaming API uses.
 */
static srtp_err_status_t srtp_aes_gcm_double_encrypt(void *cv,
                                                     unsigned char *buf,
                                                     unsigned int *enc_size)
{
    srtp_err_status_t err;
    srtp_aes_gcm_double_ctx_t *c = (srtp_aes_gcm_double_ctx_t *)cv;

    /* This transform requires a minimum amount of AAD */
    if (c->aad_size < RTP_HEADER_SIZE) {
        return srtp_err_status_bad_param;
    }

    /*
     * Prepare the AAD for the inner transform by unsetting the X
     * bit and truncating to remove the extension.
     */
    unsigned char x = c->aad[0] & 0x10;
    c->aad[0] = c->aad[0] & 0xef;
    int cc = c->aad[0] & 0x0f;
    int inner_aad_size = RTP_HEADER_SIZE + (4 * cc);
    if (inner_aad_size > c->aad_size) {
        return srtp_err_status_bad_param;
    }

    /* Set the AAD for the inner transform and reset the X bit */
    debug_print(srtp_mod_aes_gcm_double, "inner aad: %s",
                srtp_octet_string_hex_string(c->aad, inner_aad_size));
    err = c->inner->type->set_aad(c->inner->state, c->aad, inner_aad_size);
    if (err != srtp_err_status_ok) {
        return err;
    }

    /* Reset the X bit and set the AAD for the outer transform */
    c->aad[0] |= x;
    debug_print(srtp_mod_aes_gcm_double, "outer aad: %s",
                srtp_octet_string_hex_string(c->aad, c->aad_size));
    err = c->outer->type->set_aad(c->outer->state, c->aad, c->aad_size);
    if (err != srtp_err_status_ok) {
        return err;
    }

    /* Copy the plaintext into a working buffer */
    // XXX(rlb@ipv.sx): This is super wasteful, but avoids a lot of
    // of the interpretation risks of the current API
    unsigned int pt_size = *enc_size;
    unsigned int ct_size = *enc_size;
    unsigned char
        ct[GCM_DOUBLE_MAX_PLAINTEXT_LEN + GCM_DOUBLE_MAX_AUTH_TAG_LEN];
    if (*enc_size > GCM_DOUBLE_MAX_PLAINTEXT_LEN) {
        return srtp_err_status_bad_param;
    }
    memset(ct, 0, GCM_DOUBLE_MAX_PLAINTEXT_LEN + GCM_DOUBLE_MAX_AUTH_TAG_LEN);
    memcpy(ct, buf, *enc_size);

    debug_print(srtp_mod_aes_gcm_double, "inner plaintext: %s",
                srtp_octet_string_hex_string(ct, ct_size));

    /* Perform the inner encryption */
    err = c->inner->type->encrypt(c->inner->state, ct, &ct_size);
    if (err != srtp_err_status_ok) {
        return err;
    }

    /* Read the inner tag into the buffer */
    unsigned int tag_size = 0;
    err = c->inner->type->get_tag(c->inner->state, ct + ct_size, &tag_size);
    if (err != srtp_err_status_ok) {
        return err;
    }

    debug_print(srtp_mod_aes_gcm_double, "inner ciphertext: %s",
                srtp_octet_string_hex_string(ct, ct_size + tag_size));

    /* Append a null byte */
    ct_size += tag_size + 1;

    debug_print(srtp_mod_aes_gcm_double, "outer plaintext: %s",
                srtp_octet_string_hex_string(ct, ct_size));

    /* Perform the outer encryption */
    err = c->outer->type->encrypt(c->outer->state, ct, &ct_size);
    if (err != srtp_err_status_ok) {
        return err;
    }

    /* Read the outer tag into the buffer */
    tag_size = 0;
    err = c->outer->type->get_tag(c->outer->state, ct + ct_size, &tag_size);
    if (err != srtp_err_status_ok) {
        return err;
    }

    ct_size += tag_size;

    debug_print(srtp_mod_aes_gcm_double, "outer ciphertext: %s",
                srtp_octet_string_hex_string(ct, ct_size));

    /* Copy the ciphertext and tag to their respective buffers */
    memcpy(buf, ct, pt_size);

    c->tag_size = ct_size - pt_size;
    memcpy(c->tag, ct + pt_size, c->tag_size);

    /* Reset AAD */
    c->aad_size = 0;

    return srtp_err_status_ok;
}

/*
 * This function calculates and returns the cached tag for a given context.
 * This should be called after encrypting the data.  The *len value
 * is increased by the tag size.  The caller must ensure that *buf has
 * enough room to accept the appended tag.
 */
static srtp_err_status_t srtp_aes_gcm_double_get_tag(void *cv,
                                                     uint8_t *buf,
                                                     uint32_t *len)
{
    srtp_aes_gcm_double_ctx_t *c = (srtp_aes_gcm_double_ctx_t *)cv;
    *len = c->tag_size;
    memcpy(buf, c->tag, c->tag_size);
    return (srtp_err_status_ok);
}

/*
 * This function decrypts a buffer using double AES GCM mode
 */
static srtp_err_status_t srtp_aes_gcm_double_decrypt(void *cv,
                                                     unsigned char *buf,
                                                     unsigned int *enc_size)
{
    srtp_err_status_t err;
    srtp_aes_gcm_double_ctx_t *c = (srtp_aes_gcm_double_ctx_t *)cv;

    /* Set the outer AAD */
    debug_print(srtp_mod_aes_gcm_double, "outer aad: %s",
                srtp_octet_string_hex_string(c->aad, c->aad_size));
    err = c->outer->type->set_aad(c->outer->state, c->aad, c->aad_size);
    if (err != srtp_err_status_ok) {
        return err;
    }

    /* Perform the outer decryption */
    err = c->outer->type->decrypt(c->outer->state, buf, enc_size);
    if (err != srtp_err_status_ok) {
        return err;
    }

    debug_print(srtp_mod_aes_gcm_double, "outer plaintext: %s",
                srtp_octet_string_hex_string(buf, *enc_size));

    if (*enc_size < MAX_OHB_LEN) {
        return srtp_err_status_auth_fail;
    }

    /* Parse the OHB and apply it to the AAD */
    *enc_size -= 1;
    unsigned int config = buf[*enc_size];
    if (config & 0xf0) {
        return srtp_err_status_auth_fail;
    }

    if (config & OHB_MODIFIED_SEQ) {
        *enc_size -= 2;
        c->aad[2] = buf[*enc_size];
        c->aad[3] = buf[*enc_size + 1];
    }
    if (config & OHB_MODIFIED_PT) {
        *enc_size -= 1;
        c->aad[1] = (c->aad[1] & 0x80) | (buf[*enc_size] & 0x7f);
    }
    if (config & OHB_MODIFIED_M) {
        c->aad[1] = (c->aad[1] & 0x7f) | ((config >> 3) << 7);
    }

    /* Unset the X bit */
    c->aad[0] = c->aad[0] & 0xef;

    /* Truncate the inner AAD to remove the extension */
    int cc = c->aad[0] & 0x0f;
    int inner_aad_size = RTP_HEADER_SIZE + (4 * cc);
    if (inner_aad_size > c->aad_size) {
        return srtp_err_status_bad_param;
    }

    /* Set the inner AAD */
    debug_print(srtp_mod_aes_gcm_double, "inner aad: %s",
                srtp_octet_string_hex_string(c->aad, inner_aad_size));

    err = c->inner->type->set_aad(c->inner->state, c->aad, inner_aad_size);
    if (err != srtp_err_status_ok) {
        return err;
    }

    /* Perform the inner decryption */
    debug_print(srtp_mod_aes_gcm_double, "inner ciphertext: %s",
                srtp_octet_string_hex_string(buf, *enc_size));

    err = c->inner->type->decrypt(c->inner->state, buf, enc_size);
    if (err != srtp_err_status_ok) {
        return err;
    }

    debug_print(srtp_mod_aes_gcm_double, "inner plaintext: %s",
                srtp_octet_string_hex_string(buf, *enc_size));

    /* Reset AAD */
    c->aad_size = 0;

    return srtp_err_status_ok;
}

/*
 * Name of this crypto engine
 */
static const char srtp_aes_gcm_128_double_description[] = "Double AES-128 GCM";
static const char srtp_aes_gcm_256_double_description[] = "Double AES-256 GCM";

/*
 * KAT values for AES self-test.  These
 * values we're derived from independent test code
 * using the Go crypto library.
 */
/* clang-format off */
static const uint8_t srtp_aes_gcm_double_test_key_128[SRTP_AES_GCM_128_DOUBLE_KEY_LEN_WSALT] = {
    0x95, 0x9a, 0x19, 0x07, 0x83, 0xce, 0x31, 0x2d,
    0xb4, 0xef, 0xdc, 0x1d, 0x0f, 0x0e, 0xf9, 0x85,
    0xed, 0x77, 0xbb, 0x00, 0x32, 0x34, 0x6d, 0x65,
    0xff, 0x08, 0xf3, 0x40, 0x97, 0xc3, 0x27, 0x35,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
};

static const uint8_t srtp_aes_gcm_double_test_key_256[SRTP_AES_GCM_256_DOUBLE_KEY_LEN_WSALT] = {
    0x1e, 0x69, 0x10, 0xc1, 0xc0, 0x25, 0x96, 0x05,
    0xbc, 0x0a, 0xea, 0xf1, 0x6c, 0xcb, 0x2a, 0x2f,
    0x2e, 0x4e, 0x0c, 0x7f, 0x2d, 0xef, 0x1d, 0x0f,
    0x08, 0xbb, 0x72, 0x96, 0x74, 0x32, 0x53, 0x43,
    0x9e, 0x7d, 0x33, 0xfb, 0x26, 0xeb, 0x3d, 0x56,
    0xb7, 0xc9, 0x72, 0x76, 0xd9, 0x45, 0x27, 0x0a,
    0xc9, 0xad, 0x69, 0x08, 0xa0, 0x67, 0x7e, 0x16,
    0xe2, 0x86, 0xc7, 0x11, 0x17, 0x30, 0x08, 0x44,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
};

static uint8_t srtp_aes_gcm_double_test_iv[24] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
    0xde, 0xca, 0xf8, 0x88, 0xca, 0xfe, 0xba, 0xbe,
    0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
};

static const uint8_t srtp_aes_gcm_double_test_aad[20] = {
    0xf1, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xab, 0xad, 0xda, 0xd2,
};

static const uint8_t srtp_aes_gcm_double_test_plaintext[60] = {
    0x34, 0x25, 0x0c, 0xe8, 0xb6, 0xbf, 0xd5, 0x01,
    0xb6, 0xc8, 0x5a, 0xc8, 0x8b, 0x54, 0x54, 0xe8,
    0xad, 0x38, 0x73, 0xdd, 0x19, 0x44, 0x2a, 0x14,
    0x9f, 0xd8, 0x13, 0xd1, 0x29, 0xe3, 0x3b, 0xfe,
    0xff, 0x7c, 0x2d, 0xa4, 0x6c, 0x5f, 0x66, 0x35,
    0xd8, 0x75, 0x66, 0xb9, 0xc5, 0x08, 0xa1, 0x78,
    0xc6, 0xee, 0xea, 0x6f, 0xca, 0x2e, 0x38, 0xbc,
    0xff, 0x06, 0x0f, 0x51,
};

static const uint8_t srtp_aes_gcm_double_test_ciphertext_128[93] = {
    0x7d, 0xb3, 0xaf, 0xec, 0x3d, 0x4a, 0xfc, 0x1e,
    0x85, 0xea, 0x90, 0x9a, 0x30, 0x9a, 0x83, 0xf6,
    0x87, 0x57, 0x67, 0x00, 0x7f, 0x57, 0xe3, 0x24,
    0x77, 0xdb, 0x19, 0x6b, 0xe5, 0x4f, 0xf5, 0x63,
    0xd4, 0x94, 0x81, 0x3a, 0x3d, 0x12, 0x0a, 0xeb,
    0xcb, 0x80, 0xdd, 0x2d, 0x0f, 0x0a, 0xf2, 0x97,
    0x66, 0x54, 0xdd, 0xd2, 0xdb, 0x4b, 0x87, 0xca,
    0x32, 0x8b, 0x63, 0xaf, 0x61, 0x48, 0x92, 0x29,
    0x8c, 0x4d, 0xc0, 0x5d, 0xfc, 0x79, 0x03, 0xe4,
    0xb6, 0xd0, 0x8e, 0xf1, 0x54, 0x19, 0x6e, 0xda,
    0x31, 0x3c, 0x79, 0xef, 0x43, 0x5e, 0xb9, 0x3f,
    0xaa, 0xfe, 0x39, 0xe4, 0xb0,
};

static const uint8_t srtp_aes_gcm_double_test_ciphertext_256[93] = {
    0x1f, 0xaa, 0x28, 0xc6, 0x2a, 0x3e, 0x8e, 0x9e,
    0xb9, 0x25, 0xf8, 0x26, 0x00, 0x39, 0xae, 0x43,
    0x0e, 0xc5, 0x1f, 0xed, 0x5b, 0x61, 0xb1, 0x1b,
    0xf5, 0x9c, 0xd5, 0x59, 0x93, 0x9d, 0x3f, 0xcd,
    0xc9, 0x66, 0xf7, 0x85, 0xe0, 0xff, 0x1a, 0xf7,
    0xbc, 0x0a, 0xdc, 0x47, 0x25, 0xf7, 0x02, 0x8d,
    0x54, 0xc8, 0x4a, 0x6e, 0xce, 0x6d, 0x64, 0x56,
    0x60, 0x4a, 0xec, 0x25, 0xbb, 0x6d, 0xda, 0x0c,
    0xd0, 0xb9, 0xde, 0xa0, 0xd1, 0x97, 0x59, 0xe5,
    0x4b, 0xa0, 0xda, 0xc8, 0x2d, 0xf2, 0x92, 0x07,
    0x6d, 0xdf, 0x7e, 0x85, 0x97, 0xfa, 0xb3, 0x3d,
    0x1c, 0x18, 0x15, 0xa5, 0xc0,
};

/* clang-format on */

static const srtp_cipher_test_case_t srtp_aes_gcm_128_double_test_case = {
    SRTP_AES_GCM_128_DOUBLE_KEY_LEN_WSALT,   /* octets in key            */
    srtp_aes_gcm_double_test_key_128,        /* key                      */
    srtp_aes_gcm_double_test_iv,             /* packet index             */
    60,                                      /* octets in plaintext      */
    srtp_aes_gcm_double_test_plaintext,      /* plaintext                */
    93,                                      /* octets in ciphertext     */
    srtp_aes_gcm_double_test_ciphertext_128, /* ciphertext  + tag        */
    20,                                      /* octets in AAD            */
    srtp_aes_gcm_double_test_aad,            /* AAD                      */
    GCM_AUTH_TAG_LEN + 1 + GCM_AUTH_TAG_LEN, /* */
    NULL                                     /* pointer to next testcase */
};

static const srtp_cipher_test_case_t srtp_aes_gcm_256_double_test_case = {
    SRTP_AES_GCM_256_DOUBLE_KEY_LEN_WSALT,   /* octets in key            */
    srtp_aes_gcm_double_test_key_256,        /* key                      */
    srtp_aes_gcm_double_test_iv,             /* packet index             */
    60,                                      /* octets in plaintext      */
    srtp_aes_gcm_double_test_plaintext,      /* plaintext                */
    93,                                      /* octets in ciphertext     */
    srtp_aes_gcm_double_test_ciphertext_256, /* ciphertext  + tag        */
    20,                                      /* octets in AAD            */
    srtp_aes_gcm_double_test_aad,            /* AAD                      */
    GCM_AUTH_TAG_LEN + 1 + GCM_AUTH_TAG_LEN, /* */
    NULL                                     /* pointer to next testcase */
};

/*
 * This is the vector function table for this crypto engine.
 */
const srtp_cipher_type_t srtp_aes_gcm_128_double = {
    srtp_aes_gcm_double_alloc,
    srtp_aes_gcm_double_dealloc,
    srtp_aes_gcm_double_context_init,
    srtp_aes_gcm_double_set_aad,
    srtp_aes_gcm_double_encrypt,
    srtp_aes_gcm_double_decrypt,
    srtp_aes_gcm_double_set_iv,
    srtp_aes_gcm_double_get_tag,
    srtp_aes_gcm_128_double_description,
    &srtp_aes_gcm_128_double_test_case,
    SRTP_AES_GCM_128_DOUBLE
};

/*
 * This is the vector function table for this crypto engine.
 */
const srtp_cipher_type_t srtp_aes_gcm_256_double = {
    srtp_aes_gcm_double_alloc,
    srtp_aes_gcm_double_dealloc,
    srtp_aes_gcm_double_context_init,
    srtp_aes_gcm_double_set_aad,
    srtp_aes_gcm_double_encrypt,
    srtp_aes_gcm_double_decrypt,
    srtp_aes_gcm_double_set_iv,
    srtp_aes_gcm_double_get_tag,
    srtp_aes_gcm_256_double_description,
    &srtp_aes_gcm_256_double_test_case,
    SRTP_AES_GCM_256_DOUBLE
};
