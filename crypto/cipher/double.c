/*
 * double.c
 *
 * Doubled AEAD mode, with specialization to AES-GCM
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

srtp_debug_module_t srtp_mod_double = {
    0,               /* debugging is off by default */
    "double"         /* printable module name       */
};

#define MAX_AAD_LEN                512
#define MAX_TAG_LEN                64

/*
 * The double framework can be used with different combinations of ciphers.
 * Most of the functions below will just work with any length-preserving AEAD
 * cipher.  However, to define a different combination, you will need to define
 * a new srtp_cipher_type_t value and an allocator for it that calls
 * srtp_double_alloc().
 */
typedef struct {
    int inner_key_size;
    int outer_key_size;
    int inner_tag_size;
    int outer_tag_size;
    srtp_cipher_t *inner;
    srtp_cipher_t *outer;
    int do_inner;
    uint8_t inner_aad[MAX_AAD_LEN];
    uint8_t inner_tag[MAX_TAG_LEN];
} srtp_double_ctx_t;

/* XXX: srtp_hdr_t borrowed from srtp_priv.h */
#ifndef WORDS_BIGENDIAN

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
#define E2EEL_LEN         2

/*
 * This function allocates an instance of a doubled cipher, allowing general
 * combinations of ciphers.
 */
static srtp_err_status_t srtp_double_alloc(const srtp_cipher_type_t *inner_type,
                                           const srtp_cipher_type_t *outer_type,
                                           const srtp_cipher_type_t *total_type,
                                           int algorithm,
                                           int inner_key_size, int outer_key_size,
                                           int inner_tag_size, int outer_tag_size,
                                           srtp_cipher_t **c)
{
    srtp_err_status_t err;
    srtp_double_ctx_t *dbl;

    debug_print(srtp_mod_double, "alloc with key size %d", inner_key_size + outer_key_size);
    debug_print(srtp_mod_double, "       ... tag size %d", inner_tag_size + outer_tag_size);

    /* Allocate the base structs */
    *c = (srtp_cipher_t *)srtp_crypto_alloc(sizeof(srtp_cipher_t));
    if (*c == NULL) {
        return (srtp_err_status_alloc_fail);
    }
    memset(*c, 0x0, sizeof(srtp_cipher_t));

    dbl = (srtp_double_ctx_t *)srtp_crypto_alloc(sizeof(srtp_double_ctx_t));
    if (dbl == NULL) {
        srtp_crypto_free(*c);
        *c = NULL;
        return (srtp_err_status_alloc_fail);
    }
    memset(dbl, 0x0, sizeof(srtp_double_ctx_t));

    /* Allocate the inner and outer contexts */
    err = inner_type->alloc(&dbl->inner, inner_key_size + SRTP_AEAD_SALT_LEN, inner_tag_size);
    if (err != srtp_err_status_ok) {
      debug_print(srtp_mod_double, "error alloc inner: %d", err);
      return err;
    }

    err = outer_type->alloc(&dbl->outer, outer_key_size + SRTP_AEAD_SALT_LEN, outer_tag_size);
    if (err != srtp_err_status_ok) {
      debug_print(srtp_mod_double, "error alloc outer: %d", err);
      return err;
    }

    /* Set up the cipher */
    dbl->inner_key_size = inner_key_size;
    dbl->outer_key_size = outer_key_size;
    dbl->inner_tag_size = inner_tag_size;
    dbl->outer_tag_size = outer_tag_size;
    (*c)->state = dbl;
    (*c)->key_len = inner_key_size + outer_key_size;
    (*c)->type = total_type;
    (*c)->algorithm = algorithm;

    debug_print(srtp_mod_double, "alloc ok", NULL);
    return (srtp_err_status_ok);
}

/*
 * This function deallocates a GCM session
 */
static srtp_err_status_t srtp_double_dealloc (srtp_cipher_t *c)
{
    srtp_double_ctx_t *ctx;

    debug_print(srtp_mod_double, "dealloc", NULL);

    ctx = (srtp_double_ctx_t*)c->state;
    if (ctx) {
        ctx->inner->type->dealloc(ctx->inner);
        ctx->outer->type->dealloc(ctx->outer);

        /* zeroize the key material */
        octet_string_set_to_zero(ctx, sizeof(srtp_double_ctx_t));
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
static srtp_err_status_t srtp_double_context_init (void* cv, const uint8_t *key)
{
    uint8_t inner_non_zero;
    srtp_err_status_t err;
    srtp_double_ctx_t *c = (srtp_double_ctx_t *)cv;

    debug_print(srtp_mod_double, "init with key %s",
                srtp_octet_string_hex_string(key, c->inner_key_size + c->outer_key_size));

    /* This context performs the inner transform iff the inner key is not all zero */
    inner_non_zero = 0;
    for (int i=0; i < c->inner_key_size; i++) {
        inner_non_zero |= key[i];
    }

    c->do_inner = 0;
    if (inner_non_zero != 0) {
        c->do_inner = 1;
    }

    /* Initialize the inner and outer contexts */
    if (c->do_inner) {
        err = c->inner->type->init(c->inner->state, key);
        if (err != srtp_err_status_ok) {
            return err;
        }
    }

    return c->outer->type->init(c->outer->state, key + c->inner_key_size);
}


/*
 * aes_gcm_openssl_set_iv(c, iv) sets the counter value to the exor of iv with
 * the offset
 *
 * XXX: We use the same IV for both inner and outer contexts.  This should be
 * safe because the keys should be different.
 */
static srtp_err_status_t srtp_double_set_iv (void *cv, uint8_t *iv, srtp_cipher_direction_t direction)
{
    srtp_err_status_t err;
    srtp_double_ctx_t *c = (srtp_double_ctx_t *)cv;

    debug_print(srtp_mod_double, "iv: %s",
                srtp_octet_string_hex_string(iv, 12));

    if (c->do_inner) {
        err = c->inner->type->set_iv(c->inner->state, iv, direction);
        if (err != srtp_err_status_ok) {
            return err;
        }
    }

    return c->outer->type->set_iv(c->outer->state, iv, direction);
}

/*
 * This function processes the AAD
 *
 * Parameters:
 *	c	Crypto context
 *	aad	Additional data to process for AEAD cipher suites
 *	aad_len	length of aad buffer
 */
static srtp_err_status_t srtp_double_set_aad (void *cv, const uint8_t *aad, uint32_t aad_len)
{
    srtp_err_status_t err;
    srtp_double_ctx_t *c = (srtp_double_ctx_t *)cv;
    srtp_hdr_t *hdr;
    srtp_hdr_xtnd_t *ext_hdr;
    int inner_aad_len;
    int ext_hdr_len;
    int ext_len;
    uint8_t *ext_data;
    uint8_t ohb_r_pt;
    uint16_t ohb_seq;
    uint16_t e2e_ext_len;

    debug_print(srtp_mod_double, "aad: %s",
                srtp_octet_string_hex_string(aad, aad_len));

    /*
     * Process the End-to-End Extensions Length and Original Headers Block
     * extensions to determine the inner AAD.
     *
     * TODO: Move this to be gated on c->do_inner?
     */
    if ((aad_len < RTP_HDR_LEN) || (aad_len > MAX_AAD_LEN)) {
        return (srtp_err_status_bad_param);
    }

    /* By default, inner AAD only covers the base header */
    memcpy(c->inner_aad, aad, aad_len);
    hdr = (srtp_hdr_t *)c->inner_aad;
    inner_aad_len = RTP_HDR_LEN + (4 * hdr->cc);

    if (hdr->x == 1) {
        ext_hdr = (srtp_hdr_xtnd_t *)(c->inner_aad + inner_aad_len);
        if (ntohs(ext_hdr->profile_specific) == 0xbede) {
            ext_hdr_len = 1;
        } else if ((ntohs(ext_hdr->profile_specific) & 0x1fff) == 0x100) {
            ext_hdr_len = 2;
        } else {
            debug_print(srtp_mod_double, "bad ext_hdr_len %04x", ntohs(ext_hdr->profile_specific));
            return (srtp_err_status_bad_param);
        }

        debug_print(srtp_mod_double, "ext header len: %d", ext_hdr_len);

        /* If len of first extn == 2, append to inner_aad */
        ext_data = ((uint8_t*)ext_hdr) + sizeof(srtp_hdr_xtnd_t);
        ext_len = (ext_hdr_len == 2)? *(ext_data + 1) : (*ext_data & 0x0f) + 1;
        if (ext_len == 2) {
            e2e_ext_len = ntohs(*((uint16_t*) (ext_data + ext_hdr_len)));
            inner_aad_len += RTP_EXT_HDR_LEN + ext_hdr_len + E2EEL_LEN + e2e_ext_len;
            ext_data += ext_hdr_len + E2EEL_LEN + e2e_ext_len;
            if (aad_len < inner_aad_len) {
                debug_print(srtp_mod_double, "bad e2e_ext_len %d", e2e_ext_len);
                return (srtp_err_status_bad_param);
            }

            debug_print(srtp_mod_double, "e2e extensions len: %d", e2e_ext_len);

            /* Adjust the extension length */
            /* XXX: Set padding bytes to zero? and cover those? */
            ext_hdr->length = (ext_hdr_len + E2EEL_LEN + e2e_ext_len) / 4;
            if ((ext_hdr_len + E2EEL_LEN + e2e_ext_len) % 4 > 0) {
                ext_hdr->length += 1;
            }
            ext_hdr->length = htons(ext_hdr->length);

            debug_print(srtp_mod_double, "new extensions len: %02x", ntohs(ext_hdr->length));
        } else {
            /* If there were no E2E extensions, unset the X bit */
            hdr->x = 0;
        }

        /* Process the OHB, if present */
        if (aad_len > inner_aad_len) {
            ext_len = (ext_hdr_len == 2)? *(ext_data + 1) : (*ext_data & 0x0f) + 1;
            if (ext_len == 1) {
                ohb_r_pt = *(ext_data + ext_hdr_len);
                if ((ohb_r_pt & 0x80) != 0) {
                    debug_print(srtp_mod_double, "bad R bit [short] %02x", ohb_r_pt);
                    return (srtp_err_status_bad_param);
                }

                hdr->pt = ohb_r_pt & 0x7f;
                debug_print(srtp_mod_double, "short OHB: R=%d", ohb_r_pt >> 7);
                debug_print(srtp_mod_double, "           PT=%d", ohb_r_pt & 0x7f);
            } else if (ext_len == 3) {
                ohb_r_pt = *(ext_data + ext_hdr_len);
                ohb_seq = *((uint16_t*) (ext_data + ext_hdr_len + 1));
                if ((ohb_r_pt & 0x80) != 0) {
                    debug_print(srtp_mod_double, "bad R bit [long] %02x", ohb_r_pt);
                    return (srtp_err_status_bad_param);
                }

                hdr->pt = ohb_r_pt & 0x7f;
                hdr->seq = ohb_seq;
                debug_print(srtp_mod_double, "long OHB: R=%d", ohb_r_pt >> 7);
                debug_print(srtp_mod_double, "          PT=%02x", ohb_r_pt & 0x7f);
                debug_print(srtp_mod_double, "          SEQ=%04x", ntohs(ohb_seq));
            } else {
                debug_print(srtp_mod_double, "bad OHB length %02x", ext_len);
                return (srtp_err_status_bad_param);
            }
        }
    }

    /* Provide the proper AAD to the inner and outer contexts */
    if (c->do_inner) {
        debug_print(srtp_mod_double, "inner aad: %s",
                    srtp_octet_string_hex_string(c->inner_aad, inner_aad_len));
        err = c->inner->type->set_aad(c->inner->state, c->inner_aad, inner_aad_len);
        if (err != srtp_err_status_ok) {
            return err;
        }
    }

    debug_print(srtp_mod_double, "outer aad: %s",
                srtp_octet_string_hex_string(aad, aad_len));
    return c->outer->type->set_aad(c->outer->state, aad, aad_len);
}

/*
 * This function encrypts a buffer using AES GCM mode
 *
 * Parameters:
 *	c	Crypto context
 *	buf	data to encrypt
 *	enc_len	length of encrypt buffer
 */
static srtp_err_status_t srtp_double_encrypt (void *cv, unsigned char *buf, unsigned int *enc_len)
{
    srtp_err_status_t err;
    srtp_double_ctx_t *c = (srtp_double_ctx_t *)cv;

    debug_print(srtp_mod_double, "plaintext: %s",
                srtp_octet_string_hex_string(buf, *enc_len));

    /*
     * Encrypt the data with the inner transform, if applicable.  If
     * we are not applying the inner transform, then the input is required
     * to be a GCM-protected payload+tag.  So we need to truncate it and
     * cache the tag.
     *
     * XXX: Decreasing enc_len seems likely to cause problems.
     */
    if (c->do_inner) {
        err = c->inner->type->encrypt(c->inner->state, buf, enc_len);
        if (err != srtp_err_status_ok) {
            return err;
        }
    } else {
        *enc_len -= c->inner_tag_size;
        memcpy(c->inner_tag, buf + *enc_len, c->inner_tag_size);
    }

    debug_print(srtp_mod_double, "inner ciphertext: %s",
                srtp_octet_string_hex_string(buf, *enc_len));

    err = c->outer->type->encrypt(c->outer->state, buf, enc_len);

    debug_print(srtp_mod_double, "outer ciphertext: %s",
                srtp_octet_string_hex_string(buf, *enc_len));

    return err;
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
static srtp_err_status_t srtp_double_get_tag (void *cv, uint8_t *buf, uint32_t *len)
{
    srtp_err_status_t err;
    uint32_t temp_len = 0;
    srtp_double_ctx_t *c = (srtp_double_ctx_t *)cv;

    /*
     * The first part of the tag is the tag from the inner transform,
     * encrypted with the outer transform.
     */
    if (c->do_inner) {
        err = c->inner->type->get_tag(c->inner->state, buf, &temp_len);
        if (err != srtp_err_status_ok) {
            return err;
        }
    } else {
        memcpy(buf, c->inner_tag, c->inner_tag_size);
        temp_len = c->inner_tag_size;
    }

    debug_print(srtp_mod_double, "inner tag: %s",
                srtp_octet_string_hex_string(buf, c->inner_tag_size));

    /* XXX: This assumes that encryption is size-preserving */
    err = c->outer->type->encrypt(c->outer->state, buf, &temp_len);
    if (err != srtp_err_status_ok) {
        return err;
    }

    /*
     * The second part of the tag is the tag from the outer tranform
     */
    err = c->outer->type->get_tag(c->outer->state, buf + c->inner_tag_size, &temp_len);
    if (err != srtp_err_status_ok) {
        return err;
    }

    *len = c->inner_tag_size + c->outer_tag_size;

    debug_print(srtp_mod_double, "outer tag: %s",
                srtp_octet_string_hex_string(buf, *len));

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
static srtp_err_status_t srtp_double_decrypt (void *cv, unsigned char *buf, unsigned int *enc_len)
{
    srtp_err_status_t err;
    srtp_double_ctx_t *c = (srtp_double_ctx_t *)cv;

    debug_print(srtp_mod_double, "outer ciphertext: %s",
                srtp_octet_string_hex_string(buf, *enc_len));

    /*
     * Undo the outer transform
     */
    err = c->outer->type->decrypt(c->outer->state, buf, enc_len);
    if (err != srtp_err_status_ok) {
        return err;
    }

    debug_print(srtp_mod_double, "inner ciphertext: %s",
                srtp_octet_string_hex_string(buf, *enc_len));

    /*
     * Undo the inner transform
     */
    if (c->do_inner) {
        err = c->inner->type->decrypt(c->inner->state, buf, enc_len);
    } else {
        err = (srtp_err_status_ok);
    }

    debug_print(srtp_mod_double, "plaintext: %s",
                srtp_octet_string_hex_string(buf, *enc_len));

    return err;
}

/*
 * Here we define the specific instantiation of the double framework with
 * AES-GCM as the inner and outer transforms.  There are two variants, one with
 * AES-128-GCM as the inner and outer transforms, and one with AES-256-GCM
 * likewise.
 */

/*
 * The auth tag for the doubled GCM mode consists of two
 * full-size GCM auth tags.
 */
#define GCM_AUTH_TAG_LEN           16
#define GCM_DOUBLE_AUTH_TAG_LEN    32

/*
 * The following are the global singleton isntances for the
 * base 128-bit and 256-bit GCM ciphers.
 */
extern const srtp_cipher_type_t srtp_aes_gcm_128_openssl;
extern const srtp_cipher_type_t srtp_aes_gcm_256_openssl;

/*
 * The following are the global singleton instances for the
 * 128-bit and 256-bit GCM ciphers.
 */
extern const srtp_cipher_type_t srtp_aes_gcm_128_double_openssl;
extern const srtp_cipher_type_t srtp_aes_gcm_256_double_openssl;


/*
 * This function allocates a new instance of this crypto engine.
 * The key_len parameter should be the length of two AES keys plus
 * the 12-byte salt used by SRTP with AEAD modes:
 *
 *   * 44 = 16 + 16 + 12
 *   * 76 = 32 + 32 + 12
 */
static srtp_err_status_t srtp_aes_gcm_double_openssl_alloc (srtp_cipher_t **c, int key_len, int tag_len)
{
    int base_key_size;
    int base_tag_size;
    const srtp_cipher_type_t *base_type;
    const srtp_cipher_type_t *total_type;
    int algorithm;

    /*
     * Verify the key_len is valid for one of: AES-128/256
     */
    if (key_len != SRTP_AES_GCM_128_DOUBLE_KEY_LEN_WSALT &&
        key_len != SRTP_AES_GCM_256_DOUBLE_KEY_LEN_WSALT) {
        return (srtp_err_status_bad_param);
    }

    if (tag_len != GCM_DOUBLE_AUTH_TAG_LEN) {
        return (srtp_err_status_bad_param);
    }

    /* setup cipher attributes */
    switch (key_len) {
    case SRTP_AES_GCM_128_DOUBLE_KEY_LEN_WSALT:
        base_key_size = SRTP_AES_128_KEY_LEN;
        base_tag_size = GCM_AUTH_TAG_LEN;
        base_type = &srtp_aes_gcm_128_openssl;
        total_type = &srtp_aes_gcm_128_double_openssl;
        algorithm = SRTP_AES_GCM_128_DOUBLE;
        break;
    case SRTP_AES_GCM_256_DOUBLE_KEY_LEN_WSALT:
        base_key_size = SRTP_AES_256_KEY_LEN;
        base_tag_size = GCM_AUTH_TAG_LEN;
        base_type = &srtp_aes_gcm_256_openssl;
        total_type = &srtp_aes_gcm_256_double_openssl;
        algorithm = SRTP_AES_GCM_256_DOUBLE;
        break;
    }

    return srtp_double_alloc(base_type, base_type,
                             total_type, algorithm,
                             base_key_size, base_key_size,
                             base_tag_size, base_tag_size, c);
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

static const uint8_t srtp_aes_gcm_double_test_case_0_aad_no_ext[12] = {
    0x80, 0x01, 0x02, 0x03, 0xde, 0xad, 0xbe, 0xef,
    0xfe, 0xed, 0xfa, 0xce,
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
    0x9e, 0x24, 0x5d, 0xec, 0xe9, 0xde, 0xc5, 0x0c,
    0x12, 0xcf, 0x6f, 0xa5, 0xe1, 0xdd, 0x7c, 0x2f,
    0x38, 0x38, 0xe7, 0x18,
};

static const uint8_t srtp_aes_gcm_double_test_case_0_ciphertext[92] = {
    0x14, 0x9d, 0xc0, 0xb9, 0x2a, 0xa0, 0x36, 0x91,
    0x52, 0x53, 0xc4, 0x22, 0x82, 0x4e, 0xec, 0x4a,
    0x14, 0x2d, 0xc9, 0x40, 0xa5, 0x0f, 0xcd, 0x8e,
    0x5d, 0x2e, 0x9c, 0x61, 0x9f, 0x13, 0x3c, 0x02,
    0xd8, 0x5f, 0x9e, 0x54, 0xbb, 0xc0, 0xec, 0xd5,
    0xb3, 0xe5, 0x22, 0xde, 0xd0, 0xdf, 0x51, 0xe1,
    0x1c, 0xda, 0x6e, 0x5b, 0xca, 0x54, 0xf8, 0x77,
    0x1a, 0x7d, 0xbf, 0xb7, 0x96, 0x0d, 0xab, 0xd3,
    0xeb, 0x67, 0xdd, 0xe8, 0xd7, 0x6b, 0xc2, 0x0e,
    0x95, 0x07, 0x05, 0xb5, 0xda, 0x55, 0x86, 0xe5,
    0x92, 0x3c, 0x20, 0x6c, 0x22, 0xae, 0xc1, 0xe8,
    0x62, 0x3a, 0xc7, 0x09,
};

static const uint8_t srtp_aes_gcm_double_test_case_0_aad_ohb[24] = {
    0x90, 0x01, 0x02, 0x03, 0xde, 0xad, 0xbe, 0xef,
    0xfe, 0xed, 0xfa, 0xce, 0xbe, 0xde, 0x00, 0x02,
    0x10, 0x7f, 0x23, 0xa0, 0xa1, 0xa2, 0xa3, 0x00,
};

static const uint8_t srtp_aes_gcm_double_test_case_0_ciphertext_ohb[92] = {
    0x14, 0x9d, 0xc0, 0xb9, 0x2a, 0xa0, 0x36, 0x91,
    0x52, 0x53, 0xc4, 0x22, 0x82, 0x4e, 0xec, 0x4a,
    0x14, 0x2d, 0xc9, 0x40, 0xa5, 0x0f, 0xcd, 0x8e,
    0x5d, 0x2e, 0x9c, 0x61, 0x9f, 0x13, 0x3c, 0x02,
    0xd8, 0x5f, 0x9e, 0x54, 0xbb, 0xc0, 0xec, 0xd5,
    0xb3, 0xe5, 0x22, 0xde, 0xd0, 0xdf, 0x51, 0xe1,
    0x1c, 0xda, 0x6e, 0x5b, 0xca, 0x54, 0xf8, 0x77,
    0x1a, 0x7d, 0xbf, 0xb7, 0x63, 0x58, 0x69, 0x4d,
    0x9a, 0x59, 0xf6, 0x7e, 0x59, 0xea, 0x65, 0xf4,
    0xde, 0x79, 0x05, 0x90, 0xbe, 0xe2, 0x57, 0x09,
    0x77, 0xd1, 0x8b, 0xa9, 0x41, 0xa4, 0xfc, 0xdd,
    0xc9, 0x0b, 0xd7, 0xa9,
};

static const uint8_t srtp_aes_gcm_double_test_case_0_aad_e2eel[28] = {
    0x90, 0x01, 0x02, 0x03, 0xde, 0xad, 0xbe, 0xef,
    0xfe, 0xed, 0xfa, 0xce, 0xbe, 0xde, 0x00, 0x03,
    0x11, 0x00, 0x03, 0x00, 0x00, 0x00, 0x22, 0x7f,
    0xaa, 0xbb, 0x00, 0x00,
};

static const uint8_t srtp_aes_gcm_double_test_case_0_ciphertext_e2eel[92] = {
    0x14, 0x9d, 0xc0, 0xb9, 0x2a, 0xa0, 0x36, 0x91,
    0x52, 0x53, 0xc4, 0x22, 0x82, 0x4e, 0xec, 0x4a,
    0x14, 0x2d, 0xc9, 0x40, 0xa5, 0x0f, 0xcd, 0x8e,
    0x5d, 0x2e, 0x9c, 0x61, 0x9f, 0x13, 0x3c, 0x02,
    0xd8, 0x5f, 0x9e, 0x54, 0xbb, 0xc0, 0xec, 0xd5,
    0xb3, 0xe5, 0x22, 0xde, 0xd0, 0xdf, 0x51, 0xe1,
    0x1c, 0xda, 0x6e, 0x5b, 0xca, 0x54, 0xf8, 0x77,
    0x1a, 0x7d, 0xbf, 0xb7, 0xca, 0x1e, 0xba, 0x18,
    0x99, 0xf0, 0x0c, 0x3a, 0x54, 0xde, 0x6a, 0xdf,
    0xe6, 0xf6, 0x32, 0x4f, 0xae, 0x52, 0x34, 0x96,
    0x3f, 0x23, 0x1c, 0xae, 0x7f, 0xa2, 0x6f, 0x3b,
    0x1c, 0xb2, 0xa0, 0x56,
};

/* OHB and E2EEL, full key */
static const srtp_cipher_test_case_t srtp_aes_gcm_double_test_case_0_e2eel = {
    SRTP_AES_GCM_128_DOUBLE_KEY_LEN_WSALT,            /* octets in key            */
    srtp_aes_gcm_double_test_case_0_key,              /* key                      */
    srtp_aes_gcm_double_test_case_0_iv,               /* packet index             */
    60,                                               /* octets in plaintext      */
    srtp_aes_gcm_double_test_case_0_plaintext,        /* plaintext                */
    92,                                               /* octets in ciphertext     */
    srtp_aes_gcm_double_test_case_0_ciphertext_e2eel, /* ciphertext  + tag        */
    28,                                               /* octets in AAD            */
    srtp_aes_gcm_double_test_case_0_aad_e2eel,        /* AAD                      */
    GCM_DOUBLE_AUTH_TAG_LEN,
    NULL,                                             /* pointer to next testcase */
};

/* OHB, full key */
static const srtp_cipher_test_case_t srtp_aes_gcm_double_test_case_0_ohb = {
    SRTP_AES_GCM_128_DOUBLE_KEY_LEN_WSALT,          /* octets in key            */
    srtp_aes_gcm_double_test_case_0_key,            /* key                      */
    srtp_aes_gcm_double_test_case_0_iv,             /* packet index             */
    60,                                             /* octets in plaintext      */
    srtp_aes_gcm_double_test_case_0_plaintext,      /* plaintext                */
    92,                                             /* octets in ciphertext     */
    srtp_aes_gcm_double_test_case_0_ciphertext_ohb, /* ciphertext  + tag        */
    24,                                             /* octets in AAD            */
    srtp_aes_gcm_double_test_case_0_aad_ohb,        /* AAD                      */
    GCM_DOUBLE_AUTH_TAG_LEN,
    &srtp_aes_gcm_double_test_case_0_e2eel,         /* pointer to next testcase */
};

/* No extensions, half key */
static const srtp_cipher_test_case_t srtp_aes_gcm_double_test_case_0_0 = {
    SRTP_AES_GCM_128_DOUBLE_KEY_LEN_WSALT,       /* octets in key            */
    srtp_aes_gcm_double_test_case_0_key_0,       /* key                      */
    srtp_aes_gcm_double_test_case_0_iv,          /* packet index             */
    76,                                          /* octets in plaintext      */
    srtp_aes_gcm_double_test_case_0_plaintext_0, /* plaintext                */
    92,                                          /* octets in ciphertext     */
    srtp_aes_gcm_double_test_case_0_ciphertext,  /* ciphertext  + tag        */
    12,                                          /* octets in AAD            */
    srtp_aes_gcm_double_test_case_0_aad_no_ext,  /* AAD                      */
    GCM_DOUBLE_AUTH_TAG_LEN,
    &srtp_aes_gcm_double_test_case_0_ohb,        /* pointer to next testcase */
};

/* No extensions, full key */
static const srtp_cipher_test_case_t srtp_aes_gcm_double_test_case_0 = {
    SRTP_AES_GCM_128_DOUBLE_KEY_LEN_WSALT,      /* octets in key            */
    srtp_aes_gcm_double_test_case_0_key,        /* key                      */
    srtp_aes_gcm_double_test_case_0_iv,         /* packet index             */
    60,                                         /* octets in plaintext      */
    srtp_aes_gcm_double_test_case_0_plaintext,  /* plaintext                */
    92,                                         /* octets in ciphertext     */
    srtp_aes_gcm_double_test_case_0_ciphertext, /* ciphertext  + tag        */
    12,                                         /* octets in AAD            */
    srtp_aes_gcm_double_test_case_0_aad_no_ext, /* AAD                      */
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

static const uint8_t srtp_aes_gcm_double_test_case_1_aad_no_ext[12] = {
    0x80, 0x01, 0x02, 0x03, 0xde, 0xad, 0xbe, 0xef,
    0xfe, 0xed, 0xfa, 0xce,
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
    0xee, 0xc2, 0xdc, 0x4f, 0xf2, 0xec, 0x9a, 0x70,
    0xa0, 0x39, 0xd9, 0xc6, 0xf9, 0x22, 0x86, 0xdf,
    0x1d, 0x69, 0x98, 0xac,
};

static const uint8_t srtp_aes_gcm_double_test_case_1_ciphertext[92] = {
    0x55, 0x45, 0xf2, 0xe7, 0xcf, 0x9c, 0x5d, 0x3c,
    0x0b, 0x85, 0x31, 0x81, 0x5e, 0x34, 0x38, 0x4d,
    0x6d, 0x90, 0x39, 0xb7, 0x49, 0x84, 0x5e, 0xb4,
    0xa2, 0xb1, 0x02, 0x4f, 0xd6, 0xeb, 0x89, 0x07,
    0x7d, 0xe1, 0x36, 0x59, 0x9b, 0x1c, 0xe8, 0xa9,
    0x1d, 0xda, 0xa8, 0x78, 0xfb, 0x0f, 0x2e, 0x3c,
    0x80, 0x30, 0x33, 0x81, 0x86, 0x65, 0x2e, 0x67,
    0x81, 0xc3, 0xf0, 0xbd, 0xab, 0x94, 0xcb, 0x32,
    0x80, 0xdd, 0x62, 0x21, 0x3e, 0x42, 0x46, 0x0f,
    0xbe, 0xe2, 0x49, 0x8f, 0x17, 0xf4, 0x38, 0xb1,
    0x5c, 0xa0, 0x4a, 0xa3, 0xe3, 0x85, 0x76, 0xae,
    0xc3, 0x3a, 0x6e, 0x76,
};

static const srtp_cipher_test_case_t srtp_aes_gcm_double_test_case_1_0 = {
    SRTP_AES_GCM_256_DOUBLE_KEY_LEN_WSALT,       /* octets in key            */
    srtp_aes_gcm_double_test_case_1_key_0,       /* key                      */
    srtp_aes_gcm_double_test_case_1_iv,          /* packet index             */
    76,                                          /* octets in plaintext      */
    srtp_aes_gcm_double_test_case_1_plaintext_0, /* plaintext                */
    92,                                          /* octets in ciphertext     */
    srtp_aes_gcm_double_test_case_1_ciphertext,  /* ciphertext  + tag        */
    12,                                          /* octets in AAD            */
    srtp_aes_gcm_double_test_case_1_aad_no_ext,  /* AAD                      */
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
    12,                                         /* octets in AAD            */
    srtp_aes_gcm_double_test_case_1_aad_no_ext, /* AAD                      */
    GCM_DOUBLE_AUTH_TAG_LEN,
    &srtp_aes_gcm_double_test_case_1_0          /* pointer to next testcase */
};

/*
 * This is the vector function table for this crypto engine.
 */
const srtp_cipher_type_t srtp_aes_gcm_128_double_openssl = {
    srtp_aes_gcm_double_openssl_alloc,
    srtp_double_dealloc,
    srtp_double_context_init,
    srtp_double_set_aad,
    srtp_double_encrypt,
    srtp_double_decrypt,
    srtp_double_set_iv,
    srtp_double_get_tag,
    srtp_aes_gcm_128_double_openssl_description,
    &srtp_aes_gcm_double_test_case_0,
    SRTP_AES_GCM_128_DOUBLE
};

/*
 * This is the vector function table for this crypto engine.
 */
const srtp_cipher_type_t srtp_aes_gcm_256_double_openssl = {
    srtp_aes_gcm_double_openssl_alloc,
    srtp_double_dealloc,
    srtp_double_context_init,
    srtp_double_set_aad,
    srtp_double_encrypt,
    srtp_double_decrypt,
    srtp_double_set_iv,
    srtp_double_get_tag,
    srtp_aes_gcm_256_double_openssl_description,
    &srtp_aes_gcm_double_test_case_1,
    SRTP_AES_GCM_256_DOUBLE
};

