/*
 * aes_wrap.c
 *
 * AES Key Wrap with Padding
 *
 * John A. Foley, Paul E. Jones
 * Cisco Systems, Inc.
 *
 */

/*
 *
 * Copyright (c) 2015, Cisco Systems, Inc.
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

#ifdef OPENSSL
#include <openssl/evp.h>
#include <openssl/aes.h>
#else
#include "aes.h"
#endif

#include "aes_wrap.h"
#include "crypto_types.h"
#include "alloc.h"
#include "crypto_types.h"

/* The default IV for RFC 3394  */
static const unsigned char AES_Key_Wrap_Default_IV[] = {
    0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6
};

/* AIV per RFC 5649         */
static const unsigned char Alternative_IV[] = {
    0xA6, 0x59, 0x59, 0xA6
};

/* Max key wrap length per RFC 5649  */
static const uint32_t AES_Key_Wrap_with_Padding_Max = 0xFFFFFFFF;


srtp_debug_module_t srtp_mod_aes_wrap = {
    0,               /* debugging is off by default */
    "aes key wrap"   /* printable module name       */
};
extern srtp_cipher_type_t srtp_aes_wrap;

/*
 * This function allocates a new instance of this crypto engine.
 * The key_len parameter should be one of 30, 38, or 46 for
 * AES-128, AES-192, and AES-256 respectively.  Note, this key_len
 * value is inflated, as it also accounts for the 112 bit salt
 * value.  The tlen argument is for the AEAD tag length, which
 * isn't used in counter mode.
 */
static srtp_err_status_t srtp_aes_wrap_alloc (srtp_cipher_t **c, int key_len, int tlen)
{
    srtp_aes_wrap_ctx_t *wrap;

    debug_print(srtp_mod_aes_wrap, "allocating cipher with key length %d", key_len);

    if (key_len != SRTP_AES_128_KEYSIZE &&
#ifndef SRTP_NO_AES192
        key_len != SRTP_AES_192_KEYSIZE &&
#endif
        key_len != SRTP_AES_256_KEYSIZE) {
        return srtp_err_status_bad_param;
    }

    /* allocate memory a cipher of type aes_wrap */
    *c = (srtp_cipher_t *)srtp_crypto_alloc(sizeof(srtp_cipher_t));
    if (*c == NULL) {
        return srtp_err_status_alloc_fail;
    }
    memset(*c, 0x0, sizeof(srtp_cipher_t));

    wrap = (srtp_aes_wrap_ctx_t *)srtp_crypto_alloc(sizeof(srtp_aes_wrap_ctx_t));
    if (wrap == NULL) {
        srtp_crypto_free(*c);
        *c = NULL;
        return srtp_err_status_alloc_fail;
    }
    memset(wrap, 0x0, sizeof(srtp_aes_wrap_ctx_t));

    /* set pointers */
    (*c)->state = wrap;

    /* setup cipher parameters */
    (*c)->algorithm = SRTP_AES_WRAP;
    (*c)->type = &srtp_aes_wrap;
    wrap->key_size = key_len;
    wrap->alternate_iv_len = 4; /* default to 4 byte IV for RFC 5649 */
    /* Allocate space for the max IV length */
    wrap->alternate_iv = malloc(8);
    if (!wrap->alternate_iv) {
        srtp_crypto_free(wrap);
        srtp_crypto_free(*c);
        *c = NULL;
        return srtp_err_status_alloc_fail;
    }

    /* set key size        */
    (*c)->key_len = key_len;

    return srtp_err_status_ok;
}


/*
 * This function deallocates an instance of this engine
 */
static srtp_err_status_t srtp_aes_wrap_dealloc (srtp_cipher_t *c)
{
    srtp_aes_wrap_ctx_t *ctx;

    if (c == NULL) {
        return srtp_err_status_bad_param;
    }

    /*
     * Free the context
     */
    ctx = (srtp_aes_wrap_ctx_t*)c->state;
    if (ctx != NULL) {
        if (ctx->alternate_iv) {
            free(ctx->alternate_iv);
        }
        /* zeroize the key material */
        octet_string_set_to_zero((uint8_t*)ctx, sizeof(srtp_aes_wrap_ctx_t));
        srtp_crypto_free(ctx);
    }

    /* free memory */
    srtp_crypto_free(c);

    return srtp_err_status_ok;
}


/*
 * aes_wrap_context_init(...) initializes the aes_wrap_context
 * using the value in key[].
 *
 * the key is the secret key
 *
 * the salt is unpredictable (but not necessarily secret) data which
 * randomizes the starting point in the keystream
 */
static srtp_err_status_t srtp_aes_wrap_context_init (srtp_aes_wrap_ctx_t *c, const uint8_t *key)
{
    /* copy key to be used later when OpenSSL crypto context is created */
    v128_copy_octet_string((v128_t*)&c->key, key);

    /* if the key is greater than 16 bytes, copy the second
     * half.  Note, we treat AES-192 and AES-256 separately here
     * as the source key storage is different. The storage location receiving the
     * key is statically allocated to handle a full 32 byte key
     * regardless of the cipher in use.
     */
    if (c->key_size == SRTP_AES_256_KEYSIZE) {
        debug_print(srtp_mod_aes_wrap, "Copying last 16 bytes of key: %s",
                    v128_hex_string((v128_t*)(key + SRTP_AES_128_KEYSIZE)));
        v128_copy_octet_string(((v128_t*)(&c->key.v8)) + 1, key + SRTP_AES_128_KEYSIZE);
    }
#ifndef SRTP_NO_AES192
    else if (c->key_size == SRTP_AES_192_KEYSIZE) {
        debug_print(srtp_mod_aes_wrap, "Copying last 8 bytes of key: %s",
                    srtp_octet_string_hex_string((key + SRTP_AES_128_KEYSIZE), SRTP_AES_128_KEYSIZE / 2));
       
        v128_copy_octet_string((v128_t*)(&(c->key.v64[1])), key + SRTP_AES_128_KEYSIZE / 2);
    }
#endif

    debug_print(srtp_mod_aes_wrap, "key:  %s", v128_hex_string((v128_t*)&c->key));


    return srtp_err_status_ok;
}

/*
 * srtp_aes_wrap_set_iv(c, iv) sets the key wrap initialization vector and
 * encryption direction.  The iv parameter may be NULL, in which case
 * this module will perform Key Wrap with padding as defined in RFC 5649.
 * Alternatively, the user can pass in an alternate IV using the iv parameter.
 */
static srtp_err_status_t srtp_aes_wrap_set_iv (srtp_aes_wrap_ctx_t *c, const uint8_t *iv, int dir)
{
    /*
     * Set the encryption direction
     */
    c->direction = dir;

    /*
     * Populate the alternate IV value from either the user provided value
     * or the preset value
     */
    if (iv) {
        memcpy(c->alternate_iv, iv, c->alternate_iv_len);
        debug_print(srtp_mod_aes_wrap, "iv:  %s", v128_hex_string((v128_t*)c->alternate_iv));
    } else {
        switch (c->alternate_iv_len) {
        case 4:
            memcpy(c->alternate_iv, Alternative_IV, 4);
            break;
        case 8:
            memcpy(c->alternate_iv, AES_Key_Wrap_Default_IV, 8);
            break;
        default:
            return srtp_err_status_bad_param;
            break;
        }

    }
    return srtp_err_status_ok;
}

/*
 * srtp_aes_wrap_set_iv_len(c, iv_len) sets the IV length
 * This function is optional.  The default IV length is 4, which indicates
 * to perform Key Wrap with padding as defined in RFC 5649.  The user can
 * elect to use this function to set the IV length to 8, in which
 * case this module will perform Key Wrap w/o padding as defined
 * in RFC 3394.  Specifying an IV length other than 4 or 8 will
 * result in an error.
 */
static srtp_err_status_t srtp_aes_wrap_set_iv_len (srtp_aes_wrap_ctx_t *c, const uint8_t iv_len)
{
    /*
     * RFC 5649 uses 4 byte IV, RFC 3394 uses 8 bytes
     */
    if (iv_len == 4 || iv_len == 8) {
        c->alternate_iv_len = iv_len;
        return srtp_err_status_ok;
    } else {
        return srtp_err_status_bad_param;
    }
}

#ifdef OPENSSL
/*
 * This function does simple AES-ECB crypto
 */
static srtp_err_status_t srtp_aes_wrap_ecb_decrypt(srtp_aes_wrap_ctx_t *c,
                                                   const unsigned char *ciphertext,
                                                   unsigned char *plaintext)
{
    EVP_CIPHER_CTX ctx;                         /* Crypto context           */
    const EVP_CIPHER *cipher = NULL;            /* Cipher to use            */
    int plaintext_length = 0;                   /* Length of text           */
    int final_length = 0;                       /* Length of final text     */

    /*
     * Select the cipher based on the key length
     */
    switch (c->key_size) {
    case SRTP_AES_256_KEYSIZE:
        cipher = EVP_aes_256_ecb();
        break;
#ifndef SRTP_NO_AES192
    case SRTP_AES_192_KEYSIZE:
        cipher = EVP_aes_192_ecb();
        break;
#endif
    case SRTP_AES_128_KEYSIZE:
        cipher = EVP_aes_128_ecb();
        break;
    default:
        return srtp_err_status_bad_param;
        break;
    }

    /*
     * Encrypt the plaintext
     */
    EVP_CIPHER_CTX_init(&ctx);

    if (!EVP_DecryptInit_ex(&ctx, cipher, NULL, c->key.v8, NULL)) {
        debug_print(srtp_mod_aes_wrap, "unable to initialize AES ECB cipher for decryption", NULL);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return srtp_err_status_cipher_fail;
    }

    EVP_CIPHER_CTX_set_padding(&ctx, 0);

    if (!EVP_DecryptUpdate(&ctx, plaintext, &plaintext_length, ciphertext, AES_BLOCK_SIZE)) {
        debug_print(srtp_mod_aes_wrap, "call to EVP_DecryptUpdate failed trying to decrypt " "using AES ECB", NULL);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return srtp_err_status_cipher_fail;
    }

    if (!EVP_DecryptFinal_ex(&ctx, plaintext + plaintext_length, &final_length)) {
        debug_print(srtp_mod_aes_wrap, "call to EVP_DecryptFinal failed trying to decrypt " "using AES ECB", NULL);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return srtp_err_status_cipher_fail;
    }

    EVP_CIPHER_CTX_cleanup(&ctx);

    /*
     * Verify the ciphertext length is correct
     */
    if (plaintext_length + final_length != AES_BLOCK_SIZE) {
        debug_print(srtp_mod_aes_wrap, "Unexpected plaintext length in AES ECB encryption", NULL);
        return srtp_err_status_cipher_fail;
    }

    return srtp_err_status_ok;
}



/*
 * This function does simple AES-ECB crypto
 */
static srtp_err_status_t srtp_aes_wrap_ecb_encrypt(srtp_aes_wrap_ctx_t *c,
                                                   const unsigned char *plaintext,
                                                   unsigned char *ciphertext)
{
    EVP_CIPHER_CTX ctx;                         /* Crypto context           */
    const EVP_CIPHER *cipher = NULL;            /* Cipher to use            */
    int ciphertext_length = 0;                  /* Length of ciphertext     */
    int final_length = 0;                       /* Length of final text     */

    /*
     * Select the cipher based on the key length
     */
    switch (c->key_size) {
    case SRTP_AES_256_KEYSIZE:
        cipher = EVP_aes_256_ecb();
        break;
#ifndef SRTP_NO_AES192
    case SRTP_AES_192_KEYSIZE:
        cipher = EVP_aes_192_ecb();
        break;
#endif
    case SRTP_AES_128_KEYSIZE:
        cipher = EVP_aes_128_ecb();
        break;
    default:
        return srtp_err_status_bad_param;
        break;
    }

    /*
     * Encrypt the plaintext
     */
    EVP_CIPHER_CTX_init(&ctx);

    if (!EVP_EncryptInit_ex(&ctx, cipher, NULL, c->key.v8, NULL)) {
        debug_print(srtp_mod_aes_wrap, "unable to initialize AES ECB cipher for encryption", NULL);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return srtp_err_status_cipher_fail;
    }

    EVP_CIPHER_CTX_set_padding(&ctx, 0);

    if (!EVP_EncryptUpdate(&ctx, ciphertext, &ciphertext_length, plaintext, AES_BLOCK_SIZE)) {
        debug_print(srtp_mod_aes_wrap, "call to EVP_EncryptUpdate failed trying to encrypt " "using AES ECB", NULL);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return srtp_err_status_cipher_fail;
    }

    if (!EVP_EncryptFinal_ex(&ctx, ciphertext + ciphertext_length, &final_length)) {
        debug_print(srtp_mod_aes_wrap, "call to EVP_EncryptFinal failed trying to encrypt " "using AES ECB", NULL);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return srtp_err_status_cipher_fail;
    }

    EVP_CIPHER_CTX_cleanup(&ctx);

    /*
     * Verify the ciphertext length is correct
     */
    if (ciphertext_length + final_length != AES_BLOCK_SIZE) {
        debug_print(srtp_mod_aes_wrap, "Unexpected ciphertext length in AES ECB encryption", NULL);
        return srtp_err_status_cipher_fail;
    }

    return srtp_err_status_ok;
}
#else
static srtp_err_status_t srtp_aes_wrap_ecb_decrypt(srtp_aes_wrap_ctx_t *c,
                                                   const unsigned char *ciphertext,
                                                   unsigned char *plaintext)
{
    srtp_aes_expanded_key_t expanded_key; 
    srtp_err_status_t stat;
    v128_t buf;
    int i;

    stat = srtp_aes_expand_encryption_key(c->key.v8, c->key_size, &expanded_key);
    if (stat) {
        return stat;
    }
    stat = srtp_aes_expand_decryption_key(c->key.v8, c->key_size, &expanded_key);
    if (stat) {
        return stat;
    }

    v128_copy_octet_string(&buf, ciphertext);
    srtp_aes_decrypt(&buf, (const srtp_aes_expanded_key_t *)&expanded_key);
    for (i=0; i<16; i++) {
	plaintext[i] = buf.v8[i];
    }

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_aes_wrap_ecb_encrypt(srtp_aes_wrap_ctx_t *c,
                                                   const unsigned char *plaintext,
                                                   unsigned char *ciphertext)
{
    srtp_aes_expanded_key_t expanded_key; 
    srtp_err_status_t stat;
    v128_t buf;
    int i;

    stat = srtp_aes_expand_encryption_key(c->key.v8, c->key_size, &expanded_key);
    if (stat) {
        return stat;
    }

    v128_copy_octet_string(&buf, plaintext);
    srtp_aes_encrypt(&buf, (const srtp_aes_expanded_key_t *)&expanded_key);
    for (i=0; i<16; i++) {
	ciphertext[i] = buf.v8[i];
    }

    return srtp_err_status_ok;
}
#endif

/*
 *  srtp_aes_key_unwrap_nopad
 *
 *  Description:
 *      This performs the AES Key Unwrap as per RFC 3394.  It allows one
 *      to optionally pass a pointer to a buffer to hold the 64-bit IV.
 *      If the "initialization_vector" is provided, this will be used for
 *      integrity checking, rather than using the default value defined
 *      in RFC 3394.  Additionally, to support AES Key Wrap with Padding
 *      (RFC 5639), the "initialization_vector" should be NULL and the
 *      caller should provide a pointer to a 64-bit "integrity_data".
 *      In that case, this function will NOT perform integrity checking
 *      on the unwrapped key.
 *
 *  Parameters:
 *      buf [out]
 *          A pointer to a buffer to hold the plaintext.  This function does
 *          not allocate memory and expects the caller to pass a pointer
 *          to a block of memory large enough to hold the output.
 *      enc_len [out]
 *          This is a the length of the resulting plaintext, which will be
 *          exactly 8 octets smaller than the original ciphertext.
 *      integrity_data [out]
 *          This is a pointer to a 64-bit buffer that will contain
 *          the integrity data determined through the unwrap process.
 *          If this parameter is NULL, this function will perform integrity
 *          checking internally.  If this parameter is present, this function
 *          will not perform integrity checking and simply return the
 *          integrity data to the caller to be checked.  If both this
 *          and the initialization_vector are present, this parameter
 *          takes precedence.
 *
 *  Returns:
 *      srtp_err_status_ok (0) if successful, non-zero if there was an error.
 *      The error code will be one defined by srtp_err_status_t.  The
 *      plaintext and plaintext_length parameters will be populated
 *      with the decrypted data and length, respectively.  If the
 *      integrity_data parameter was not NULL, then the 64-bit integrity
 *      check register (A[] as defined in RFC 3394) will be returned to
 *      the caller without the integrity data being checked.
 *
 *  Comments:
 *      The reason that the ciphertext must be a multiple of 8 octets is
 *      that AES Key Wrap requires it (see RFC 3394).  The decryption routines
 *      expected to decrypt "in place", which AES will do.  Thus, the plaintext
 *      and ciphertext pointers are the same when attempting to encrypt data
 *      in some parts of this code.  However, callers of this function should
 *      use different pointers to memory for the ciphertext and plaintext.
 *
 */
static srtp_err_status_t srtp_aes_key_unwrap_nopad(srtp_aes_wrap_ctx_t *c,
                                                   unsigned char *buf,
                                                   unsigned int *enc_len,
                                                   unsigned char *integrity_data)
{
    unsigned int i;                             /* Loop counter             */
    int j, k;                                   /* Loop counters            */
    unsigned int n;                             /* Number of 64-bit blocks  */
    unsigned int t, tt;                         /* Step counters            */
    unsigned char *A;                           /* Integrity check register */
    unsigned char B[16];                        /* Buffer for encryption    */
    unsigned char *R;                           /* Pointer to register i    */

    if (!integrity_data) {
        debug_print(srtp_mod_aes_wrap, "null integrity_data pointer", NULL);
        return srtp_err_status_bad_param;
    }

    /*
     * Ensure the plaintext length is valid (Note: "& 0x07" == "% 8")
     */
    if ((*enc_len & 0x07) || (!*enc_len)) {
        debug_print(srtp_mod_aes_wrap, "ciphertext length invalid for AES Key Unrap", NULL);
        return srtp_err_status_bad_param;
    }

    /*
     * Determine the number of 64-bit blocks to process
     */
    n = (*enc_len-8) >> 3;

    /*
     * Assign A to be C[0] (first 64-bit block of the ciphertext)
     */
    A = B;
    memcpy(A, buf, 8);

    /*
     * Perform the key wrap
     */
    memmove(buf, buf + 8, *enc_len-8);
    for (j = 5, t = 6*n; j >= 0; j--) {
        for (i = n, R = buf+*enc_len-16; i >= 1; i--, t--, R -= 8) {
            for (k = 7, tt = t; (k >= 0) && (tt > 0); k--, tt >>= 8) {
                A[k] ^= (unsigned char) (tt & 0xFF);
            }
            memcpy(B+8, R, 8);
            if (srtp_aes_wrap_ecb_decrypt(c, B, B)) {
                return srtp_err_status_cipher_fail;
            }
            memcpy(R, B+8, 8);
        }
    }

    /*
     * Set the ciphertext length value
     */
    *enc_len = *enc_len - 8;

    /*
     * If the integrity_data paramter is provided, return A[] to the caller
     * to perform integrity checking
     */
    memcpy(integrity_data, A, 8);

    return srtp_err_status_ok;
}

/*
 *  srtp_aes_key_wrap_nopad
 *
 *  Description:
 *      This performs the AES Key Wrap as per RFC 3394.
 *
 *  Parameters:
 *      plaintext_length [in]
 *          The length in octets of the plaintext.  This value
 *          must be a multiple of 8 octets.
 *      buf [out]
 *          A pointer to a buffer to containing plaintext and will receive
 *          the ciphertext.  This function does
 *          not allocate memory and expects the caller to pass a pointer
 *          to a block of memory large enough to hold the ciphertext.
 *      enc_len [out]
 *          This is a the length of the resulting ciphertext, which will be
 *          exactly 8 octets larger than the original plaintext.
 *
 *  Returns:
 *      srtp_err_status_ok (0) if successful, non-zero if there was an error.
 *      The error code will be one defined by srtp_err_status_t.  The
 *      ciphertext and ciphertext_length parameters will be populated
 *      with the encrypted data and length, respectively.
 *
 *  Comments:
 *      The reason that the plaintext must be a multiple of 8 octets is
 *      that AES Key Wrap requires it (see RFC 3394).  The encryption routines
 *      expected to encrypt "in place", which AES will do.  Thus, the plaintext
 *      and ciphertext pointers are the same when attempting to encrypt data
 *      in some parts of this code.  However, callers of this function should
 *      use different pointers to memory for the ciphertext and plaintext.
 *
 */
static srtp_err_status_t srtp_aes_key_wrap_nopad(srtp_aes_wrap_ctx_t *c,
                                                 unsigned int plaintext_length,
                                                 unsigned char *buf,
                                                 unsigned int *enc_len)
{
    unsigned int i;                             /* Loop counter             */
    int j, k;                                   /* Loop counters            */
    unsigned int n;                             /* Number of 64-bit blocks  */
    unsigned int t, tt;                         /* Step counters            */
    unsigned char *A;                           /* Integrity check register */
    unsigned char B[16];                        /* Buffer for encryption    */
    unsigned char *R;                           /* Pointer to register i    */

    /*
     * Ensure the plaintext length is valid (Note: "& 0x07" == "% 8")
     */
    if ((plaintext_length & 0x07) || (!plaintext_length)) {
        debug_print(srtp_mod_aes_wrap, "plaintext length invalid for AES Key Wrap", NULL);
        return srtp_err_status_bad_param;
    }

    /*
     * Determine the number of 64-bit blocks to process
     */
    n = plaintext_length >> 3;

    /*
     * Assign the IV.  This assumes the IV was already prepended to the ciphertext.
     */
    A = B;
    memcpy(A, buf, 8);

    /*
     * Perform the key wrap
     */
    for (j = 0, t = 1; j <= 5; j++) {
        for (i = 1, R = buf+8; i <= n; i++, t++, R += 8) {
            memcpy(B+8, R, 8);
            if (srtp_aes_wrap_ecb_encrypt(c, B, B)) {
                return srtp_err_status_cipher_fail;
            }
            for (k = 7, tt = t; (k >= 0) && (tt > 0); k--, tt >>= 8) {
                A[k] ^= (unsigned char) (tt & 0xFF);
            }
            memcpy(R, B+8, 8);
        }
    }
    memcpy(buf, A, 8);

    /*
     * Set the ciphertext length value
     */
    *enc_len = plaintext_length + 8;

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_aes_key_unwrap_padded (srtp_aes_wrap_ctx_t *c, 
	                                             unsigned char *buf, 
						     unsigned int *enc_len)
{
    unsigned char integrity_data[8];            /* Integrity data           */
    uint32_t network_word;                      /* Word, network byte order */
    unsigned int message_length_indicator;      /* MLI value                */
    unsigned char *p, *q;                       /* Pointers                 */

    /*
     * Check to ensure that the ciphertext length is proper, though no
     * length check is performed.  (Note: "& 0x07" == "% 8")
     */
    if ((!enc_len) || (!*enc_len) || (*enc_len & 0x07)) {
        debug_print(srtp_mod_aes_wrap, "key unwrap with padding ciphertext length invalid", NULL);
        return srtp_err_status_bad_param;
    }

    /*
     * Decrypt the ciphertext
     */
    if (*enc_len == 16) {
        /*
         * Decrypt using AES ECB mode
         */
        if (srtp_aes_wrap_ecb_decrypt(c, buf, buf)) {
            debug_print(srtp_mod_aes_wrap, "key unwrap with padding failed to decrypt ciphertext", NULL);
            return srtp_err_status_cipher_fail;
        }

        /*
         * Copy the integrity array
         */
        memcpy(integrity_data, buf, 8);

        /*
         * Copy the plaintext into the output buffer
         */
        memmove(buf, buf+8, 8);

        /*
         * Set the plaintext_length to 8
         */
        *enc_len = 8;
    } else {
        /*
         * Decrypt using AES Key Wrap
         */
        if (srtp_aes_key_unwrap_nopad(c, buf, enc_len, integrity_data)) {
            debug_print(srtp_mod_aes_wrap, "key unwrap with padding failed to unwrap", NULL);
            return srtp_err_status_cipher_fail;
        }
    }

    /*
     * Verify the integrity data is correct
     */
    if (c->alternate_iv_len == 8) {
        /*
         * Perform RFC 3394 integrity check
         */
        if (memcmp(c->alternate_iv, integrity_data, c->alternate_iv_len)) {
            debug_print(srtp_mod_aes_wrap, "key unwrap with padding integrity check failed", NULL);
            return srtp_err_status_cipher_fail;
        }
    } else {
        /*
         * We're doing RFC 5649 key wrap (padded)
         */
        if (memcmp(c->alternate_iv, integrity_data, 4)) {
            debug_print(srtp_mod_aes_wrap, "key unwrap with padding integrity check failed", NULL);
            return srtp_err_status_cipher_fail;
        }

        /*
         * Determine the original message length and sanity check
         */
        memcpy(&network_word, integrity_data+4, 4);
        message_length_indicator = ntohl(network_word);
        if ((message_length_indicator > *enc_len) || ((*enc_len > 8) && (message_length_indicator < (*enc_len)-7))) {
            debug_print(srtp_mod_aes_wrap, "key unwrap with padding plaintex message length invalid", NULL);
            return srtp_err_status_cipher_fail;
        }

        /*
         * Ensure that all padding bits are zero
         */
        p = buf + message_length_indicator;
        q = buf + *enc_len;
        while (p < q) {
            if (*p++) {
                debug_print(srtp_mod_aes_wrap, "key unwrap with padding zero octets not zero", NULL);
                return srtp_err_status_cipher_fail;
            }
        }
        *enc_len = message_length_indicator;
    }

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_aes_key_wrap_padded (srtp_aes_wrap_ctx_t *c, unsigned char *buf, unsigned int *enc_len)
{
    unsigned int plaintext_padded_length;       /* Len of padded plaintext  */
    unsigned int padding_length;                /* Number of padding octets */
    uint32_t network_word;                      /* Word, network byte order */

    /*
     * Check to ensure that the plaintext lenth is properly bounded
     */
    if (!(enc_len) || (*enc_len > AES_Key_Wrap_with_Padding_Max)) {
        debug_print(srtp_mod_aes_wrap, "key wrap with padding plaintext length invalid", NULL);
        return srtp_err_status_bad_param;
    }

    /*
     * Make room for the IV
     */
    memmove(buf+8, buf, *enc_len);

    /*
     * Store the initialization vector as the first 4 octets of the ciphertext
     */
    if (c->alternate_iv_len == 8) {
        /*
         * We're doing RFC 3394 key wrap
         */
        memcpy(buf, c->alternate_iv, c->alternate_iv_len);
    } else {
        /*
         * No alternate IV provided, we must be doing RFC 5649
         */
        memcpy(buf, c->alternate_iv, 4);
        /*
         * Store the original message length in network byte order as the
         * second 4 octets of the buffer
         */
        network_word = htonl(*enc_len);
        memcpy(buf+4, &network_word, 4);
    }

    /*
     * Now pad the buffer to be an even 8 octets and compute the length
     * of the padded buffer.  (Note: "& 0x07" == "% 8")
     */
    if (*enc_len & 0x07) {
        padding_length = 8 - (*enc_len & 0x07);

        /*
         * Pad with padding_length zeros
         */
        memset(buf + *enc_len + 8, 0, padding_length);
    } else {
        padding_length = 0;
    }
    plaintext_padded_length = *enc_len + padding_length;

    /*
     * Now encrypt the plaintext
     */
    if (plaintext_padded_length == 8) {
        /*
         * Encrypt using AES ECB mode
         */
        if (srtp_aes_wrap_ecb_encrypt(c, buf, buf)) {
            debug_print(srtp_mod_aes_wrap, "key wrap with padding failed to encrypt plaintext", NULL);
            return srtp_err_status_cipher_fail;
        }

        /*
         * Set the ciphertext length
         */
        *enc_len = 16;
    } else {
        /*
         * Encrypt using AES Key Wrap
         */
        if (srtp_aes_key_wrap_nopad(c, plaintext_padded_length, buf, enc_len)) {
            debug_print(srtp_mod_aes_wrap, "key wrap with padding failed to wrap", NULL);
            return srtp_err_status_cipher_fail;
        }
    }
    return srtp_err_status_ok;
}


/*
 * This function encrypts a buffer using AES keywrap mode
 *
 * Parameters:
 *	c	Crypto context
 *	buf	data to encrypt
 *	enc_len	length of encrypt buffer
 */
static srtp_err_status_t srtp_aes_wrap_encrypt (srtp_aes_wrap_ctx_t *c, unsigned char *buf, unsigned int *enc_len)
{
    /*
     * Ensure we do not receive NULL pointers
     */
    if (!c || !buf) {
        debug_print(srtp_mod_aes_wrap, "key wrap with padding pointers to buffers invalid", NULL);
        return srtp_err_status_bad_param;
    }

    /*
     * fork to the correct handler for wrap or unwrap
     */
    switch (c->direction) {
    case direction_encrypt:
        return (srtp_aes_key_wrap_padded(c, buf, enc_len));
        break;
    case direction_decrypt:
        return (srtp_aes_key_unwrap_padded(c, buf, enc_len));
        break;
    default:
        debug_print(srtp_mod_aes_wrap, "Invalid cipher direction", NULL);
        return srtp_err_status_bad_param;
        break;
    }

    return (srtp_err_status_fail);
}

/*
 * Name of this crypto engine
 */
static char srtp_aes_wrap_description[] = "AES key wrap";


/*
 * KAT values for AES self-test.  These values came from RFC 5649.
 */
static uint8_t srtp_aes_wrap_test_case_0_key[SRTP_AES_128_KEYSIZE] = {
    0x58, 0x40, 0xDF, 0x6E, 0x29, 0xB0, 0x2A, 0XF1,
    0xAB, 0x49, 0x3B, 0x70, 0x5B, 0xF1, 0x6E, 0XA1,
};

static uint8_t srtp_aes_wrap_test_case_0_nonce[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static uint8_t srtp_aes_wrap_test_case_0_plaintext[20] = {
    0xC3, 0x7B, 0x7E, 0x64, 0x92, 0x58, 0x43, 0x40,
    0xBE, 0xD1, 0x22, 0x07, 0x80, 0x89, 0x41, 0x15,
    0x50, 0x68, 0xF7, 0x38
};

static uint8_t srtp_aes_wrap_test_case_0_ciphertext[32] = {
    0xed, 0x9f, 0x0e, 0xcf, 0xbb, 0x76, 0x1b, 0x73, 
    0x65, 0x83, 0x87, 0x33, 0xe3, 0xf4, 0x2f, 0x81, 
    0xa0, 0x49, 0xf0, 0x77, 0xe9, 0x01, 0xf6, 0x3b, 
    0xfe, 0x05, 0x19, 0xe8, 0xa1, 0x2e, 0x9b, 0xcf
};

static srtp_cipher_test_case_t srtp_aes_wrap_test_case_0 = {
    SRTP_AES_128_KEYSIZE,			/* octets in key            */
    srtp_aes_wrap_test_case_0_key,              /* key                      */
    srtp_aes_wrap_test_case_0_nonce,            /* packet index             */
    20,						/* octets in plaintext      */
    srtp_aes_wrap_test_case_0_plaintext,        /* plaintext                */
    32,						/* octets in ciphertext     */
    srtp_aes_wrap_test_case_0_ciphertext,       /* ciphertext               */
    0,
    NULL,
    0,
    NULL					/* pointer to next testcase */
};


#ifdef OPENSSL
static uint8_t srtp_aes_wrap_test_case_1_key[SRTP_AES_192_KEYSIZE] = {
    0x58, 0x40, 0xDF, 0x6E, 0x29, 0xB0, 0x2A, 0XF1,
    0xAB, 0x49, 0x3B, 0x70, 0x5B, 0xF1, 0x6E, 0XA1,
    0xAE, 0x83, 0x38, 0xF4, 0xDC, 0xC1, 0x76, 0xA8
};

static uint8_t srtp_aes_wrap_test_case_1_nonce[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static uint8_t srtp_aes_wrap_test_case_1_plaintext[20] = {
    0xC3, 0x7B, 0x7E, 0x64, 0x92, 0x58, 0x43, 0x40,
    0xBE, 0xD1, 0x22, 0x07, 0x80, 0x89, 0x41, 0x15,
    0x50, 0x68, 0xF7, 0x38
};

static uint8_t srtp_aes_wrap_test_case_1_ciphertext[32] = {
    0x13, 0x8B, 0xDE, 0xAA, 0x9B, 0x8F, 0xA7, 0xFC,
    0x61, 0xF9, 0x77, 0x42, 0xE7, 0x22, 0x48, 0xEE,
    0x5A, 0xE6, 0xAE, 0x53, 0x60, 0xD1, 0xAE, 0x6A,
    0x5F, 0x54, 0xF3, 0x73, 0xFA, 0x54, 0x3B, 0x6A
};

static srtp_cipher_test_case_t srtp_aes_wrap_test_case_1 = {
    SRTP_AES_192_KEYSIZE,			/* octets in key            */
    srtp_aes_wrap_test_case_1_key,              /* key                      */
    srtp_aes_wrap_test_case_1_nonce,            /* packet index             */
    20,						/* octets in plaintext      */
    srtp_aes_wrap_test_case_1_plaintext,        /* plaintext                */
    32,						/* octets in ciphertext     */
    srtp_aes_wrap_test_case_1_ciphertext,       /* ciphertext               */
    0,
    NULL,
    0,
    &srtp_aes_wrap_test_case_0			/* pointer to next testcase */
};

static uint8_t srtp_aes_wrap_test_case_2_key[SRTP_AES_192_KEYSIZE] = {
    0x58, 0x40, 0xDF, 0x6E, 0x29, 0xB0, 0x2A, 0XF1,
    0xAB, 0x49, 0x3B, 0x70, 0x5B, 0xF1, 0x6E, 0XA1,
    0xAE, 0x83, 0x38, 0xF4, 0xDC, 0xC1, 0x76, 0xA8
};

static uint8_t srtp_aes_wrap_test_case_2_nonce[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static uint8_t srtp_aes_wrap_test_case_2_plaintext[7] = {
    0x46, 0x6F, 0x72, 0x50, 0x61, 0x73, 0x69
};

static uint8_t srtp_aes_wrap_test_case_2_ciphertext[16] = {
    0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41,
    0x92, 0x00, 0xf2, 0xcc, 0xb5, 0x0b, 0xb2, 0x4f
};

static srtp_cipher_test_case_t srtp_aes_wrap_test_case_2 = {
    SRTP_AES_192_KEYSIZE,			/* octets in key            */
    srtp_aes_wrap_test_case_2_key,              /* key                      */
    srtp_aes_wrap_test_case_2_nonce,            /* packet index             */
    7,						/* octets in plaintext      */
    srtp_aes_wrap_test_case_2_plaintext,        /* plaintext                */
    16,						/* octets in ciphertext     */
    srtp_aes_wrap_test_case_2_ciphertext,       /* ciphertext               */
    0,
    NULL,
    0,
    &srtp_aes_wrap_test_case_1			/* pointer to next testcase */
};
#endif




/*
 * This is the function table for this crypto engine.
 * note: the encrypt function is identical to the decrypt function
 */
srtp_cipher_type_t srtp_aes_wrap = {
    (cipher_alloc_func_t)          srtp_aes_wrap_alloc,
    (cipher_dealloc_func_t)        srtp_aes_wrap_dealloc,
    (cipher_init_func_t)           srtp_aes_wrap_context_init,
    (cipher_set_aad_func_t)        0,
    (cipher_encrypt_func_t)        srtp_aes_wrap_encrypt,
    (cipher_decrypt_func_t)        srtp_aes_wrap_encrypt,
    (cipher_set_iv_func_t)         srtp_aes_wrap_set_iv,
    (cipher_set_iv_len_func_t)     srtp_aes_wrap_set_iv_len,
    (cipher_get_tag_func_t)        0,
    (char*)                        srtp_aes_wrap_description,
#ifndef OPENSSL
    (srtp_cipher_test_case_t*)     &srtp_aes_wrap_test_case_0,
#else
    (srtp_cipher_test_case_t*)     &srtp_aes_wrap_test_case_2,
#endif
    (srtp_debug_module_t*)         &srtp_mod_aes_wrap,
    (srtp_cipher_type_id_t)        SRTP_AES_WRAP
};

