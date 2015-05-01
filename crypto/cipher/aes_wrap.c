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

#include <openssl/evp.h>
#include "aes_wrap.h"
#include "crypto_types.h"
#include "alloc.h"
#include "crypto_types.h"

/*
 * Define module-level global constants
 */
static const unsigned char AES_Key_Wrap_Default_IV[] = /* The default IV    */
{
    0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6
};
static const unsigned char Alternative_IV[] =   /* AIV per RFC 5649         */
{
    0xA6, 0x59, 0x59, 0xA6
};
static const uint32_t AES_Key_Wrap_with_Padding_Max = 0xFFFFFFFF; /* Ditto  */


srtp_debug_module_t srtp_mod_aes_wrap = {
    0,               /* debugging is off by default */
    "aes key wrap"   /* printable module name       */
};
extern srtp_cipher_type_t srtp_aes_wrap;
#ifndef SRTP_NO_AES192
extern srtp_cipher_type_t srtp_aes_wrap_192;
#endif
extern srtp_cipher_type_t srtp_aes_wrap_256;

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
    switch (key_len) {
    case SRTP_AES_128_KEYSIZE:
        (*c)->algorithm = SRTP_AES_128_WRAP;
        (*c)->type = &srtp_aes_wrap;
        wrap->key_size = SRTP_AES_128_KEYSIZE;
        break;
#ifndef SRTP_NO_AES192
    case SRTP_AES_192_KEYSIZE:
        (*c)->algorithm = SRTP_AES_192_WRAP;
        (*c)->type = &srtp_aes_wrap_192;
        wrap->key_size = SRTP_AES_192_KEYSIZE;
        break;
#endif
    case SRTP_AES_256_KEYSIZE:
        (*c)->algorithm = SRTP_AES_256_WRAP;
        (*c)->type = &srtp_aes_wrap_256;
        wrap->key_size = SRTP_AES_256_KEYSIZE;
        break;
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
     * half.  Note, we treat AES-192 and AES-256 the same here
     * for simplicity.  The storage location receiving the
     * key is statically allocated to handle a full 32 byte key
     * regardless of the cipher in use.
     */
    if (c->key_size == SRTP_AES_256_KEYSIZE || 
#ifndef SRTP_NO_AES192
	    c->key_size == SRTP_AES_192_KEYSIZE
#endif
	    ) {
        debug_print(srtp_mod_aes_wrap, "Copying last 16 bytes of key: %s",
                    v128_hex_string((v128_t*)(key + SRTP_AES_128_KEYSIZE)));
        v128_copy_octet_string(((v128_t*)(&c->key.v8)) + 1, key + SRTP_AES_128_KEYSIZE);
    }

    debug_print(srtp_mod_aes_wrap, "key:  %s", v128_hex_string((v128_t*)&c->key));


    return srtp_err_status_ok;
}

/*
 * srtp_aes_wrap_set_iv(c, iv) sets the counter value to the exor of iv with
 * the offset
 */
static srtp_err_status_t srtp_aes_wrap_set_iv (srtp_aes_wrap_ctx_t *c, const uint8_t *iv, int dir)
{
    c->direction = dir;
    memcpy(c->alternate_iv, iv, 4);
    debug_print(srtp_mod_aes_wrap, "iv:  %s", v128_hex_string((v128_t*)c->alternate_iv));

    return srtp_err_status_ok;
}

/*
 * This function does simple AES-ECB crypto
 * FIXME: this function currently uses OpenSSL crypto, need to support built-in crypto too
 */
static srtp_err_status_t srtp_aes_wrap_ecb_decrypt( srtp_aes_wrap_ctx_t *c,   
        const unsigned char *ciphertext,
        unsigned int ciphertext_length,
        unsigned char *plaintext)
{
    EVP_CIPHER_CTX ctx;                         /* Crypto context           */
    const EVP_CIPHER *cipher = NULL;            /* Cipher to use            */
    int plaintext_length = 0;                   /* Length of text           */
    int final_length = 0;                       /* Length of final text     */

    /*
     * Ensure the plaintext length is valid (Note: "& 0x0F" == "% 16")
     */
    if ((ciphertext_length & 0x0F) || (!ciphertext_length)) {
        debug_print(srtp_mod_aes_wrap, "ciphertext length invalid for AES ECB encryption", NULL);
        return srtp_err_status_bad_param;
    }

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

    if (!EVP_DecryptUpdate(&ctx, plaintext, &plaintext_length, ciphertext, ciphertext_length)) {
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
    if (plaintext_length + final_length != ciphertext_length) {
        debug_print(srtp_mod_aes_wrap, "Unexpected plaintext length in AES ECB encryption", NULL);
        return srtp_err_status_cipher_fail;
    }

    return srtp_err_status_ok;
}



/*
 * This function does simple AES-ECB crypto
 * FIXME: this function currently uses OpenSSL crypto, need to support built-in crypto too
 */
static srtp_err_status_t srtp_aes_wrap_ecb_encrypt( srtp_aes_wrap_ctx_t *c,   
        const unsigned char *plaintext,
        unsigned int plaintext_length,
        unsigned char *ciphertext)
{
    EVP_CIPHER_CTX ctx;                         /* Crypto context           */
    const EVP_CIPHER *cipher = NULL;            /* Cipher to use            */
    int ciphertext_length = 0;                  /* Length of ciphertext     */
    int final_length = 0;                       /* Length of final text     */

    /*
     * Ensure the plaintext length is valid (Note: "& 0x0F" == "% 16")
     */
    if ((plaintext_length & 0x0F) || (!plaintext_length)) {
        debug_print(srtp_mod_aes_wrap, "plaintext length invalid for AES ECB encryption", NULL);
        return srtp_err_status_bad_param;
    }

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

    if (!EVP_EncryptUpdate(&ctx, ciphertext, &ciphertext_length, plaintext, plaintext_length)) {
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
    if (ciphertext_length + final_length != plaintext_length) {
        debug_print(srtp_mod_aes_wrap, "Unexpected ciphertext length in AES ECB encryption", NULL);
        return srtp_err_status_cipher_fail;
    }

    return srtp_err_status_ok;
}

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
    int i, j, k;                                /* Loop counters            */
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
    for(j=5, t=6*n; j>=0; j--) {
        for(i=n, R=buf+*enc_len-16; i>=1; i--, t--, R-=8) {
            for(k=7, tt=t; (k>=0) && (tt>0); k--, tt>>=8) {
                A[k] ^= (unsigned char) (tt & 0xFF);
            }
            memcpy(B+8, R, 8);
            if (srtp_aes_wrap_ecb_decrypt(c, B, 16, B)) {
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
    int i, j, k;                                /* Loop counters            */
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
    for(j=0, t=1; j<=5; j++) {
        for(i=1, R=buf+8; i<=n; i++, t++, R+=8) {
            memcpy(B+8, R, 8);
            if (srtp_aes_wrap_ecb_encrypt(c, B, 16, B)) {
                return srtp_err_status_cipher_fail;
            }
            for(k=7, tt=t; (k>=0) && (tt>0); k--, tt>>=8) {
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

static srtp_err_status_t srtp_aes_key_unwrap_padded (srtp_aes_wrap_ctx_t *c, unsigned char *buf, unsigned int *enc_len)
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
        if (srtp_aes_wrap_ecb_decrypt(c , buf, 16, buf)) {
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
     * Verify that the first 4 octets of the integrity data are correct
     */
    if (c->alternate_iv) {
        if (memcmp(c->alternate_iv, integrity_data, 4)) {
            debug_print(srtp_mod_aes_wrap, "key unwrap with padding integrity check failed", NULL);
            return srtp_err_status_cipher_fail;
        }
    } else {
        if (memcmp(Alternative_IV, integrity_data, 4)) {
            debug_print(srtp_mod_aes_wrap, "key unwrap with padding integrity check failed", NULL);
            return srtp_err_status_cipher_fail;
        }
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
    while(p<q) {
        if (*p++) {
            debug_print(srtp_mod_aes_wrap, "key unwrap with padding zero octets not zero", NULL);
            return srtp_err_status_cipher_fail;
        }
    }

    *enc_len = message_length_indicator;

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
    if (c->alternate_iv) {
        memcpy(buf, c->alternate_iv, 4);
    } else {
        memcpy(buf, Alternative_IV, 4);
    }

    /*
     * Store the original message length in network byte order as the
     * second 4 octets of the buffer
     */
    network_word = htonl(*enc_len);
    memcpy(buf+4, &network_word, 4);

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
        if (srtp_aes_wrap_ecb_encrypt(c, buf, 16, buf)) {
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
static char srtp_aes_wrap_description[] = "AES-128 key wrap";
#ifndef SRTP_NO_AES192
static char srtp_aes_wrap_192_description[] = "AES-192 key wrap";
#endif
static char srtp_aes_wrap_256_description[] = "AES-256 key wrap";


#if 0
//FIXME: need to setup key wrap KAT values

/*
 * KAT values for AES self-test.  These
 * values came from the legacy libsrtp code.
 */
static uint8_t srtp_aes_icm_test_case_0_key[SRTP_AES_128_KEYSIZE_WSALT] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd
};

static uint8_t srtp_aes_icm_test_case_0_nonce[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static uint8_t srtp_aes_icm_test_case_0_plaintext[32] =  {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static uint8_t srtp_aes_icm_test_case_0_ciphertext[32] = {
    0xe0, 0x3e, 0xad, 0x09, 0x35, 0xc9, 0x5e, 0x80,
    0xe1, 0x66, 0xb1, 0x6d, 0xd9, 0x2b, 0x4e, 0xb4,
    0xd2, 0x35, 0x13, 0x16, 0x2b, 0x02, 0xd0, 0xf7,
    0x2a, 0x43, 0xa2, 0xfe, 0x4a, 0x5f, 0x97, 0xab
};

static srtp_cipher_test_case_t srtp_aes_icm_test_case_0 = {
    SRTP_AES_128_KEYSIZE_WSALT,                 /* octets in key            */
    srtp_aes_icm_test_case_0_key,               /* key                      */
    srtp_aes_icm_test_case_0_nonce,             /* packet index             */
    32,                                    /* octets in plaintext      */
    srtp_aes_icm_test_case_0_plaintext,         /* plaintext                */
    32,                                    /* octets in ciphertext     */
    srtp_aes_icm_test_case_0_ciphertext,        /* ciphertext               */
    0,
    NULL,
    0,
    NULL                                   /* pointer to next testcase */
};

#ifndef SRTP_NO_AES192
/*
 * KAT values for AES-192-CTR self-test.  These
 * values came from section 7 of RFC 6188.
 */
static uint8_t srtp_aes_icm_192_test_case_1_key[SRTP_AES_192_KEYSIZE_WSALT] = {
    0xea, 0xb2, 0x34, 0x76, 0x4e, 0x51, 0x7b, 0x2d,
    0x3d, 0x16, 0x0d, 0x58, 0x7d, 0x8c, 0x86, 0x21,
    0x97, 0x40, 0xf6, 0x5f, 0x99, 0xb6, 0xbc, 0xf7,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd
};

static uint8_t srtp_aes_icm_192_test_case_1_nonce[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static uint8_t srtp_aes_icm_192_test_case_1_plaintext[32] =  {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static uint8_t srtp_aes_icm_192_test_case_1_ciphertext[32] = {
    0x35, 0x09, 0x6c, 0xba, 0x46, 0x10, 0x02, 0x8d,
    0xc1, 0xb5, 0x75, 0x03, 0x80, 0x4c, 0xe3, 0x7c,
    0x5d, 0xe9, 0x86, 0x29, 0x1d, 0xcc, 0xe1, 0x61,
    0xd5, 0x16, 0x5e, 0xc4, 0x56, 0x8f, 0x5c, 0x9a
};

static srtp_cipher_test_case_t srtp_aes_icm_192_test_case_1 = {
    SRTP_AES_192_KEYSIZE_WSALT,                 /* octets in key            */
    srtp_aes_icm_192_test_case_1_key,           /* key                      */
    srtp_aes_icm_192_test_case_1_nonce,         /* packet index             */
    32,                                    /* octets in plaintext      */
    srtp_aes_icm_192_test_case_1_plaintext,     /* plaintext                */
    32,                                    /* octets in ciphertext     */
    srtp_aes_icm_192_test_case_1_ciphertext,    /* ciphertext               */
    0,
    NULL,
    0,
    NULL                                   /* pointer to next testcase */
};
#endif

/*
 * KAT values for AES-256-CTR self-test.  These
 * values came from section 7 of RFC 6188.
 */
static uint8_t srtp_aes_icm_256_test_case_2_key[SRTP_AES_256_KEYSIZE_WSALT] = {
    0x57, 0xf8, 0x2f, 0xe3, 0x61, 0x3f, 0xd1, 0x70,
    0xa8, 0x5e, 0xc9, 0x3c, 0x40, 0xb1, 0xf0, 0x92,
    0x2e, 0xc4, 0xcb, 0x0d, 0xc0, 0x25, 0xb5, 0x82,
    0x72, 0x14, 0x7c, 0xc4, 0x38, 0x94, 0x4a, 0x98,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd
};

static uint8_t srtp_aes_icm_256_test_case_2_nonce[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static uint8_t srtp_aes_icm_256_test_case_2_plaintext[32] =  {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static uint8_t srtp_aes_icm_256_test_case_2_ciphertext[32] = {
    0x92, 0xbd, 0xd2, 0x8a, 0x93, 0xc3, 0xf5, 0x25,
    0x11, 0xc6, 0x77, 0xd0, 0x8b, 0x55, 0x15, 0xa4,
    0x9d, 0xa7, 0x1b, 0x23, 0x78, 0xa8, 0x54, 0xf6,
    0x70, 0x50, 0x75, 0x6d, 0xed, 0x16, 0x5b, 0xac
};

static srtp_cipher_test_case_t srtp_aes_icm_256_test_case_2 = {
    SRTP_AES_256_KEYSIZE_WSALT,                 /* octets in key            */
    srtp_aes_icm_256_test_case_2_key,           /* key                      */
    srtp_aes_icm_256_test_case_2_nonce,         /* packet index             */
    32,                                    /* octets in plaintext      */
    srtp_aes_icm_256_test_case_2_plaintext,     /* plaintext                */
    32,                                    /* octets in ciphertext     */
    srtp_aes_icm_256_test_case_2_ciphertext,    /* ciphertext               */
    0,
    NULL,
    0,
    NULL                                   /* pointer to next testcase */
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
    (cipher_get_tag_func_t)        0,
    (char*)                        srtp_aes_wrap_description,
    (srtp_cipher_test_case_t*)     0,
    (srtp_debug_module_t*)         &srtp_mod_aes_wrap,
    (srtp_cipher_type_id_t)        SRTP_AES_128_WRAP
};

#ifndef SRTP_NO_AES192
/*
 * This is the function table for this crypto engine.
 * note: the encrypt function is identical to the decrypt function
 */
srtp_cipher_type_t srtp_aes_wrap_192 = {
    (cipher_alloc_func_t)          srtp_aes_wrap_alloc,
    (cipher_dealloc_func_t)        srtp_aes_wrap_dealloc,
    (cipher_init_func_t)           srtp_aes_wrap_context_init,
    (cipher_set_aad_func_t)        0,
    (cipher_encrypt_func_t)        srtp_aes_wrap_encrypt,
    (cipher_decrypt_func_t)        srtp_aes_wrap_encrypt,
    (cipher_set_iv_func_t)         srtp_aes_wrap_set_iv,
    (cipher_get_tag_func_t)        0,
    (char*)                        srtp_aes_wrap_192_description,
    (srtp_cipher_test_case_t*)     0,
    (srtp_debug_module_t*)         &srtp_mod_aes_wrap,
    (srtp_cipher_type_id_t)        SRTP_AES_192_WRAP
};
#endif

/*
 * This is the function table for this crypto engine.
 * note: the encrypt function is identical to the decrypt function
 */
srtp_cipher_type_t srtp_aes_wrap_256 = {
    (cipher_alloc_func_t)          srtp_aes_wrap_alloc,
    (cipher_dealloc_func_t)        srtp_aes_wrap_dealloc,
    (cipher_init_func_t)           srtp_aes_wrap_context_init,
    (cipher_set_aad_func_t)        0,
    (cipher_encrypt_func_t)        srtp_aes_wrap_encrypt,
    (cipher_decrypt_func_t)        srtp_aes_wrap_encrypt,
    (cipher_set_iv_func_t)         srtp_aes_wrap_set_iv,
    (cipher_get_tag_func_t)        0,
    (char*)                        srtp_aes_wrap_256_description,
    (srtp_cipher_test_case_t*)     0,
    (srtp_debug_module_t*)         &srtp_mod_aes_wrap,
    (srtp_cipher_type_id_t)        SRTP_AES_256_WRAP
};

