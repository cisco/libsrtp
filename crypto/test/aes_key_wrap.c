/*
 *  aes_key_wrap
 *
 *  Copyright (C) 2015
 *  Cisco Systems, Inc.
 *  All Rights Reserved.
 *
 *  Authors:
 *      Paul E. Jones, John A. Foley
 *
 *  Description:
 *      This module will exercise the AES Key Wrap (RFC 3394) and
 *      AES Key Wrap with Padding (RFC 5649) logic in crypto/cipher/aes_wrap.c
 *      module.
 *
 *  Portability Issues:
 *      None.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "srtp.h"
#include "srtp_priv.h"
#include "ekt_tag_utils.h"

#ifdef OPENSSL
/*
 *  aeskw_with_padding_test
 *
 *  Description:
 *      Test AES Key Wrap with Padding test routine
 *
 *  Parameters:
 *      key
 *          The encryption key
 *      key_length
 *          The length of the encryption key in bits
 *      plaintext
 *          The plaintext to encrypt
 *      plaintext_length
 *          The length of the plaintext
 *      expected_ciphertext
 *          The expected ciphertext
 *      expected_ciphertext_length
 *          The expected ciphertext length
 *
 *  Returns:
 *      Zero if successful, non-zero otherwise.
 *
 *  Comments:
 *      None.
 *
 */
static int aeskw_with_padding_test(const unsigned char *key,
                                   unsigned int key_length,
                                   const unsigned char *plaintext,
                                   unsigned int plaintext_length,
                                   const unsigned char *expected_ciphertext,
                                   unsigned int expected_ciphertext_length)
{
    srtp_cipher_t *kw;
    srtp_err_status_t stat;
    int ct_len;
    unsigned char *ct;

    printf("Testing wrap/unwrap with key size %d and PT length %d\n", key_length/8, plaintext_length);

    /* allocate key wrap cipher */
    stat = srtp_crypto_kernel_alloc_cipher(SRTP_AES_WRAP, &kw, key_length/8, 0);
    if (stat) {
        printf("Error: Failed to allocate key wrap cipher\n");
        return stat;
    }

    /* initialize key wrap cipher */
    stat = srtp_cipher_init(kw, key);
    if (stat) {
        printf("Error: Failed to initialize key wrap cipher\n");
        return stat;
    }

    /*
     * Set the encryption direction
     */
    stat = srtp_cipher_set_iv(kw, NULL, direction_encrypt);
    if (stat) {
        printf("Error: Failed to set key wrap IV and direction for encrypt\n");
        return stat;
    }

    /*
     * Encrypt the payload
     */
    ct = malloc(plaintext_length + 8);
    memcpy(ct, plaintext, plaintext_length);
    ct_len = plaintext_length;
    stat = srtp_cipher_encrypt(kw, (uint8_t*)ct, (uint32_t*)&ct_len);
    if (stat) {
        printf("Error: Key wrap encryption failed\n");
        return stat;
    }



    /************************************************
    * CHECK AGAINST KNOWN CIPHERTEXT
    ************************************************/
    printf("Checking known ciphertext\n");

    if (ct_len != expected_ciphertext_length) {
        printf("Error: ciphertext length (%i) does not match expected (%i)\n", ct_len, expected_ciphertext_length);
        return (-1);
    } else {
        printf("Encrypted lengths match\n");
    }

    /*
     * Compare computed ciphertext against expected ciphertext
     */
    if (memcmp(expected_ciphertext, ct, ct_len)) {
        printf("Error: Expected ciphertext mismatch\n");
        return -1;
    }

    /*
     * Set the encryption direction
     */
    stat = srtp_cipher_set_iv(kw, NULL, direction_decrypt);
    if (stat) {
        printf("Error: Failed to set key wrap IV and direction for decrypt\n");
        return stat;
    }

    /*
     * Decrypt the payload
     */
    stat = srtp_cipher_encrypt(kw, (uint8_t*)ct, (uint32_t*)&ct_len);
    if (stat) {
        printf("Error: Key wrap decryption failed\n");
        return stat;
    }

    if (ct_len != plaintext_length) {
        printf("Error: Decrypt length doesn't match original plaintext length\n");
        return -1;
    }

    if (memcmp(ct, plaintext, plaintext_length)) {
        printf("Error: Original plaintext mismatch\n");
        return -1;
    }

    /*
     * Dealloc the key wrap cipher.
     */
    free(ct);
    srtp_cipher_dealloc(kw);
    return (0);
}

/*
 *  rfc5649_test
 *
 *  Description:
 *      This routine will test using the test vectors published in RFC 5649
 *      by calling srtp_ekt_aes_key_wrap_with_padding() and
 *      srtp_ekt_aes_key_unwrap_with_padding().
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      Zero if successful, non-zero otherwise.
 *
 *  Comments:
 *      None.
 *
 */
static int rfc5649_test()
{
    unsigned char key[] =
    {
        0x58, 0x40, 0xDF, 0x6E, 0x29, 0xB0, 0x2A, 0XF1,
        0xAB, 0x49, 0x3B, 0x70, 0x5B, 0xF1, 0x6E, 0XA1,
        0xAE, 0x83, 0x38, 0xF4, 0xDC, 0xC1, 0x76, 0XA8
    };
    unsigned char plaintext_20[] =
    {
        0xC3, 0x7B, 0x7E, 0x64, 0x92, 0x58, 0x43, 0x40,
        0xBE, 0xD1, 0x22, 0x07, 0x80, 0x89, 0x41, 0x15,
        0x50, 0x68, 0xF7, 0x38
    };
    unsigned char ciphertext_20[] =
    {
        0x13, 0x8B, 0xDE, 0xAA, 0x9B, 0x8F, 0xA7, 0xFC,
        0x61, 0xF9, 0x77, 0x42, 0xE7, 0x22, 0x48, 0xEE,
        0x5A, 0xE6, 0xAE, 0x53, 0x60, 0xD1, 0xAE, 0x6A,
        0x5F, 0x54, 0xF3, 0x73, 0xFA, 0x54, 0x3B, 0x6A
    };
    unsigned char plaintext_7[] =
    {
        0x46, 0x6F, 0x72, 0x50, 0x61, 0x73, 0x69
    };
    unsigned char ciphertext_7[] =
    {
        0xAF, 0xBE, 0xB0, 0xF0, 0x7D, 0xFB, 0xF5, 0x41,
        0x92, 0x00, 0xF2, 0xCC, 0xB5, 0x0B, 0xB2, 0x4F
    };

    printf("Entering rfc5649_test()\n");

    if (aeskw_with_padding_test(key,
                                sizeof(key)*8,
                                plaintext_20,
                                sizeof(plaintext_20),
                                ciphertext_20,
                                sizeof(ciphertext_20)))
    {
        printf("Exiting rfc5649_test()\n");
        return (-1);
    }

    if (aeskw_with_padding_test(key,
                                sizeof(key)*8,
                                plaintext_7,
                                sizeof(plaintext_7),
                                ciphertext_7,
                                sizeof(ciphertext_7)))
    {
        printf("Exiting rfc5649_test()\n");
        return (-1);
    }

    printf("Exiting rfc5649_test()\n");

    return 0;
}
#endif



static unsigned char key_1[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};
static unsigned char plaintext_1[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};
static unsigned char ciphertext_1[] = {
    0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
    0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
    0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5
};
static unsigned char key_2[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
};
static unsigned char plaintext_2[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};
static unsigned char ciphertext_2[] = {
    0x96, 0x77, 0x8B, 0x25, 0xAE, 0x6C, 0xA4, 0x35,
    0xF9, 0x2B, 0x5B, 0x97, 0xC0, 0x50, 0xAE, 0xD2,
    0x46, 0x8A, 0xB8, 0xA1, 0x7A, 0xD8, 0x4E, 0x5D
};
static unsigned char key_3[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};
static unsigned char plaintext_3[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};
static unsigned char ciphertext_3[] = {
    0x64, 0xE8, 0xC3, 0xF9, 0xCE, 0x0F, 0x5B, 0xA2,
    0x63, 0xE9, 0x77, 0x79, 0x05, 0x81, 0x8A, 0x2A,
    0x93, 0xC8, 0x19, 0x1E, 0x7D, 0x6E, 0x8A, 0xE7
};
static unsigned char key_4[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
};
static unsigned char plaintext_4[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
};
static unsigned char ciphertext_4[] = {
    0x03, 0x1D, 0x33, 0x26, 0x4E, 0x15, 0xD3, 0x32,
    0x68, 0xF2, 0x4E, 0xC2, 0x60, 0x74, 0x3E, 0xDC,
    0xE1, 0xC6, 0xC7, 0xDD, 0xEE, 0x72, 0x5A, 0x93,
    0x6B, 0xA8, 0x14, 0x91, 0x5C, 0x67, 0x62, 0xD2
};
static unsigned char key_5[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};
static unsigned char plaintext_5[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
};
static unsigned char ciphertext_5[] = {
    0xA8, 0xF9, 0xBC, 0x16, 0x12, 0xC6, 0x8B, 0x3F,
    0xF6, 0xE6, 0xF4, 0xFB, 0xE3, 0x0E, 0x71, 0xE4,
    0x76, 0x9C, 0x8B, 0x80, 0xA3, 0x2C, 0xB8, 0x95,
    0x8C, 0xD5, 0xD1, 0x7D, 0x6B, 0x25, 0x4D, 0xA1
};
static unsigned char key_6[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};
static unsigned char plaintext_6[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};
static unsigned char ciphertext_6[] = {
    0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4,
    0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87, 0xF8, 0x26,
    0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26,
    0xCB, 0xC7, 0xF0, 0xE7, 0x1A, 0x99, 0xF4, 0x3B,
    0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21
};


/*
 * This function runs an individual test case.  This will encrypt the given
 * plaintext and compare it to the expected ciphertext.  It will then
 * decrypt the cipher text and compare it to the original plaintext.
 *
 * The input parameters are:
 *
 *  kek:	Key to use for encrypting (key encryption key)
 *  keysize:	Size, in bytes, of the kek
 *  expected:	The expected ciphertext
 *  pt:		The plaintext to be encrypted
 *  pt_len:	Lentgh of the plaintext
 *
 * Returns 0 on success, non-zero on failure
 */
static int aes_wrap_test(unsigned char *kek, int keysize, unsigned char *expected, unsigned char *pt, int pt_len)
{
    srtp_cipher_t *kw;
    srtp_err_status_t stat;
    int ct_len;
    unsigned char *ct;

#ifndef OPENSSL
    /*
     * 192-bit keys are only supported when using OpenSSL crypto
     */
    if (keysize == 24) {
	return (0);
    }
#endif

    printf("Testing wrap/unwrap with key size %d and PT length %d\n", keysize, pt_len);

    /* allocate key wrap cipher */
    stat = srtp_crypto_kernel_alloc_cipher(SRTP_AES_WRAP, &kw, keysize, 0);
    if (stat) {
        printf("Failed to allocate key wrap cipher\n");
        return stat;
    }

    /* initialize key wrap cipher */
    stat = srtp_cipher_init(kw, kek);
    if (stat) {
        printf("Failed to initialize key wrap cipher\n");
        return stat;
    }

    /*
     * Set the RFC 3394 IV length
     */
    stat = srtp_cipher_set_iv_len(kw, 8);
    if (stat) {
        printf("Failed to set RFC 3394 IV length\n");
        return stat;
    }

    /*
     * Set the encryption direction
     */
    stat = srtp_cipher_set_iv(kw, NULL, direction_encrypt);
    if (stat) {
        printf("Failed to set key wrap IV and direction for encrypt\n");
        return stat;
    }

    /*
     * Encrypt the payload
     */
    ct = malloc(pt_len + 8);
    memcpy(ct, pt, pt_len);
    ct_len = pt_len;
    stat = srtp_cipher_encrypt(kw, (uint8_t*)ct, (uint32_t*)&ct_len);
    if (stat) {
        printf("Key wrap encryption failed\n");
        return stat;
    }

    /*
     * Compare computed ciphertext against expected ciphertext
     */
    if (memcmp(expected, ct, ct_len)) {
        printf("Expected ciphertext mismatch\n");
        return -1;
    }


    /*
     * Set the encryption direction
     */
    stat = srtp_cipher_set_iv(kw, NULL, direction_decrypt);
    if (stat) {
        printf("Failed to set key wrap IV and direction for decrypt\n");
        return stat;
    }

    /*
     * Decrypt the payload
     */
    stat = srtp_cipher_encrypt(kw, (uint8_t*)ct, (uint32_t*)&ct_len);
    if (stat) {
        printf("Key wrap decryption failed\n");
        return stat;
    }

    if (ct_len != pt_len) {
        printf("Decrypt length doesn't match original plaintext length\n");
        return -1;
    }

    if (memcmp(ct, pt, pt_len)) {
        printf("Original plaintext mismatch\n");
        return -1;
    }

    /*
     * Dealloc the key wrap cipher.
     */
    free(ct);
    srtp_cipher_dealloc(kw);
    return 0;
}

/*
 * Entry point for tests
 */
int main(int argc, char *argv[])
{
    srtp_err_status_t stat;

#if 0
    /*
     * enable debugs
     */
    stat = srtp_set_debug_module("crypto", 1);
    if (stat) {
        printf("error: set debug module failed\n");
        exit(1);
    }
#endif

    /* initialize srtp library */
    stat = srtp_init();
    if (stat) {
        printf("error: srtp initialization failed with error code %d\n", stat);
        exit(1);
    }

#ifdef OPENSSL
    /*
     * Test RFC 5649 using published test vectors.  These use 192 bit keys,
     * which are only supported when OpenSSL crypto is used.
     */
    if (rfc5649_test())
    {
        printf("RFC 5649 tests failed!\n");
        exit(1);
    }
#endif

    /*
     * Wrap/unwrap test #1
     */
    if (aes_wrap_test(key_1, sizeof(key_1), ciphertext_1, plaintext_1, sizeof(plaintext_1))) {
        printf("Key wrap test# 1 failed!\n");
        exit(1);
    }

    /*
     * Wrap/unwrap test #2
     */
    if (aes_wrap_test(key_2, sizeof(key_2), ciphertext_2, plaintext_2, sizeof(plaintext_2))) {
        printf("Key wrap test# 2 failed!\n");
        exit(1);
    }

    /*
     * Wrap/unwrap test #3
     */
    if (aes_wrap_test(key_3, sizeof(key_3), ciphertext_3, plaintext_3, sizeof(plaintext_3))) {
        printf("Key wrap test# 3 failed!\n");
        exit(1);
    }

    /*
     * Wrap/unwrap test #4
     */
    if (aes_wrap_test(key_4, sizeof(key_4), ciphertext_4, plaintext_4, sizeof(plaintext_4))) {
        printf("Key wrap test# 4 failed!\n");
        exit(1);
    }

    /*
     * Wrap/unwrap test #5
     */
    if (aes_wrap_test(key_5, sizeof(key_5), ciphertext_5, plaintext_5, sizeof(plaintext_5))) {
        printf("Key wrap test# 5 failed!\n");
        exit(1);
    }

    /*
     * Wrap/unwrap test #1
     */
    if (aes_wrap_test(key_6, sizeof(key_6), ciphertext_6, plaintext_6, sizeof(plaintext_6))) {
        printf("Key wrap test# 6 failed!\n");
        exit(1);
    }

    printf("All key wrap tests passed.\n");

    return (0);
}

