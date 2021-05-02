/*
 * cipher.h
 *
 * common interface to ciphers
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 */
/*
 *
 * Copyright (c) 2001-2017 Cisco Systems, Inc.
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

#ifndef SRTP_CIPHER_STRUCTS_H
#define SRTP_CIPHER_STRUCTS_H

#include "srtp.h"
#include "crypto_types.h" /* for values of cipher_type_id_t */

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  a srtp_cipher_alloc_func_t allocates (but does not initialize) a
 * srtp_cipher_t
 */
typedef srtp_err_status_t (*srtp_cipher_alloc_func_t)(srtp_cipher_pointer_t *cp,
                                                      int key_len,
                                                      int tag_len);

/*
 * a srtp_cipher_init_func_t [re-]initializes a cipher_t with a given key
 */
typedef srtp_err_status_t (*srtp_cipher_init_func_t)(void *state,
                                                     const uint8_t *key);

/* a srtp_cipher_dealloc_func_t de-allocates a cipher_t */
typedef srtp_err_status_t (*srtp_cipher_dealloc_func_t)(
    srtp_cipher_pointer_t cp);

/*
 * a srtp_cipher_set_aad_func_t processes the AAD data for AEAD ciphers
 */
typedef srtp_err_status_t (*srtp_cipher_set_aad_func_t)(void *state,
                                                        const uint8_t *aad,
                                                        uint32_t aad_len);

/* a srtp_cipher_encrypt_func_t encrypts data in-place */
typedef srtp_err_status_t (*srtp_cipher_encrypt_func_t)(
    void *state,
    uint8_t *buffer,
    unsigned int *octets_to_encrypt);

/* a srtp_cipher_decrypt_func_t decrypts data in-place */
typedef srtp_err_status_t (*srtp_cipher_decrypt_func_t)(
    void *state,
    uint8_t *buffer,
    unsigned int *octets_to_decrypt);

/*
 * a srtp_cipher_set_iv_func_t function sets the current initialization vector
 */
typedef srtp_err_status_t (*srtp_cipher_set_iv_func_t)(
    void *state,
    uint8_t *iv,
    srtp_cipher_direction_t direction);

/*
 * a cipher_get_tag_func_t function is used to get the authentication
 * tag that was calculated by an AEAD cipher.
 */
typedef srtp_err_status_t (*srtp_cipher_get_tag_func_t)(void *state,
                                                        uint8_t *tag,
                                                        uint32_t *len);

/* srtp_cipher_type_t defines the 'metadata' for a particular cipher type */
typedef struct srtp_cipher_type_t {
    srtp_cipher_alloc_func_t alloc;
    srtp_cipher_dealloc_func_t dealloc;
    srtp_cipher_init_func_t init;
    srtp_cipher_set_aad_func_t set_aad;
    srtp_cipher_encrypt_func_t encrypt;
    srtp_cipher_encrypt_func_t decrypt;
    srtp_cipher_set_iv_func_t set_iv;
    srtp_cipher_get_tag_func_t get_tag;
    const char *description;
    const srtp_cipher_test_case_t *test_data;
    srtp_cipher_type_id_t id;
} srtp_cipher_type_t;

/*
 * srtp_cipher_t defines an instantiation of a particular cipher, with fixed
 * key length, key and salt values
 */
typedef struct srtp_cipher_t {
    const srtp_cipher_type_t *type;
    void *state;
    int key_len;
    int algorithm;
} srtp_cipher_t;

#ifdef __cplusplus
}
#endif

#endif /* SRTP_CIPHER_STRUCTS_H */

