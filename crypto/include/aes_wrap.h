/*
 * aes_wrap.h
 *
 * Header for AES Key Wrap Mode.
 *
 * John A. Foley 
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

#ifndef AES_WRAP_H
#define AES_WRAP_H

#include "cipher.h"

#ifdef OPENSSL_IS_BORINGSSL
/* BoringSSL doesn't support AES-192, cipher will be disabled */
#define SRTP_NO_AES192
#endif

#define     SRTP_AES_128_KEYSIZE         AES_BLOCK_SIZE
#define     SRTP_AES_256_KEYSIZE         AES_BLOCK_SIZE * 2
#ifndef SRTP_NO_AES192
#define     SRTP_AES_192_KEYSIZE         AES_BLOCK_SIZE + AES_BLOCK_SIZE / 2
#endif

typedef struct {
    v256_t key;
    int key_size;
    int direction; /* encrypt is wrap, decrypt is unwrap */
    unsigned char *alternate_iv;
    uint8_t alternate_iv_len;
} srtp_aes_wrap_ctx_t;

#endif /* AES_ICM_H */

