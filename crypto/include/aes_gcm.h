/*
 * aes_gcm.h
 *
 * Header for AES Galois Counter Mode.
 *
 * John A. Foley
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

#ifndef AES_GCM_H
#define AES_GCM_H

#include "cipher.h"
#include "srtp.h"
#include "datatypes.h"

/*
 * For now we only support 8 and 16 octet tags.  The spec allows for
 * optional 12 byte tag, which may be supported in the future.
 */
#define GCM_IV_LEN 12
#define GCM_AUTH_TAG_LEN 16
#define GCM_AUTH_TAG_LEN_8 8

#ifdef OPENSSL

#include <openssl/evp.h>
#include <openssl/aes.h>

typedef struct {
    int key_size;
    int tag_len;
    EVP_CIPHER_CTX *ctx;
    srtp_cipher_direction_t dir;
} srtp_aes_gcm_ctx_t;

#endif /* OPENSSL */

#ifdef NSS

#include <pk11pub.h>

#define GCM_MAX_AD_SIZE 512

typedef struct {
    int key_size;
    int tag_size;
    srtp_cipher_direction_t dir;
    PK11SymKey *key;
    uint8_t iv[12];
    uint8_t aad[GCM_MAX_AD_SIZE];
    int aad_size;
    CK_GCM_PARAMS params;
    uint8_t tag[16];
} srtp_aes_gcm_ctx_t;

#endif /* NSS */

#endif /* AES_GCM_H */
