/*
 * crypto_backend.c
 *
 * startup and shutdown for the selected crypto backend
 *
 * Cisco Systems, Inc.
 */
/*
 *
 * Copyright (c) 2026 Cisco Systems, Inc.
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

#include "crypto_backend.h"

#if defined(NSS)

#define NSS_PKCS11_2_0_COMPAT 1

#include <nss.h>

static NSSInitContext *srtp_nss_context = NULL;

srtp_err_status_t srtp_crypto_backend_init(void)
{
    if (srtp_nss_context != NULL) {
        return srtp_err_status_ok;
    }

    /* Initialize NSS equiv of NSS_NoDB_Init(NULL) */
    srtp_nss_context = NSS_InitContext(
        "", "", "", "", NULL,
        NSS_INIT_READONLY | NSS_INIT_NOCERTDB | NSS_INIT_NOMODDB |
            NSS_INIT_FORCEOPEN | NSS_INIT_OPTIMIZESPACE);
    if (srtp_nss_context == NULL) {
        return srtp_err_status_cipher_fail;
    }

    return srtp_err_status_ok;
}

void srtp_crypto_backend_shutdown(void)
{
    if (srtp_nss_context != NULL) {
        NSS_ShutdownContext(srtp_nss_context);
        srtp_nss_context = NULL;
    }
}

#elif defined(MBEDTLS)

#include <psa/crypto.h>

static int srtp_psa_initialized = 0;

srtp_err_status_t srtp_crypto_backend_init(void)
{
    if (srtp_psa_initialized) {
        return srtp_err_status_ok;
    }

    if (psa_crypto_init() != PSA_SUCCESS) {
        return srtp_err_status_cipher_fail;
    }
    srtp_psa_initialized = 1;

    return srtp_err_status_ok;
}

void srtp_crypto_backend_shutdown(void)
{
    if (srtp_psa_initialized) {
        /* this was not called previously so do not do it now either */
        /* mbedtls_psa_crypto_free(); */
        srtp_psa_initialized = 0;
    }
}

#else

srtp_err_status_t srtp_crypto_backend_init(void)
{
    return srtp_err_status_ok;
}

void srtp_crypto_backend_shutdown(void) {}

#endif
