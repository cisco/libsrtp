/*
 * auth.h
 *
 * common interface to authentication functions
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 */

/*
 *
 * Copyright (c) 2001-2017, Cisco Systems, Inc.
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

#ifndef SRTP_AUTH_STRUCTS_H
#define SRTP_AUTH_STRUCTS_H

#include "srtp.h"
#include "crypto_types.h" /* for values of auth_type_id_t */

#ifdef __cplusplus
extern "C" {
#endif

typedef const struct srtp_auth_type_t *srtp_auth_type_pointer;
typedef struct srtp_auth_t *srtp_auth_pointer_t;

typedef srtp_err_status_t (*srtp_auth_alloc_func)(srtp_auth_pointer_t *ap,
                                                  int key_len,
                                                  int out_len);

typedef srtp_err_status_t (*srtp_auth_init_func)(void *state,
                                                 const uint8_t *key,
                                                 int key_len);

typedef srtp_err_status_t (*srtp_auth_dealloc_func)(srtp_auth_pointer_t ap);

typedef srtp_err_status_t (*srtp_auth_compute_func)(void *state,
                                                    const uint8_t *buffer,
                                                    int octets_to_auth,
                                                    int tag_len,
                                                    uint8_t *tag);

typedef srtp_err_status_t (*srtp_auth_update_func)(void *state,
                                                   const uint8_t *buffer,
                                                   int octets_to_auth);

typedef srtp_err_status_t (*srtp_auth_start_func)(void *state);

/* srtp_auth_type_t */
struct srtp_auth_type_t {
    srtp_auth_alloc_func alloc;
    srtp_auth_dealloc_func dealloc;
    srtp_auth_init_func init;
    srtp_auth_compute_func compute;
    srtp_auth_update_func update;
    srtp_auth_start_func start;
    const char *description;
    const srtp_auth_test_case_t *test_data;
    srtp_auth_type_id_t id;
};

struct srtp_auth_t {
    const srtp_auth_type_t *type;
    void *state;
    int out_len;    /* length of output tag in octets */
    int key_len;    /* length of key in octets        */
    int prefix_len; /* length of keystream prefix     */
};

#ifdef __cplusplus
}
#endif

#endif /* SRTP_AUTH_STRUCTS_H */
