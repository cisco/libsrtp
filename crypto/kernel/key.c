/*
 * key.c
 *
 * key usage limits enforcement
 *
 * David A. Mcgrew
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "key.h"

srtp_err_status_t srtp_key_limit_set(srtp_key_limit_t key,
                                     const srtp_xtd_seq_num_t s)
{
    if (key == NULL || s == 0) {
        return srtp_err_status_bad_param;
    }
    key->limit = s;
    key->used = 0;
    key->soft_warned = false;
    return srtp_err_status_ok;
}

bool srtp_key_limit_is_expired(srtp_key_limit_t key)
{
    return key == NULL || key->used >= key->limit;
}

/*
 * callers reject an expired key before encrypting; the check also prevents
 * incrementing an exhausted count. When the soft limit and expiry fall on
 * the same packet only the hard limit is reported.
 */
srtp_key_event_t srtp_key_limit_update(srtp_key_limit_t key)
{
    if (key->used >= key->limit) {
        return srtp_key_event_normal;
    }

    key->used++;
    if (key->used == key->limit) {
        return srtp_key_event_hard_limit;
    }
    if (!key->soft_warned && key->limit - key->used < key->limit / 10) {
        key->soft_warned = true;
        return srtp_key_event_soft_limit;
    }
    return srtp_key_event_normal;
}

void srtp_key_limit_carry_over(srtp_key_limit_t to,
                               const struct srtp_key_limit_ctx_t *from)
{
    if (to == NULL || from == NULL) {
        return;
    }

    to->used = from->used;
    to->soft_warned = from->soft_warned;
}
