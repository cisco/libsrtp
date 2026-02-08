/*
 * test_srtp_policy.c
 *
 * Unit tests for srtp_policy2 API
 *
 */
/*
 *
 * Copyright (c) 2026
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

#include "cutest.h"

#include "srtp.h"
#include "util.h"

static void srtp_policy2_create_destroy_ok(void)
{
    srtp_policy2_t policy;

    CHECK_RETURN(srtp_policy2_create(&policy), srtp_err_status_ok);
    CHECK(policy != NULL);

    srtp_policy2_destroy(policy);
}

static void srtp_policy2_empty_not_valid(void)
{
    srtp_policy2_t policy;

    CHECK_RETURN(srtp_policy2_create(&policy), srtp_err_status_ok);

    CHECK_RETURN(srtp_policy2_validate(policy), srtp_err_status_bad_param);

    srtp_policy2_destroy(policy);
}

static void srtp_policy2_minimal(void)
{
    // clang-format off
    uint8_t master_key[16] = {
        0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0,
        0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39,
    };
    uint8_t master_salt[14] = {
        0xc3, 0x17, 0xf2, 0xda, 0xbe, 0x35, 0x77, 0x93,
        0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6
    };
    // clang-format on

    srtp_policy2_t policy;

    CHECK_RETURN(srtp_policy2_create(&policy), srtp_err_status_ok);

    CHECK_RETURN(
        srtp_policy2_set_ssrc(policy, (srtp_ssrc_t){ ssrc_any_outbound, 0 }),
        srtp_err_status_ok);
    CHECK_RETURN(
        srtp_policy2_set_profile(policy, srtp_profile_aes128_cm_sha1_80),
        srtp_err_status_ok);
    CHECK_RETURN(srtp_policy2_set_key(policy, master_key, sizeof(master_key),
                                      master_salt, sizeof(master_salt)),
                 srtp_err_status_ok);

    CHECK_RETURN(srtp_policy2_validate(policy), srtp_err_status_ok);

    srtp_t srtp;
    srtp_init();
    CHECK_RETURN(srtp_create2(&srtp, policy), srtp_err_status_ok);
    srtp_dealloc(srtp);
    srtp_shutdown();

    srtp_policy2_destroy(policy);
}

static void srtp_policy2_mki(void)
{
    // clang-format off
    uint8_t master_key[16] = {
        0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0,
        0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39,
    };
    uint8_t master_salt[14] = {
        0xc3, 0x17, 0xf2, 0xda, 0xbe, 0x35, 0x77, 0x93,
        0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6
    };
    uint8_t mki[4] = {
        0x01, 0x02, 0x03, 0x04
    };
    // clang-format on

    srtp_policy2_t policy;

    CHECK_RETURN(srtp_policy2_create(&policy), srtp_err_status_ok);

    CHECK_RETURN(
        srtp_policy2_set_ssrc(policy, (srtp_ssrc_t){ ssrc_any_outbound, 0 }),
        srtp_err_status_ok);
    CHECK_RETURN(
        srtp_policy2_set_profile(policy, srtp_profile_aes128_cm_sha1_80),
        srtp_err_status_ok);
    CHECK_RETURN(srtp_policy2_use_mki(policy, sizeof(mki)), srtp_err_status_ok);
    CHECK_RETURN(srtp_policy2_add_key(policy, master_key, sizeof(master_key),
                                      master_salt, sizeof(master_salt), mki,
                                      sizeof(mki)),
                 srtp_err_status_ok);

    CHECK_RETURN(srtp_policy2_validate(policy), srtp_err_status_ok);

    srtp_t srtp;
    srtp_init();
    CHECK_RETURN(srtp_create2(&srtp, policy), srtp_err_status_ok);
    srtp_dealloc(srtp);
    srtp_shutdown();

    srtp_policy2_destroy(policy);
}

TEST_LIST = {
    { "srtp_policy2_create_destroy_ok()", srtp_policy2_create_destroy_ok },
    { "srtp_policy2_empty_not_valid()", srtp_policy2_empty_not_valid },
    { "srtp_policy2_minimal()", srtp_policy2_minimal },
    { "srtp_policy2_mki()", srtp_policy2_mki },
    { 0 }
};
