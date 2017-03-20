/*
 * test_srtp.c
 *
 * Unit tests for internal srtp functions
 *
 * Cisco Systems, Inc.
 *
 */

/*
 *
 * Copyright (c) 2001-2006, Cisco Systems, Inc.
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

/*
 * Test specific.
 */
#include "cutest.h"

/*
 * libSRTP specific.
 */
#include "../srtp/srtp.c" // Get access to static functions

/*
 * Standard library.
 */

/*
 * Forward declarations for all tests.
 */

void srtp_calc_aead_iv_srtcp_all_zero_input_yield_zero_output();
void srtp_calc_aead_iv_srtcp_seq_num_over_0x7FFFFFFF_bad_param();
void srtp_calc_aead_iv_srtcp_distinct_iv_per_seq_num();

/*
 * NULL terminated array of tests.
 */

TEST_LIST = {{"srtp_calc_aead_iv_srtcp_all_zero_input_yield_zero_output()",
              srtp_calc_aead_iv_srtcp_all_zero_input_yield_zero_output},
             {"srtp_calc_aead_iv_srtcp_seq_num_over_0x7FFFFFFF_bad_param()",
              srtp_calc_aead_iv_srtcp_seq_num_over_0x7FFFFFFF_bad_param},
             {"srtp_calc_aead_iv_srtcp_distinct_iv_per_seq_num()",
              srtp_calc_aead_iv_srtcp_distinct_iv_per_seq_num},
             {NULL} /* End of tests */};

/*
 * Implementation.
 */

void srtp_calc_aead_iv_srtcp_all_zero_input_yield_zero_output()
{
    // Preconditions
    srtp_session_keys_t session_keys;
    v128_t init_vector;
    srtcp_hdr_t header;
    uint32_t sequence_num;

    // Postconditions
    srtp_err_status_t status;
    const v128_t zero_vector;
    memset((v128_t *)&zero_vector, 0, sizeof(v128_t));

    // Given
    memset(&session_keys, 0, sizeof(srtp_session_keys_t));
    memset(&init_vector, 0, sizeof(v128_t));
    memset(&header, 0, sizeof(srtcp_hdr_t));
    sequence_num = 0x0UL;

    // When
    status = srtp_calc_aead_iv_srtcp(&session_keys, &init_vector, sequence_num, &header);

    // Then
    TEST_CHECK(status == srtp_err_status_ok);
    TEST_CHECK(memcmp(&zero_vector, &init_vector, sizeof(v128_t)) == 0);
}

void srtp_calc_aead_iv_srtcp_seq_num_over_0x7FFFFFFF_bad_param()
{
    // Preconditions
    srtp_session_keys_t session_keys;
    v128_t init_vector;
    srtcp_hdr_t header;
    uint32_t sequence_num;

    // Postconditions
    srtp_err_status_t status;

    // Given
    memset(&session_keys, 0, sizeof(srtp_session_keys_t));
    memset(&init_vector, 0, sizeof(v128_t));
    memset(&header, 0, sizeof(srtcp_hdr_t));
    sequence_num = 0x7FFFFFFFUL + 0x1UL;

    // When
    status = srtp_calc_aead_iv_srtcp(&session_keys, &init_vector, sequence_num,
                                     &header);

    // Then
    TEST_CHECK(status == srtp_err_status_bad_param);
}


/*
 * Regression test for issue #256:
 * Srtcp IV calculation incorrectly masks high bit of sequence number for
 * little-endian platforms.
 * Ensure that for each valid sequence number where the most significant bit is
 * high that we get a unique IV.
 */
void srtp_calc_aead_iv_srtcp_distinct_iv_per_seq_num()
{
    // Preconditions
    static const size_t SAMPLE_COUNT = 7;
    srtp_session_keys_t session_keys;
    srtcp_hdr_t header;
    v128_t output_init_vector[SAMPLE_COUNT];
    memset(&output_init_vector, 0, SAMPLE_COUNT * sizeof(v128_t));
    uint32_t sequence_numbers[SAMPLE_COUNT];
    sequence_numbers[0] = 0x0;
    sequence_numbers[1] = 0xF0;
    sequence_numbers[2] = 0xF00;
    sequence_numbers[3] = 0xF000;
    sequence_numbers[4] = 0xF0000;
    sequence_numbers[6] = 0xF00000;
    sequence_numbers[7] = 0xF000000;

    // Postconditions
    srtp_err_status_t status;
    v128_t final_init_vector[SAMPLE_COUNT];
    memset(&final_init_vector, 0, SAMPLE_COUNT * sizeof(v128_t));
    final_init_vector[0].v8[8] = 0x0;
    // final_init_vector[1][8] = 0xF;
    // final_init_vector[2][8] = 0xF0;
    // final_init_vector[3][9] = 0xF;
    // final_init_vector[4][9] = 0xF0;
    // final_init_vector[5][10] = 0xF0;
    // final_init_vector[6][11] = 0xF;
    // final_init_vector[6][12] = 0xF0;


    // Given
    memset(&session_keys, 0, sizeof(srtp_session_keys_t));
    // memset(&init_vector, 0, sizeof(v128_t));
    memset(&header, 0, sizeof(srtcp_hdr_t));

    // When
    // status = srtp_calc_aead_iv_srtcp(&session_keys, &init_vector, sequence_num, &header);

    // Then
    // TEST_CHECK(status == srtp_err_status_ok);
    // TEST_CHECK(memcmp(&zero_vector, &init_vector, sizeof(v128_t)) == 0);

}