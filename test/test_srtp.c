/*
 * Tests specific.
 */
#include "cutest.h"

/*
 * libSRTP specific.
 */
#include "../srtp/srtp.c" // Get access to static functions

/*
 * Standard library
 */

/*
 *Forward declaration of all tests
 */

void srtp_calc_aead_iv_srtcp_all_zero_input_yield_zero_output();
// void srtp_calc_aead_iv_srtcp_seq_num_over_0x7FFFFFFF_bad_param();

/*
 * NULL terminated array of tests.
 */

TEST_LIST = {{"srtp_calc_aead_iv_srtcp_all_zero_input_yield_zero_output()",
              srtp_calc_aead_iv_srtcp_all_zero_input_yield_zero_output},
             /* {"srtp_calc_aead_iv_srtcp_seq_num_over_0x7FFFFFFF_bad_param()",
              srtp_calc_aead_iv_srtcp_seq_num_over_0x7FFFFFFF_bad_param}, */
             {NULL} /* End of tests */};

/*
 * Implementation
 */

void srtp_calc_aead_iv_srtcp_all_zero_input_yield_zero_output()
{
    // Preconditions
    srtp_session_keys_t session_keys;
    v128_t init_vector;
    srtcp_hdr_t header;
    uint32_t sequence_num;

    // Postconditions
    const v128_t zero_vector;
    memset((v128_t *)&zero_vector, 0, sizeof(v128_t));

    // Given
    memset(&session_keys, 0, sizeof(srtp_session_keys_t));
    memset(&init_vector, 0, sizeof(v128_t));
    memset(&header, 0, sizeof(srtcp_hdr_t));
    sequence_num = 0x0;

    // When
    srtp_calc_aead_iv_srtcp(&session_keys, &init_vector, sequence_num, &header);

    // Then
    TEST_CHECK(memcmp(&zero_vector, &init_vector, sizeof(v128_t)) == 0);
}

/*
void srtp_calc_aead_iv_srtcp_seq_num_over_0x7FFFFFFF_bad_param()
{
    // Preconditions
    srtp_session_keys_t session_keys;
    v128_t init_vector;
    srtcp_hdr_t header;
    uint32_t sequence_num;

    // Postconditions
    srtp_err_status_t status

    // Given
    memset(&session_keys, 0, sizeof(srtp_session_keys_t));
    memset(&init_vector, 0, sizeof(v128_t));
    memset(&header, 0, sizeof(srtcp_hdr_t));
    sequence_num = 0x7FFFFFFF + 0x1;

    // When
    srtp_err_status_t status = srtp_calc_aead_iv_srtcp(
        &session_keys, &init_vector, sequence_num, &header);

    // Then
    TEST_CHECK(status == srtp_err_status_bad_param);
}
*/
