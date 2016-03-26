/*
 *  eck_tag_utils.h
 *  
 *  Copyright (C) 2015
 *  Cisco Systems, Inc.
 *  All Rights Reserved.
 *
 *  Author:
 *      Paul E. Jones
 *
 *  Description:
 *      This file defines function prototypes used for "EKT_Plaintext"
 *      encrytion and decryption.
 *
 *  Portability Issues:
 *      None.
 *
 */

#ifndef EKT_TAG_UTILS_H
#define EKT_TAG_UTILS_H

#include "integers.h"                           /* For uint32_t             */

/*
 *  srtp_ekt_plaintext_encrypt
 *
 *  Description:
 *      This fuction performs the AES Key Wrap with Padding for SRTP as
 *      required by the EKT specification (draft-ietf-avtcore-srtp-ekt-03).
 *      The ROC value is XORed with the alternative IV specified in RFC 5649
 *      per the draft-jones-avtcore-private-media-framework.
 *
 *  Parameters:
 *      ekt_key [in]
 *          A pointer to the EKT key.
 *      ekt_key_length [in]
 *          The length in bits of the EKT key.  Valid values are 128, 192,
 *          and 256.
 *      ekt_plaintext [in]
 *          The "EKT_Plaintext" value that is to be encrypted with the
 *          provided key.
 *      ekt_plaintext_length [in]
 *          The length in octets of the ekt_plaintext paramter.  This value
 *          must be in the range of 1 to AES_Key_Wrap_with_Padding_Max.
 *      rollover_counter [in]
 *          The SRTP "rollover counter" value.  This parameter should always
 *          be zero (0) except when draft-jones-perc-private-media-framework-01
 *          is being used.
 *      ekt_ciphertext [out]
 *          A pointer to a buffer to hold the "EKT_Ciphertext".  This function
 *          does not allocate memory and expects the caller to pass a pointer
 *          to a block of memory large enough to hold the output.
 *      ekt_ciphertext_length [out]
 *          This is a the length of the resulting ekt_ciphertext.
 *
 *  Returns:
 *      srtp_err_status_ok (0) if successful, non-zero if there was an error.
 *      The error code will be one defined by srtp_err_status_t.
 *
 *  Comments:
 *      None.
 *
 */
int srtp_ekt_plaintext_encrypt( const unsigned char *ekt_key,
                                unsigned int ekt_key_length,
                                const unsigned char *ekt_plaintext,
                                unsigned int ekt_plaintext_length,
                                uint32_t rollover_counter,
                                unsigned char *ekt_ciphertext,
                                unsigned int *ekt_ciphertext_length);

/*
 *  srtp_ekt_ciphertext_decrypt
 *
 *  Description:
 *      This function uses AES Key Wrap with Padding procedures to decrypt
 *      the "EKT_Ciphertext" as specified in draft-ietf-avtcore-srtp-ekt-03.
 *      The ROC value is XORed with the alternative IV specified in RFC 5649
 *      per the draft-jones-avtcore-private-media-framework.
 *
 *  Parameters:
 *      ekt_key [in]
 *          A pointer to the EKT key.
 *      ekt_key_length [in]
 *          The length in bits of the EKT key.  Valid values are 128, 192,
 *          and 256.
 *      ekt_ciphertext [in]
 *          A pointer to the "EKT_Ciphertext" to decrypt.
 *      ekt_ciphertext_length [in]
 *          This is a the length of the ekt_ciphertext.
 *      rollover_counter [in]
 *          The SRTP "rollover counter" value.  This parameter should always
 *          be zero (0) except when draft-jones-perc-private-media-framework-01
 *          is being used.
 *      ekt_plaintext [out]
 *          A pointer to a buffer to hold the "EKT_Plaintext".  This function
 *          does not allocate memory and expects the caller to pass a pointer
 *          to a block of memory large enough to hold the output.
 *      ekt_plaintext_length [out]
 *          This is a the length of the resulting ekt_plaintext.
 *
 *  Returns:
 *      srtp_err_status_ok (0) if successful, non-zero if there was an error.
 *      The error code will be one defined by srtp_err_status_t.
 *
 *  Comments:
 *      None.
 *
 */
int srtp_ekt_ciphertext_decrypt(const unsigned char *ekt_key,
                                unsigned int ekt_key_length,
                                const unsigned char *ekt_ciphertext,
                                unsigned int ekt_ciphertext_length,
                                uint32_t rollover_counter,
                                unsigned char *ekt_plaintext,
                                unsigned int *ekt_plaintext_length);

#endif /* EKT_TAG_UTILS_H */
