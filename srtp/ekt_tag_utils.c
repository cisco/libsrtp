/*
 *  eck_tag_utils.c
 *  
 *  Copyright (C) 2015
 *  Cisco Systems, Inc.
 *  All Rights Reserved.
 *
 *  Author:
 *      Paul E. Jones
 *
 *  Description:
 *      This file implements functions used for "EKT_Plaintext" encrytion
 *      and decryption.  The AES Key Wrap with Padding (RFC 5649) and
 *      AES Key Wrap logic (RFC 3394) are implemented within this module.
 *
 *  Portability Issues:
 *      It is assumed that The AES ECB cipher routines will encrypt or
 *      decrypt "in place", which AES can do and the AES implementations
 *      in OpenSSL and integrated in libsrtp will do.  Thus, the plaintext
 *      and ciphertext pointers are the same when attempting to encrypt data
 *      in some instances.
 *
 *  Dependencies:
 *      None.
 *
 */

#include "srtp_priv.h"
#include "err.h"
#include "srtp.h"

/*
 * Reference the external module name
 */
extern srtp_debug_module_t mod_srtp;

static const unsigned char Alternative_IV[] =   /* AIV per RFC 5649         */
{
    0xA6, 0x59, 0x59, 0xA6
};
static const uint32_t AES_Key_Wrap_with_Padding_Max = 0xFFFFFFFF;

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
                                unsigned int *ekt_ciphertext_length)
{
    int i;                                      /* Loop counter             */
    unsigned char alternative_iv[4];            /* Alternative IV           */
    srtp_cipher_t *kw;
    srtp_err_status_t stat;

    /*
     * Ensure we do not receive NULL pointers
     */
    if (!ekt_plaintext || !ekt_ciphertext || !ekt_ciphertext_length)
    {
        debug_print(mod_srtp,
                    "EKT plaintext encrypt pointers to buffers invalid",
                    NULL);
        return srtp_err_status_bad_param;
    }

    /*
     * Check to ensure that the plaintext lenth is properly bounded
     */
    if (!(ekt_plaintext_length) ||
        (ekt_plaintext_length > AES_Key_Wrap_with_Padding_Max))
    {
        debug_print(mod_srtp,
                    "EKT plaintext encrypt plaintext length invalid",
                    NULL);
        return srtp_err_status_bad_param;
    }

    /*
     * XOR the Alternative IV with the ROC value (no effect when ROC == 0) and
     * use that when performing the AES key wrap
     */
    memcpy(alternative_iv, Alternative_IV, 4);
    for(i=3; (i>=0) && (rollover_counter); i--, rollover_counter>>=8)
    {
        alternative_iv[i] ^= (unsigned char) (rollover_counter & 0xFF);
    }


    /* allocate key wrap cipher */
    stat = srtp_crypto_kernel_alloc_cipher(SRTP_AESKW_128, &kw, ekt_key_length/8, 0); 
    if (stat) {
        debug_print(mod_srtp, "Failed to allocate key wrap cipher", NULL);
	return stat;
    }

    /* initialize key wrap cipher */
    stat = srtp_cipher_init(kw, ekt_key);
    if (stat) {
        debug_print(mod_srtp, "Failed to initialize key wrap cipher", NULL);
	return stat; 
    }

    /*
     * Set the IV 
     */
    stat = srtp_cipher_set_iv(kw, (uint8_t*)alternative_iv, direction_encrypt);
    if (stat) {
        debug_print(mod_srtp, "Failed to set key wrap IV", NULL);
        return stat;
    }

    /* 
     * Encrypt the payload  
     */
    memcpy(ekt_ciphertext, ekt_plaintext, ekt_plaintext_length);
    *ekt_ciphertext_length = ekt_plaintext_length;
    stat = srtp_cipher_encrypt(kw, (uint8_t*)ekt_ciphertext, ekt_ciphertext_length);
    if (stat) {
        debug_print(mod_srtp, "Key wrap encryption failed", NULL);
        return srtp_err_status_cipher_fail;
    }

    /*
     * Dealloc the key wrap cipher.
     */
    srtp_cipher_dealloc(kw);
    return srtp_err_status_ok;
}

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
                                unsigned int *ekt_plaintext_length)
{
    int i;                                      /* Loop counter             */
    unsigned char alternative_iv[4];            /* Alternative IV           */
    srtp_cipher_t *kw;
    srtp_err_status_t stat;

    /*
     * Ensure we do not receive NULL pointers
     */
    if (!ekt_key || !ekt_ciphertext || !ekt_plaintext || !ekt_plaintext_length)
    {
        debug_print(mod_srtp,
                    "EKT ciphertext decryption pointers to buffers invalid",
                    NULL);
        return srtp_err_status_bad_param;
    }

    /*
     * Check to ensure that the ciphertext length is proper, though no
     * length check is performed.  (Note: "& 0x07" == "% 8")
     */
    if ((ekt_ciphertext_length & 0x07) || (!ekt_ciphertext_length))
    {
        debug_print(mod_srtp,
                    "EKT ciphertext length invalid",
                    NULL);
        return srtp_err_status_bad_param;
    }

    /*
     * XOR the Alternative IV with the ROC value (no effect when ROC == 0) and
     * use that when performing the AES key unwrap
     */
    memcpy(alternative_iv, Alternative_IV, 4);
    for(i=3; (i>=0) && (rollover_counter); i--, rollover_counter>>=8)
    {
        alternative_iv[i] ^= (unsigned char) (rollover_counter & 0xFF);
    }

    /* allocate key wrap cipher */
    stat = srtp_crypto_kernel_alloc_cipher(SRTP_AESKW_128, &kw, ekt_key_length/8, 0); 
    if (stat) {
        debug_print(mod_srtp, "Failed to allocate key wrap cipher", NULL);
	return stat;
    }

    /* initialize key wrap cipher */
    stat = srtp_cipher_init(kw, ekt_key);
    if (stat) {
        debug_print(mod_srtp, "Failed to initialize key wrap cipher", NULL);
	return stat; 
    }

    /*
     * Set the IV 
     */
    stat = srtp_cipher_set_iv(kw, (uint8_t*)alternative_iv, direction_decrypt);
    if (stat) {
        debug_print(mod_srtp, "Failed to set key wrap IV", NULL);
        return stat;
    }

    /* 
     * Decrypt the payload  
     */
    memcpy(ekt_plaintext, ekt_ciphertext, ekt_ciphertext_length);
    *ekt_plaintext_length = ekt_ciphertext_length;
    stat = srtp_cipher_encrypt(kw, (uint8_t*)ekt_plaintext, ekt_plaintext_length);
    if (stat) {
        debug_print(mod_srtp, "Key wrap decryption failed", NULL);
        return srtp_err_status_cipher_fail;
    }

    /*
     * Dealloc the key wrap cipher.
     */
    srtp_cipher_dealloc(kw);
    return srtp_err_status_ok;
}

