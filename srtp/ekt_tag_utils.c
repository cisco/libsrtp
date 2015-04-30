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
 *      and decryption.  It utilizes OpenSSL for AES encryption.  The AES Key
 *      Wrap with Padding (RFC 5649) and AES Key Wrap logic (RFC 3394) are
 *      implemented within this module.
 *
 *  Portability Issues:
 *      It is assumed that The AES ECB cipher routines will encrypt or
 *      decrypt "in place", which AES can do and the implementation
 *      in OpenSSL certainly does do.  Thus, the plaintext and ciphertext
 *      pointers are the same when attempting to encrypt data in some
 *      instances.
 *
 *  Dependencies:
 *      OpenSSL with AES encryption via the EVP_*() APIs.
 *
 */

#include <string.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "srtp_priv.h"
#include "err.h"
#include "srtp.h"
#include "ekt_tag_utils.h"

/*
 * Reference the external module name
 */
extern srtp_debug_module_t mod_srtp;

/*
 * Define module-level global constants
 */
static const unsigned char AES_Key_Wrap_Default_IV[] = /* The default IV    */
{
    0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6
};
static const unsigned char Alternative_IV[] =   /* AIV per RFC 5649         */
{
    0xA6, 0x59, 0x59, 0xA6
};
static const uint32_t AES_Key_Wrap_with_Padding_Max = 0xFFFFFFFF;
                                                /* Max length per RFC 5649  */

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
 *          be zero (0) if draft-jones-avtcore-private-media-framework is
 *          not being used.
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

    return srtp_ekt_aes_key_wrap_with_padding(  ekt_key,
                                                ekt_key_length,
                                                ekt_plaintext,
                                                ekt_plaintext_length,
                                                alternative_iv,
                                                ekt_ciphertext,
                                                ekt_ciphertext_length);
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
 *          be zero (0) if draft-jones-avtcore-private-media-framework is
 *          not being used.
 *      ekt_plaintext_length [in]
 *          The length in octets of the ekt_plaintext paramter.
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

    return srtp_ekt_aes_key_unwrap_with_padding(ekt_key,
                                                ekt_key_length,
                                                ekt_ciphertext,
                                                ekt_ciphertext_length,
                                                alternative_iv,
                                                ekt_plaintext,
                                                ekt_plaintext_length);
}

/*
 *  srtp_ekt_aes_ecb_encrypt
 *
 *  Description:
 *      This fuction performs AES encryption using ECB mode.
 *
 *  Parameters:
 *      key [in]
 *          A pointer to the key used for encryption
 *      key_length [in]
 *          The length in bits of the encryption key.  Valid values are
 *          128, 192, and 256.
 *      plaintext [in]
 *          The plaintext that is to be encrypted with the given key.
 *      plaintext_length [in]
 *          The length in octets of the plaintext paramter.  This value
 *          must be a multiple of 16 octets. (See comments.)
 *      ciphertext [out]
 *          A pointer to a buffer to hold the ciphertext.  This function does
 *          not allocate memory and expects the caller to pass a pointer
 *          to a block of memory large enough to hold the output.
 *
 *  Returns:
 *      srtp_err_status_ok (0) if successful, non-zero if there was an error.
 *      The error code will be one defined by srtp_err_status_t.  The length
 *      of the ciphertext will be exactly the same size as the original
 *      plaintext.
 *
 *  Comments:
 *      The reason that the plaintext must be a multiple of 16 octets is
 *      that AES operates only on blocks of 16 octets.  This function has a
 *      dependency on the OpenSSL crpyto library to perform AES encryption.
 *      Note that this function will encrypt "in place", meaning the
 *      plaintext buffer and ciphertext buffers might point to the same
 *      chunk of memory.  This property is required by the key wrap function.
 *
 */
int srtp_ekt_aes_ecb_encrypt(   const unsigned char *key,
                                unsigned int key_length,
                                const unsigned char *plaintext,
                                unsigned int plaintext_length,
                                unsigned char *ciphertext)
{
    EVP_CIPHER_CTX ctx;                         /* Crypto context           */
    const EVP_CIPHER *cipher = NULL;            /* Cipher to use            */
    int ciphertext_length = 0;                  /* Length of ciphertext     */
    int final_length = 0;                       /* Length of final text     */

    /*
     * Ensure the plaintext length is valid (Note: "& 0x0F" == "% 16")
     */
    if ((plaintext_length & 0x0F) || (!plaintext_length))
    {
        debug_print(mod_srtp,
                    "plaintext length invalid for AES ECB encryption",
                    NULL);
        return srtp_err_status_bad_param;
    }

    /*
     * Select the cipher based on the key length
     */
    switch(key_length)
    {
        case 128:
            cipher = EVP_aes_128_ecb();
            break;
        case 192:
            cipher = EVP_aes_192_ecb();
            break;
        case 256:
            cipher = EVP_aes_256_ecb();
            break;
        default:
            debug_print(mod_srtp,
                        "invalid key length for AES ECB encryption",
                        NULL);
            return srtp_err_status_bad_param;
    }

    /*
     * Encrypt the plaintext
     */
    EVP_CIPHER_CTX_init(&ctx);

    if (!EVP_EncryptInit_ex(&ctx,
                            cipher,
                            NULL,
                            key,
                            NULL))
    {
        debug_print(mod_srtp,
                    "unable to initialize AES ECB cipher for encryption",
                    NULL);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return srtp_err_status_cipher_fail;
    }

    EVP_CIPHER_CTX_set_padding(&ctx, 0);

    if (!EVP_EncryptUpdate(&ctx,
                           ciphertext,
                           &ciphertext_length,
                           plaintext,
                           plaintext_length))
    {
        debug_print(mod_srtp,
                    "call to EVP_EncryptUpdate failed trying to encrypt "
                    "using AES ECB",
                    NULL);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return srtp_err_status_cipher_fail;
    }

    if (!EVP_EncryptFinal_ex(   &ctx,
                                ciphertext + ciphertext_length,
                                &final_length))
    {
        debug_print(mod_srtp,
                    "call to EVP_EncryptFinal failed trying to encrypt "
                    "using AES ECB",
                    NULL);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return srtp_err_status_cipher_fail;
    }

    EVP_CIPHER_CTX_cleanup(&ctx);

    /*
     * Verify the ciphertext length is correct
     */
    if (ciphertext_length + final_length != plaintext_length)
    {
        debug_print(mod_srtp,
                    "Unexpected ciphertext length in AES ECB encryption",
                    NULL);
        return srtp_err_status_cipher_fail;
    }

    return srtp_err_status_ok;
}

/*
 *  srtp_ekt_aes_ecb_decrypt
 *
 *  Description:
 *      This fuction performs AES decryption using ECB mode.
 *
 *  Parameters:
 *      key [in]
 *          A pointer to the key used for decryption
 *      key_length [in]
 *          The length in bits of the decryption key.  Valid values are
 *          128, 192, and 256.
 *      ciphertext [in]
 *          The ciphertext that is to be decrypted with the given key.
 *      ciphertext_length [in]
 *          The length in octets of the ciphertext paramter.  This value
 *          must be a multiple of 16 octets. (See comments.)
 *      plaintext [out]
 *          A pointer to a buffer to hold the plaintext.  This function does
 *          not allocate memory and expects the caller to pass a pointer
 *          to a block of memory large enough to hold the output.
 *
 *  Returns:
 *      srtp_err_status_ok (0) if successful, non-zero if there was an error.
 *      The error code will be one defined by srtp_err_status_t.  The length
 *      of the plaintext will be exactly the same size as the original
 *      ciphertext.
 *
 *  Comments:
 *      The reason that the ciphertext must be a multiple of 16 octets is
 *      that AES operates only on blocks of 16 octets.  This function has a
 *      dependency on the OpenSSL crpyto library to perform AES encryption.
 *      Note that this function will decrypt "in place", meaning the
 *      plaintext buffer and ciphertext buffers might point to the same
 *      chunk of memory.  This property is required by the key unwrap function.
 *
 */
int srtp_ekt_aes_ecb_decrypt(   const unsigned char *key,
                                unsigned int key_length,
                                const unsigned char *ciphertext,
                                unsigned int ciphertext_length,
                                unsigned char *plaintext)
{
    EVP_CIPHER_CTX ctx;                         /* Crypto context           */
    const EVP_CIPHER *cipher = NULL;            /* Cipher to use            */
    int plaintext_length = 0;                   /* Length of ciphertext     */
    int final_length = 0;                       /* Length of final text     */

    /*
     * Ensure the ciphertext length is valid (Note: "& 0x0F" == "% 16")
     */
    if ((ciphertext_length & 0x0F) || (!ciphertext_length))
    {
        debug_print(mod_srtp,
                    "ciphertext length invalid for AES ECB decryption",
                    NULL);
        return srtp_err_status_bad_param;
    }

    /*
     * Select the cipher based on the key length
     */
    switch(key_length)
    {
        case 128:
            cipher = EVP_aes_128_ecb();
            break;
        case 192:
            cipher = EVP_aes_192_ecb();
            break;
        case 256:
            cipher = EVP_aes_256_ecb();
            break;
        default:
            debug_print(mod_srtp,
                        "invalid key length for AES ECB decryption",
                        NULL);
            return srtp_err_status_bad_param;
    }

    /*
     * Decrypt the ciphertext
     */
    EVP_CIPHER_CTX_init(&ctx);

    if (!EVP_DecryptInit_ex(&ctx,
                            cipher,
                            NULL,
                            key,
                            NULL))
    {
        debug_print(mod_srtp,
                    "unable to initialize AES ECB cipher for decryption",
                    NULL);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return srtp_err_status_cipher_fail;
    }

    EVP_CIPHER_CTX_set_padding(&ctx, 0);

    if (!EVP_DecryptUpdate(&ctx,
                           plaintext,
                           &plaintext_length,
                           ciphertext,
                           ciphertext_length))
    {
        debug_print(mod_srtp,
                    "call to EVP_EncryptUpdate failed trying to decrypt "
                    "using AES ECB",
                    NULL);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return srtp_err_status_cipher_fail;
    }

    if (!EVP_DecryptFinal_ex(   &ctx,
                                plaintext + plaintext_length,
                                &final_length))
    {
        debug_print(mod_srtp,
                    "call to EVP_EncryptFinal failed trying to decrypt "
                    "using AES ECB",
                    NULL);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return srtp_err_status_cipher_fail;
    }

    EVP_CIPHER_CTX_cleanup(&ctx);

    /*
     * Verify the plaintext length is correct
     */
    if (plaintext_length + final_length != ciphertext_length)
    {
        debug_print(mod_srtp,
                    "Unexpected plaintext length in AES ECB decryption",
                    NULL);
        return srtp_err_status_cipher_fail;
    }

    return srtp_err_status_ok;
}

/*
 *  srtp_ekt_aes_key_wrap
 *
 *  Description:
 *      This performs the AES Key Wrap as per RFC 3394.
 *
 *  Parameters:
 *      key [in]
 *          A pointer to the key used for encryption.
 *      key_length [in]
 *          The length in bits of the encryption key.  Valid values are
 *          128, 192, and 256.
 *      plaintext [in]
 *          The plaintext that is to be encrypted with the given key.
 *      plaintext_length [in]
 *          The length in octets of the plaintext paramter.  This value
 *          must be a multiple of 8 octets.
 *      initialization_vector [in]
 *          The 16 octet initialization vector to use with AES Key Wrap.
 *          If this value is NULL, then the default IV will be used as per
 *          RFC 3394.
 *      ciphertext [out]
 *          A pointer to a buffer to hold the ciphertext.  This function does
 *          not allocate memory and expects the caller to pass a pointer
 *          to a block of memory large enough to hold the output.
 *      ciphertext_length [out]
 *          This is a the length of the resulting ciphertext, which will be
 *          exactly 8 octets larger than the original plaintext.
 *
 *  Returns:
 *      srtp_err_status_ok (0) if successful, non-zero if there was an error.
 *      The error code will be one defined by srtp_err_status_t.  The
 *      ciphertext and ciphertext_length parameters will be populated
 *      with the encrypted data and length, respectively.
 *
 *  Comments:
 *      The reason that the plaintext must be a multiple of 8 octets is
 *      that AES Key Wrap requires it (see RFC 3394).  The encryption routines
 *      expected to encrypt "in place", which AES will do.  Thus, the plaintext
 *      and ciphertext pointers are the same when attempting to encrypt data
 *      in some parts of this code.  However, callers of this function should
 *      use different pointers to memory for the ciphertext and plaintext.
 *
 */
int srtp_ekt_aes_key_wrap(  const unsigned char *key,
                            unsigned int key_length,
                            const unsigned char *plaintext,
                            unsigned int plaintext_length,
                            const unsigned char *initialization_vector,
                            unsigned char *ciphertext,
                            unsigned int *ciphertext_length)
{
    int i, j, k;                                /* Loop counters            */
    unsigned int n;                             /* Number of 64-bit blocks  */
    unsigned int t, tt;                         /* Step counters            */
    unsigned char *A;                           /* Integrity check register */
    unsigned char B[16];                        /* Buffer for encryption    */
    unsigned char *R;                           /* Pointer to register i    */

    /*
     * Ensure the plaintext length is valid (Note: "& 0x07" == "% 8")
     */
    if ((plaintext_length & 0x07) || (!plaintext_length))
    {
        debug_print(mod_srtp,
                    "plaintext length invalid for AES Key Wrap",
                    NULL);
        return srtp_err_status_bad_param;
    }

    /*
     * Determine the number of 64-bit blocks to process
     */
    n = plaintext_length >> 3;

    /*
     * Assign the IV
     */
    A = B;
    if (initialization_vector)
    {
        memcpy(A, initialization_vector, 8);
    }
    else
    {
        memcpy(A, AES_Key_Wrap_Default_IV, 8);
    }

    /*
     * Perform the key wrap
     */
    memcpy(ciphertext+8, plaintext, plaintext_length);
    for(j=0, t=1; j<=5; j++)
    {
        for(i=1, R=ciphertext+8; i<=n; i++, t++, R+=8)
        {
            memcpy(B+8, R, 8);
            if (srtp_ekt_aes_ecb_encrypt(   key,
                                            key_length,
                                            B,
                                            16,
                                            B))
            {
                return srtp_err_status_cipher_fail;
            }
            for(k=7, tt=t; (k>=0) && (tt>0); k--, tt>>=8)
            {
                A[k] ^= (unsigned char) (tt & 0xFF);
            }
            memcpy(R, B+8, 8);
        }
    }
    memcpy(ciphertext, A, 8);

    /*
     * Set the ciphertext length value
     */
    *ciphertext_length = plaintext_length + 8;

    return srtp_err_status_ok;
}

/*
 *  srtp_ekt_aes_key_unwrap
 *
 *  Description:
 *      This performs the AES Key Unwrap as per RFC 3394.  It allows one
 *      to optionally pass a pointer to a buffer to hold the 64-bit IV.
 *      If the "initialization_vector" is provided, this will be used for
 *      integrity checking, rather than using the default value defined
 *      in RFC 3394.  Additionally, to support AES Key Wrap with Padding
 *      (RFC 5639), the "initialization_vector" should be NULL and the
 *      caller should provide a pointer to a 64-bit "integrity_data".
 *      In that case, this function will NOT perform integrity checking
 *      on the unwrapped key.
 *
 *  Parameters:
 *      key [in]
 *          A pointer to the key used for encryption.
 *      key_length [in]
 *          The length in bits of the encryption key.  Valid values are
 *          128, 192, and 256.
 *      ciphertext [in]
 *          The ciphertext that is to be decrypted with the given key.
 *      ciphertext_length [in]
 *          The length in octets of the ciphertext paramter.  This value
 *          must be a multiple of 8 octets.
 *      initialization_vector [in]
 *          The 16 octet initialization vector to use with AES Key Wrap.
 *          If this value is NULL, then the default IV will be used as per
 *          RFC 3394.  However, if "integrity_data" is not NULL, this
 *          routine will not perform an integrity check and, instead,
 *          it will populate that buffer with the integrity data for the
 *          caller to further process.
 *      plaintext [out]
 *          A pointer to a buffer to hold the plaintext.  This function does
 *          not allocate memory and expects the caller to pass a pointer
 *          to a block of memory large enough to hold the output.
 *      plaintext_length [out]
 *          This is a the length of the resulting plaintext, which will be
 *          exactly 8 octets smaller than the original ciphertext.
 *      integrity_data [out]
 *          This is a pointer to a 64-bit buffer that will contain
 *          the integrity data determined through the unwrap process.
 *          If this parameter is NULL, this function will perform integrity
 *          checking internally.  If this parameter is present, this function
 *          will not perform integrity checking and simply return the
 *          integrity data to the caller to be checked.  If both this
 *          and the initialization_vector are present, this parameter
 *          takes precedence.
 *
 *  Returns:
 *      srtp_err_status_ok (0) if successful, non-zero if there was an error.
 *      The error code will be one defined by srtp_err_status_t.  The
 *      plaintext and plaintext_length parameters will be populated
 *      with the decrypted data and length, respectively.  If the
 *      integrity_data parameter was not NULL, then the 64-bit integrity
 *      check register (A[] as defined in RFC 3394) will be returned to
 *      the caller without the integrity data being checked.
 *
 *  Comments:
 *      The reason that the ciphertext must be a multiple of 8 octets is
 *      that AES Key Wrap requires it (see RFC 3394).  The decryption routines
 *      expected to decrypt "in place", which AES will do.  Thus, the plaintext
 *      and ciphertext pointers are the same when attempting to encrypt data
 *      in some parts of this code.  However, callers of this function should
 *      use different pointers to memory for the ciphertext and plaintext.
 *
 */
int srtp_ekt_aes_key_unwrap(    const unsigned char *key,
                                unsigned int key_length,
                                const unsigned char *ciphertext,
                                unsigned int ciphertext_length,
                                const unsigned char *initialization_vector,
                                unsigned char *plaintext,
                                unsigned int *plaintext_length,
                                unsigned char *integrity_data)
{
    int i, j, k;                                /* Loop counters            */
    unsigned int n;                             /* Number of 64-bit blocks  */
    unsigned int t, tt;                         /* Step counters            */
    unsigned char *A;                           /* Integrity check register */
    unsigned char B[16];                        /* Buffer for encryption    */
    unsigned char *R;                           /* Pointer to register i    */

    /*
     * Ensure the plaintext length is valid (Note: "& 0x07" == "% 8")
     */
    if ((ciphertext_length & 0x07) || (!ciphertext_length))
    {
        debug_print(mod_srtp,
                    "ciphertext length invalid for AES Key Unrap",
                    NULL);
        return srtp_err_status_bad_param;
    }

    /*
     * Determine the number of 64-bit blocks to process
     */
    n = (ciphertext_length-8) >> 3;

    /*
     * Assign A to be C[0] (first 64-bit block of the ciphertext)
     */
    A = B;
    memcpy(A, ciphertext, 8);

    /*
     * Perform the key wrap
     */
    memcpy(plaintext, ciphertext+8, ciphertext_length-8);
    for(j=5, t=6*n; j>=0; j--)
    {
        for(i=n, R=plaintext+ciphertext_length-16; i>=1; i--, t--, R-=8)
        {
            for(k=7, tt=t; (k>=0) && (tt>0); k--, tt>>=8)
            {
                A[k] ^= (unsigned char) (tt & 0xFF);
            }
            memcpy(B+8, R, 8);
            if (srtp_ekt_aes_ecb_decrypt(   key,
                                            key_length,
                                            B,
                                            16,
                                            B))
            {
                return srtp_err_status_cipher_fail;
            }
            memcpy(R, B+8, 8);
        }
    }

    /*
     * Set the ciphertext length value
     */
    *plaintext_length = ciphertext_length - 8;

    /*
     * If the integrity_data paramter is provided, return A[] to the caller
     * to perform integrity checking
     */
    if (integrity_data)
    {
        memcpy(integrity_data, A, 8);
    }
    else
    {
        /*
         * Perform integrity checking internally
         */
        if (initialization_vector)
        {
            if (memcmp(initialization_vector,A,8))
            {
                return srtp_err_status_encode_err;
            }
        }
        else
        {
            if (memcmp(AES_Key_Wrap_Default_IV,A,8))
            {
                return srtp_err_status_encode_err;
            }
        }
    }

    return srtp_err_status_ok;
}

/*
 *  srtp_ekt_aes_key_wrap_with_padding
 *
 *  Description:
 *      This fuction performs the AES Key Wrap with Padding as specified in
 *      RFC 5649.
 *
 *  Parameters:
 *      key [in]
 *          A pointer to the key encrypting key (KEK).
 *      key_length [in]
 *          The length in bits of the KEK.  Valid values are 128, 192,
 *          and 256.
 *      plaintext [in]
 *          The plaintext value that is to be encrypted with the provided key.
 *      plaintext_length [in]
 *          The length in octets of the plaintext paramter.  This value
 *          must be in the range of 1 to AES_Key_Wrap_with_Padding_Max.
 *      alternative_iv [in]
 *          This is an alternative_iv vector to use.  The default value
 *          is specified in RFC 5649, but a different value may be provided.
 *          A NULL value will cause the function to use the default IV.
 *      ciphertext [out]
 *          A pointer to a buffer to hold the ciphertext.  This function does
 *          not allocate memory and expects the caller to pass a pointer
 *          to a block of memory large enough to hold the output.
 *      ciphertext_length [out]
 *          This is a the length of the resulting ciphertext.
 *
 *  Returns:
 *      srtp_err_status_ok (0) if successful, non-zero if there was an error.
 *      The error code will be one defined by srtp_err_status_t.
 *
 *  Comments:
 *      The encryption routines expected to encrypt "in place", which AES
 *      will do.  Thus, the plaintext and ciphertext pointers are the same
 *      when attempting to encrypt data in some parts of this code.  However,
 *      callers of this function should use different pointers to memory
 *      for the ciphertext and plaintext.
 *
 */
int srtp_ekt_aes_key_wrap_with_padding( const unsigned char *key,
                                        unsigned int key_length,
                                        const unsigned char *plaintext,
                                        unsigned int plaintext_length,
                                        unsigned char *alternative_iv,
                                        unsigned char *ciphertext,
                                        unsigned int *ciphertext_length)
{
    unsigned int plaintext_padded_length;       /* Len of padded plaintext  */
    unsigned int padding_length;                /* Number of padding octets */
    uint32_t network_word;                      /* Word, network byte order */

    /*
     * Ensure we do not receive NULL pointers
     */
    if (!key || !plaintext || !ciphertext || !ciphertext_length)
    {
        debug_print(mod_srtp,
                    "key wrap with padding pointers to buffers invalid",
                    NULL);
        return srtp_err_status_bad_param;
    }

    /*
     * Check to ensure that the plaintext lenth is properly bounded
     */
    if (!(plaintext_length) ||
        (plaintext_length > AES_Key_Wrap_with_Padding_Max))
    {
        debug_print(mod_srtp,
                    "key wrap with padding plaintext length invalid",
                    NULL);
        return srtp_err_status_bad_param;
    }

    /*
     * Store the initialization vector as the first 4 octets of the ciphertext
     */
    if (alternative_iv)
    {
        memcpy(ciphertext, alternative_iv, 4);
    }
    else
    {
        memcpy(ciphertext, Alternative_IV, 4);
    }

    /*
     * Store the original message length in network byte order as the
     * second 4 octets of the buffer
     */
    network_word = htonl(plaintext_length);
    memcpy(ciphertext+4, &network_word, 4);

    /*
     * Copy the plaintext into the ciphertext buffer for encryption
     */
    memcpy(ciphertext+8, plaintext, plaintext_length);

    /*
     * Now pad the buffer to be an even 8 octets and compute the length
     * of the padded buffer.  (Note: "& 0x07" == "% 8")
     */
    if (plaintext_length & 0x07)
    {
        padding_length = 8 - (plaintext_length & 0x07);

        /*
         * Pad with padding_length zeros
         */
        memset(ciphertext + plaintext_length + 8, 0, padding_length);
    }
    else
    {
        padding_length = 0;
    }
    plaintext_padded_length = plaintext_length + padding_length;

    /*
     * Now encrypt the plaintext
     */
    if (plaintext_padded_length == 8)
    {
        /*
         * Encrypt using AES ECB mode
         */
        if (srtp_ekt_aes_ecb_encrypt(   key,
                                        key_length,
                                        ciphertext,
                                        16,
                                        ciphertext))
        {
            debug_print(mod_srtp,
                        "key wrap with padding failed to encrypt plaintext",
                        NULL);
            return srtp_err_status_cipher_fail;
        }

        /*
         * Set the ciphertext length
         */
        *ciphertext_length = 16;
    }
    else
    {
        /*
         * Encrypt using AES Key Wrap
         */
        if (srtp_ekt_aes_key_wrap(  key,
                                    key_length,
                                    ciphertext + 8,
                                    plaintext_padded_length,
                                    ciphertext,
                                    ciphertext,
                                    ciphertext_length))
        {
            debug_print(mod_srtp,
                        "key wrap with padding failed to wrap",
                        NULL);
            return srtp_err_status_cipher_fail;
        }
    }

    return srtp_err_status_ok;
}

/*
 *  srtp_ekt_aes_key_unwrap_with_padding
 *
 *  Description:
 *      This fuction performs the AES Key Unwrap with Padding as specified in
 *      RFC 5649.
 *
 *  Parameters:
 *      key [in]
 *          A pointer to the key encryption key (KEK).
 *      key_length [in]
 *          The length in bits of the KEK.  Valid values are 128, 192,
 *          and 256.
 *      ciphertext [in]
 *          A pointer to the ciphertext to decrypt.
 *      ciphertext_length [in]
 *          This is a the length of the ciphertext.
 *      alternative_iv [in]
 *          This is an alternative_iv vector to use.  The default value
 *          is specified in RFC 5649, but a different value may be provided.
 *          A NULL value will cause the function to use the default IV.
 *      plaintext [out]
 *          A pointer to a buffer to hold the decrypted ciphertext.  This
 *          function does not allocate memory and expects the caller to pass
 *          a pointer to a block of memory large enough to hold the output.
 *      plaintext_length [out]
 *          This is a the length of the resulting plaintext.
 *
 *  Returns:
 *      srtp_err_status_ok (0) if successful, non-zero if there was an error.
 *      The error code will be one defined by srtp_err_status_t.
 *
 *  Comments:
 *      The decryption routines expected to decrypt "in place", which AES
 *      will do.  Thus, the plaintext and ciphertext pointers are the same
 *      when attempting to encrypt data in some parts of this code.  However,
 *      callers of this function should use different pointers to memory
 *      for the ciphertext and plaintext.
 *
 */
int srtp_ekt_aes_key_unwrap_with_padding(   const unsigned char *key,
                                            unsigned int key_length,
                                            const unsigned char *ciphertext,
                                            unsigned int ciphertext_length,
                                            unsigned char *alternative_iv,
                                            unsigned char *plaintext,
                                            unsigned int *plaintext_length)
{
    unsigned char integrity_data[8];            /* Integrity data           */
    uint32_t network_word;                      /* Word, network byte order */
    unsigned int message_length_indicator;      /* MLI value                */
    unsigned char *p, *q;                       /* Pointers                 */
    unsigned char plaintext_buffer[16];         /* Plaintext for one block  */

    /*
     * Ensure we do not receive NULL pointers
     */
    if (!key || !ciphertext || !plaintext || !plaintext_length)
    {
        debug_print(mod_srtp,
                    "key unwrap with padding pointers to buffers invalid",
                    NULL);
        return srtp_err_status_bad_param;
    }

    /*
     * Check to ensure that the ciphertext length is proper, though no
     * length check is performed.  (Note: "& 0x07" == "% 8")
     */
    if ((ciphertext_length & 0x07) || !ciphertext_length)
    {
        debug_print(mod_srtp,
                    "key unwrap with padding ciphertext length invalid",
                    NULL);
        return srtp_err_status_bad_param;
    }

    /*
     * Decrypt the ciphertext
     */
    if (ciphertext_length == 16)
    {
        /*
         * Decrypt using AES ECB mode
         */
        if (srtp_ekt_aes_ecb_decrypt(   key,
                                        key_length,
                                        ciphertext,
                                        16,
                                        plaintext_buffer))
        {
            debug_print(mod_srtp,
                        "key unwrap with padding failed to decrypt ciphertext",
                        NULL);
            return srtp_err_status_cipher_fail;
        }

        /*
         * Copy the integrity array
         */
        memcpy(integrity_data, plaintext_buffer, 8);

        /*
         * Copy the plaintext into the output buffer
         */
        memcpy(plaintext, plaintext_buffer+8, 8);

        /*
         * Set the plaintext_length to 8
         */
        *plaintext_length = 8;
    }
    else
    {
        /*
         * Decrypt using AES Key Wrap
         */
        if (srtp_ekt_aes_key_unwrap(key,
                                    key_length,
                                    ciphertext,
                                    ciphertext_length,
                                    NULL,
                                    plaintext,
                                    plaintext_length,
                                    integrity_data))
        {
            debug_print(mod_srtp,
                        "key unwrap with padding failed to unwrap",
                        NULL);
            return srtp_err_status_cipher_fail;
        }
    }

    /*
     * Verify that the first 4 octets of the integrity data are correct
     */
    if (alternative_iv)
    {
        if (memcmp(alternative_iv, integrity_data, 4))
        {
            debug_print(mod_srtp,
                        "key unwrap with padding integrity check failed",
                        NULL);
            return srtp_err_status_cipher_fail;
        }
    }
    else
    {
        if (memcmp(Alternative_IV, integrity_data, 4))
        {
            debug_print(mod_srtp,
                        "key unwrap with padding integrity check failed",
                        NULL);
            return srtp_err_status_cipher_fail;
        }
    }
    
    /*
     * Determine the original message length and sanity check
     */
    memcpy(&network_word, integrity_data+4, 4);
    message_length_indicator = ntohl(network_word);
    if ((message_length_indicator > *plaintext_length) ||
        ((*plaintext_length > 8) &&
         (message_length_indicator < (*plaintext_length)-7)))
    {
        debug_print(mod_srtp,
                    "key unwrap with padding plaintex message length invalid",
                    NULL);
        return srtp_err_status_cipher_fail;
    }

    /*
     * Ensure that all padding bits are zero
     */
    p = plaintext + message_length_indicator;
    q = plaintext + *plaintext_length;
    while(p<q)
    {
        if (*p++)
        {
            debug_print(mod_srtp,
                        "key unwrap with padding zero octets not zero",
                        NULL);
            return srtp_err_status_cipher_fail;
        }
    }

    *plaintext_length = message_length_indicator;

    return srtp_err_status_ok;
}
