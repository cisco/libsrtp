/*
 *  ekt_tag_key_wrap_test
 *
 *  Copyright (C) 2015
 *  Cisco Systems, Inc.
 *  All Rights Reserved.
 *
 *  Author:
 *      Paul E. Jones
 *
 *  Description:
 *      This module will exercise the AES Key Wrap (RFC 3394) and
 *      AES Key Wrap with Padding (RFC 5649) logic in the ekt_tag_utils.c
 *      module.
 *
 *  Portability Issues:
 *      None.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "srtp.h"                               /* For common status codes  */
#include "srtp_priv.h"                          /* For OPENSSL define       */
#include "ekt_tag_utils.h"

/*
 *  exercise_key_and_plaintext_lengths
 *
 *  Description:
 *      This routine will exercise various key lengths and plaintext lengths
 *      to ensure that calls to srtp_ekt_plaintext_encrypt() and
 *      srtp_ciphertext_tag_decrypt() will consistently produce ciphertext
 *      that, when decrypted, matches the original plaintext.
 *      Note that the way the key and text is constructed, a key of 192
 *      bits and 20 octets aligns with the first published example
 *      in RFC 5649.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      Zero if successful, non-zero otherwise.
 *
 *  Comments:
 *      None.
 *
 */
int exercise_key_and_plaintext_lengths()
{
    unsigned char key[] =
    {
        0x58, 0x40, 0xDF, 0x6E, 0x29, 0xB0, 0x2A, 0xF1,
        0xAB, 0x49, 0x3B, 0x70, 0x5B, 0xF1, 0x6E, 0xA1,
        0xAE, 0x83, 0x38, 0xF4, 0xDC, 0xC1, 0x76, 0xA8,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
    };
    unsigned char plaintext[] =
    {
        0xC3, 0x7B, 0x7E, 0x64, 0x92, 0x58, 0x43, 0x40,
        0xBE, 0xD1, 0x22, 0x07, 0x80, 0x89, 0x41, 0x15,
        0x50, 0x68, 0xF7, 0x38, 0xAB, 0xFE, 0x01, 0xAE,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        0xC1, 0x75, 0x79, 0x6D, 0xA3, 0x19, 0x54, 0x51,
        0xB2, 0xD6, 0x2A, 0x0E, 0x91, 0x0E, 0x52, 0x06,
        0x53, 0x67, 0xFB, 0x19, 0xBC, 0xF1, 0x11, 0xBF,
        0x04, 0x08, 0x0C, 0x1A, 0x0A, 0x1B, 0x1C, 0x1D
    };
    /*
     * The following should be the ciphertext when the key
     * is 128 bits and original plaintext is 1 octet given
     * the above key and plaintext data
     */
    unsigned char known_ciphertext_1_128[] =
    {
        0x78, 0x6F, 0xC2, 0x71, 0xB0, 0xFC, 0x49, 0xE7,
        0x43, 0xD8, 0xB7, 0xC9, 0xB3, 0x0E, 0x3B, 0x31
    };
    /*
     * The following should be the ciphertext when the key
     * is 128 bits and original plaintext is 23 octets given
     * the above key and plaintext data
     */
    unsigned char known_ciphertext_23_128[] =
    {
        0x3E, 0x51, 0x0E, 0x29, 0xF7, 0xE2, 0x93, 0x9A,
        0xEF, 0x93, 0x48, 0xD3, 0x3E, 0xA8, 0x1D, 0xD9,
        0xAC, 0xDE, 0x61, 0x4B, 0xDC, 0x10, 0xC4, 0x42,
        0x49, 0xB9, 0x10, 0x57, 0xCE, 0x67, 0x75, 0xDC
    };
    /*
     * The following should be the ciphertext when the key
     * is 192 bits and original plaintext is 20 octets given
     * the above key and plaintext data
     */
    unsigned char known_ciphertext_20_192[] =
    {
        0x13, 0x8B, 0xDE, 0xAA, 0x9B, 0x8F, 0xA7, 0xFC,
        0x61, 0xF9, 0x77, 0x42, 0xE7, 0x22, 0x48, 0xEE,
        0x5A, 0xE6, 0xAE, 0x53, 0x60, 0xD1, 0xAE, 0x6A,
        0x5F, 0x54, 0xF3, 0x73, 0xFA, 0x54, 0x3B, 0x6A
    };
    /*
     * The following should be the ciphertext when the key
     * is 256 bits and original plaintext is 60 octets given
     * the above key and plaintext data
     */
    unsigned char known_ciphertext_60_256[] =
    {
        0xAD, 0x90, 0xFA, 0x8C, 0x73, 0x0B, 0x47, 0x8B,
        0x2B, 0x34, 0x53, 0x76, 0xA3, 0xB3, 0x1A, 0x32,
        0x3A, 0xC7, 0xD3, 0xC1, 0xD1, 0x93, 0xBD, 0xAF,
        0xDC, 0x41, 0x0D, 0xBC, 0x17, 0xFD, 0xDC, 0xB5,
        0xEB, 0x1F, 0x30, 0x12, 0x44, 0xA4, 0x67, 0x18,
        0x21, 0x48, 0xCA, 0xC9, 0xAA, 0x03, 0xBC, 0x9A,
        0x61, 0x44, 0x1C, 0x04, 0xA2, 0x8F, 0xD1, 0x7C,
        0xBE, 0xDD, 0x72, 0x04, 0x8A, 0xF8, 0xE1, 0x7F,
        0x2C, 0x30, 0x40, 0xA4, 0xB0, 0x7C, 0x1D, 0x7A
    };
    unsigned int key_lengths[] =
    {
        128,
#ifdef OPENSSL
        192,
#endif
        256
    };
    unsigned int text_lengths[] =
    {
        1, 5, 8, 9, 15, 16, 20, 23, 24, 25, 32, 45, 48, 51, 60, 64
    };
    unsigned int key_length, text_length, k_i, t_i;
    unsigned char ekt_ciphertext[1024];
    unsigned int ekt_ciphertext_length;
    unsigned char ekt_plaintext[1024];
    unsigned int ekt_plaintext_length;
    unsigned int expected_length;
    unsigned int known_ciphertext_length;
    int i;
    unsigned char *p1, *p2;

    printf ("Entering exercise_key_and_plaintext_lengths()\n");

    /*
     * Test various key lengths and text lengths
     */
    for (k_i = 0; k_i < sizeof(key_lengths)/sizeof(int); k_i++)
    {
        key_length = key_lengths[k_i];
        printf ("\nStarting key length %d:\n", key_length);
        for (t_i = 0; t_i < sizeof(text_lengths)/sizeof(int); t_i++)
        {
            text_length = text_lengths[t_i];

            /*
             * Zero out memory
             */
            memset(ekt_plaintext, 0, sizeof(ekt_plaintext));
            memset(ekt_ciphertext, 0, sizeof(ekt_ciphertext));

            /************************************************
             * ENCRYPT
             ***********************************************/

            printf ("Encrypting using srtp_ekt_plaintext_encrypt\n");

            if (srtp_ekt_plaintext_encrypt( key,
                                            key_length,
                                            plaintext,
                                            text_length,
                                            0, /* ROC */
                                            ekt_ciphertext,
                                            &ekt_ciphertext_length))
            {
                printf ("Error: srtp_ekt_plaintext_encrypt failed\n");
                return (-1);
            }
            printf("Text lengths: %u/%u\n", text_length, ekt_ciphertext_length);
            expected_length = text_length / 8;
            if (text_length % 8)
            {
                expected_length++;
            }
            if (expected_length < 2)
            {
                expected_length = 16;
            }
            else
            {
                expected_length = expected_length * 8 + 8;
            }
            if (expected_length != ekt_ciphertext_length)
            {
                printf ("Unexpected length: %u %u\n",
                        expected_length,
                        ekt_ciphertext_length);
                return (-1);
            }

            /************************************************
             * CHECK AGAINST KNOWN CIPHERTEXT
             ***********************************************/

            /*
             * Check against known ciphertext arrays
             */
            if ((key_length == 128) && (text_length == 1))
            {
                known_ciphertext_length = sizeof(known_ciphertext_1_128);
                p1 = known_ciphertext_1_128;
            }
            else if ((key_length == 128) && (text_length == 23))
            {
                known_ciphertext_length = sizeof(known_ciphertext_23_128);
                p1 = known_ciphertext_23_128;
            }
            else if ((key_length == 192) && (text_length == 20))
            {
                known_ciphertext_length = sizeof(known_ciphertext_20_192);
                p1 = known_ciphertext_20_192;
            }
            else if ((key_length == 256) && (text_length == 60))
            {
                known_ciphertext_length = sizeof(known_ciphertext_60_256);
                p1 = known_ciphertext_60_256;
            }
            else
            {
                known_ciphertext_length = 0;
            }

            if (known_ciphertext_length)
            {
                printf ("Checking known ciphertext with plaintext "
                        "length %i using %i bit key\n",
                        text_length,
                        key_length);

                if (ekt_ciphertext_length != known_ciphertext_length)
                {
                    printf ("Error: ciphertext length %i does not match "
                            "expected length %i\n",
                            ekt_ciphertext_length,
                            known_ciphertext_length);
                    return (-1);
                }
                else
                {
                    printf ("Encrypted lengths match\n");
                }

                for (i = 0, p2 = ekt_ciphertext;
                     i < ekt_ciphertext_length;
                     i++)
                {
                    if (*(p1++) != *(p2++))
                    {
                        printf ("Error: ciphertext does not match expected\n");
                        return (-1);
                    }
                }

                printf("Known ciphertext matches\n");
            }

            /************************************************
             * DECRYPT
             ***********************************************/

            printf ("Decrypting using srtp_ekt_ciphertext_decrypt\n");

            if (srtp_ekt_ciphertext_decrypt(key,
                                            key_length,
                                            ekt_ciphertext,
                                            ekt_ciphertext_length,
                                            0, /* ROC */
                                            ekt_plaintext,
                                            &ekt_plaintext_length))
            {
                printf ("Error: srtp_ekt_ciphertext_decrypt failed\n");
                return (-1);
            }

            /************************************************
             * CHECK DECRYPTION RESULT
             ***********************************************/

            printf ("Checking srtp_ekt_ciphertext_decrypt\n");

            if (ekt_plaintext_length != text_length)
            {
                printf ("Error: Plaintext length %i does not match "
                        "expected length %i\n",
                        ekt_plaintext_length,
                        text_length);
                return (-1);
            }
            else
            {
                printf ("Decrypted lengths match\n");
            }

            for (i = 0, p1 = ekt_plaintext, p2 = plaintext;
                 i < ekt_plaintext_length;
                 i++)
            {
                if (*(p1++) != *(p2++))
                {
                    printf ("Error: plaintext does not match expected\n");
                    return (-1);
                }
            }

            printf ("Encrypted / Decrypted strings match expected values\n");
        }
    }

    printf ("Exiting exercise_key_and_plaintext_lengths()\n");

    return (0);
}

/*
 * Entry point for tests
 */
int main()
{
    srtp_err_status_t stat;

#if 0
    /*
     * enable debugs
     */
    stat = srtp_set_debug_module("crypto", 1);
    if (stat) {
        printf("error: set debug module failed\n");
        exit(1);
    }
#endif

    /* initialize srtp library */
    stat = srtp_init();
    if (stat) {
        printf ("error: srtp initialization failed with error code %d\n", stat);
        exit(1);
    }

    /*
     * Run a number of different tests with various key and plaintext lengths
     */
    if (exercise_key_and_plaintext_lengths())
    {
        printf("There was a problem!\n");
        exit(1);
    }

    printf("All good!\n");

    return (0);
}

