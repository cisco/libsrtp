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
#include "srtp.h"
#include "ekt_tag_utils.h"

#if 0
/*  
 *  aeskw_test
 *
 *  Description:
 *      Test AES Key Wrap test routine
 *
 *  Parameters:
 *      key
 *          The encryption key
 *      key_length
 *          The length of the encryption key in bits
 *      plaintext
 *          The plaintext to encrypt
 *      plaintext_length
 *          The length of the plaintext
 *      expected_ciphertext
 *          The expected ciphertext
 *      expected_ciphertext_length
 *          The expected ciphertext length
 *
 *  Returns:
 *      Zero if successful, non-zero otherwise.
 *
 *  Comments:
 *      None.
 *
 */
int aeskw_test( const unsigned char *key,
                unsigned int key_length,
                const unsigned char *plaintext,
                unsigned int plaintext_length,
                const unsigned char *expected_ciphertext,
                unsigned int expected_ciphertext_length)
{
    unsigned char ciphertext[1024];
    unsigned char plaintext_check[1024];
    unsigned int ciphertext_length;
    unsigned int plaintext_check_length;
    int i;
    const unsigned char *p1, *p2;

    /************************************************
     * ENCRYPT 
     ************************************************/

    printf("Encrypting using srtp_ekt_aes_key_wrap\n");

    if (srtp_ekt_aes_key_wrap(  key,
                                key_length,
                                plaintext,
                                plaintext_length,
                                NULL,
                                ciphertext,
                                &ciphertext_length))
    {
        printf("Error encrypting using srtp_ekt_aes_key_wrap\n");
        return (-1);
    }

    /************************************************
     * CHECK AGAINST KNOWN CIPHERTEXT
     ************************************************/

    printf("Checking known ciphertext\n");

    if (ciphertext_length != expected_ciphertext_length)
    {
        printf("Error: ciphertext length (%i) does not match "
               "expected (%i)\n",
               ciphertext_length, expected_ciphertext_length);
        return (-1);
    }
    else
    {
        printf("Encrypted lengths match\n");
    }

    for(i=0, p1=ciphertext, p2=expected_ciphertext; i<ciphertext_length; i++)
    {
        if (*(p1++) != *(p2++))
        {
            printf ("Error: ciphertext does not match expected\n");
            return (-1);
        }
    }

    /************************************************
     * DECRYPT
     ************************************************/

    printf("Decrypting using srtp_ekt_aes_key_unwrap\n");

    if (srtp_ekt_aes_key_unwrap(key,
                                key_length,
                                ciphertext,
                                ciphertext_length,
                                NULL,
                                plaintext_check,
                                &plaintext_check_length,
                                NULL))
    {
        printf("Error decrypting using srtp_ekt_aes_key_unwrap\n");
        return (-1);
    }

    /************************************************
     * CHECK DECRYPTION RESULT
     ************************************************/

    printf("Checking srtp_ekt_aes_key_unwrap\n");

    if (plaintext_check_length != plaintext_length)
    {
        printf("Error: Plaintext length (%i) does not match "
               "expected (%i)\n",
               plaintext_check_length, plaintext_length);
        return (-1);
    }
    else
    {
        printf("Decrypted lengths match\n");
    }

    for(i=0, p1=plaintext, p2=plaintext_check; i<plaintext_check_length; i++)
    {
        if (*(p1++) != *(p2++))
        {
            printf ("Error: plaintext does not match expected\n");
            return (-1);
        }
    }

    return (0);
}

/*  
 *  aeskw_with_padding_test
 *
 *  Description:
 *      Test AES Key Wrap with Padding test routine
 *
 *  Parameters:
 *      key
 *          The encryption key
 *      key_length
 *          The length of the encryption key in bits
 *      plaintext
 *          The plaintext to encrypt
 *      plaintext_length
 *          The length of the plaintext
 *      expected_ciphertext
 *          The expected ciphertext
 *      expected_ciphertext_length
 *          The expected ciphertext length
 *
 *  Returns:
 *      Zero if successful, non-zero otherwise.
 *
 *  Comments:
 *      None.
 *
 */
int aeskw_with_padding_test(const unsigned char *key,
                            unsigned int key_length,
                            const unsigned char *plaintext,
                            unsigned int plaintext_length,
                            const unsigned char *expected_ciphertext,
                            unsigned int expected_ciphertext_length)
{
    unsigned char ciphertext[1024];
    unsigned char plaintext_check[1024];
    unsigned int ciphertext_length;
    unsigned int plaintext_check_length;
    int i;
    const unsigned char *p1, *p2;

    /************************************************
     * ENCRYPT 
     ************************************************/

    printf("Encrypting using srtp_ekt_aes_key_wrap_with_padding\n");

    if (srtp_ekt_aes_key_wrap_with_padding( key,
                                            key_length,
                                            plaintext,
                                            plaintext_length,
                                            NULL,
                                            ciphertext,
                                            &ciphertext_length))
    {
        printf("Error encrypting using srtp_ekt_aes_key_wrap_with_padding\n");
        return (-1);
    }

    /************************************************
     * CHECK AGAINST KNOWN CIPHERTEXT
     ************************************************/

    printf("Checking known ciphertext\n");

    if (ciphertext_length != expected_ciphertext_length)
    {
        printf("Error: ciphertext length (%i) does not match "
               "expected (%i)\n",
               ciphertext_length, expected_ciphertext_length);
        return (-1);
    }
    else
    {
        printf("Encrypted lengths match\n");
    }

    for(i=0, p1=ciphertext, p2=expected_ciphertext; i<ciphertext_length; i++)
    {
        if (*(p1++) != *(p2++))
        {
            printf ("Error: ciphertext does not match expected\n");
            return (-1);
        }
    }

    /************************************************
     * DECRYPT
     ************************************************/

    printf("Decrypting using srtp_ekt_aes_key_unwrap_with_padding\n");

    if (srtp_ekt_aes_key_unwrap_with_padding(   key,
                                                key_length,
                                                ciphertext,
                                                ciphertext_length,
                                                NULL,
                                                plaintext_check,
                                                &plaintext_check_length))
    {
        printf("Error decrypting using srtp_ekt_aes_key_unwrap_with_padding\n");
        return (-1);
    }

    /************************************************
     * CHECK DECRYPTION RESULT
     ************************************************/

    printf("Checking srtp_ekt_aes_key_unwrap_with_padding\n");

    if (plaintext_check_length != plaintext_length)
    {
        printf("Error: Plaintext length (%i) does not match "
               "expected (%i)\n",
               plaintext_check_length, plaintext_length);
        return (-1);
    }
    else
    {
        printf("Decrypted lengths match\n");
    }

    for(i=0, p1=plaintext, p2=plaintext_check; i<plaintext_check_length; i++)
    {
        if (*(p1++) != *(p2++))
        {
            printf ("Error: plaintext does not match expected\n");
            return (-1);
        }
    }

    return (0);
}

/*  
 *  rfc3394_test
 *
 *  Description:
 *      This routine will test using the test vectors published in RFC 3394
 *      by calling srtp_ekt_aes_key_wrap() and srtp_ekt_aes_key_unwrap().
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
int rfc3394_test()
{
    unsigned char key_1[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    unsigned char plaintext_1[] =
    {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };
    unsigned char ciphertext_1[] =
    {
        0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
        0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
        0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5
    };
    unsigned char key_2[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };
    unsigned char plaintext_2[] =
    {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };
    unsigned char ciphertext_2[] =
    {
        0x96, 0x77, 0x8B, 0x25, 0xAE, 0x6C, 0xA4, 0x35,
        0xF9, 0x2B, 0x5B, 0x97, 0xC0, 0x50, 0xAE, 0xD2,
        0x46, 0x8A, 0xB8, 0xA1, 0x7A, 0xD8, 0x4E, 0x5D
    };
    unsigned char key_3[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    unsigned char plaintext_3[] =
    {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };
    unsigned char ciphertext_3[] =
    {
        0x64, 0xE8, 0xC3, 0xF9, 0xCE, 0x0F, 0x5B, 0xA2,
        0x63, 0xE9, 0x77, 0x79, 0x05, 0x81, 0x8A, 0x2A,
        0x93, 0xC8, 0x19, 0x1E, 0x7D, 0x6E, 0x8A, 0xE7
    };
    unsigned char key_4[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };
    unsigned char plaintext_4[] =
    {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    unsigned char ciphertext_4[] =
    {
        0x03, 0x1D, 0x33, 0x26, 0x4E, 0x15, 0xD3, 0x32,
        0x68, 0xF2, 0x4E, 0xC2, 0x60, 0x74, 0x3E, 0xDC,
        0xE1, 0xC6, 0xC7, 0xDD, 0xEE, 0x72, 0x5A, 0x93,
        0x6B, 0xA8, 0x14, 0x91, 0x5C, 0x67, 0x62, 0xD2
    };
    unsigned char key_5[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    unsigned char plaintext_5[] =
    {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    unsigned char ciphertext_5[] =
    {
        0xA8, 0xF9, 0xBC, 0x16, 0x12, 0xC6, 0x8B, 0x3F,
        0xF6, 0xE6, 0xF4, 0xFB, 0xE3, 0x0E, 0x71, 0xE4,
        0x76, 0x9C, 0x8B, 0x80, 0xA3, 0x2C, 0xB8, 0x95,
        0x8C, 0xD5, 0xD1, 0x7D, 0x6B, 0x25, 0x4D, 0xA1
    };
    unsigned char key_6[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    unsigned char plaintext_6[] =
    {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    unsigned char ciphertext_6[] =
    {
        0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4,
        0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87, 0xF8, 0x26,
        0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26,
        0xCB, 0xC7, 0xF0, 0xE7, 0x1A, 0x99, 0xF4, 0x3B,
        0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21
    };

    printf("Entering rfc3394_test()\n");

    if (aeskw_test( key_1,
                    sizeof(key_1)*8,
                    plaintext_1,
                    sizeof(plaintext_1),
                    ciphertext_1,
                    sizeof(ciphertext_1)))
    {
        printf("Exiting rfc3394_test()\n");
        return (-1);
    }

    if (aeskw_test( key_2,
                    sizeof(key_2)*8,
                    plaintext_2,
                    sizeof(plaintext_2),
                    ciphertext_2,
                    sizeof(ciphertext_2)))
    {
        printf("Exiting rfc3394_test()\n");
        return (-1);
    }

    if (aeskw_test( key_3,
                    sizeof(key_3)*8,
                    plaintext_3,
                    sizeof(plaintext_3),
                    ciphertext_3,
                    sizeof(ciphertext_3)))
    {
        printf("Exiting rfc3394_test()\n");
        return (-1);
    }

    if (aeskw_test( key_4,
                    sizeof(key_4)*8,
                    plaintext_4,
                    sizeof(plaintext_4),
                    ciphertext_4,
                    sizeof(ciphertext_4)))
    {
        printf("Exiting rfc3394_test()\n");
        return (-1);
    }

    if (aeskw_test( key_5,
                    sizeof(key_5)*8,
                    plaintext_5,
                    sizeof(plaintext_5),
                    ciphertext_5,
                    sizeof(ciphertext_5)))
    {
        printf("Exiting rfc3394_test()\n");
        return (-1);
    }

    if (aeskw_test( key_6,
                    sizeof(key_6)*8,
                    plaintext_6,
                    sizeof(plaintext_6),
                    ciphertext_6,
                    sizeof(ciphertext_6)))
    {
        printf("Exiting rfc3394_test()\n");
        return (-1);
    }

    printf("Exiting rfc3394_test()\n");

    return 0;
}
#endif

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
        0x50, 0x68, 0xF7, 0x38, 0xab, 0xfe, 0x01, 0xae,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0xC1, 0x75, 0x79, 0x6D, 0xa3, 0x19, 0x54, 0x51,
        0xB2, 0xD6, 0x2A, 0x0E, 0x91, 0x0E, 0x52, 0x06,
        0x53, 0x67, 0xFB, 0x19, 0xBC, 0xF1, 0x11, 0xBF,
        0x04, 0x08, 0x0C, 0x1A, 0x0A, 0x1B, 0x1C, 0x1D,
    };
    /*
     * The following should be the ciphertext when the key
     * is 192 bits and original plaintext is 20 octets given
     * the above key and plaintext data
     */
    unsigned char known_ciphertext[] =
    {
        0x13, 0x8B, 0xDE, 0xAA, 0x9B, 0x8F, 0xA7, 0xFC,
        0x61, 0xF9, 0x77, 0x42, 0xE7, 0x22, 0x48, 0xEE,
        0x5A, 0xE6, 0xAE, 0x53, 0x60, 0xD1, 0xAE, 0x6A,
        0x5F, 0x54, 0xF3, 0x73, 0xFA, 0x54, 0x3B, 0x6A
    };
    unsigned int key_lengths[] =
    {
        128, 192, 256
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
    int i;
    unsigned char *p1, *p2;

    printf("Entering exercise_key_and_plaintext_lengths()\n");

    /*
     * Test various key lengths and text lengths
     */
    for(k_i = 0; k_i < sizeof(key_lengths)/sizeof(int); k_i++)
    {
        key_length = key_lengths[k_i];
        for(t_i = 0; t_i < sizeof(text_lengths)/sizeof(int); t_i++)
        {
            text_length = text_lengths[t_i];

            /*
             * Zero out memory
             */
            memset(ekt_plaintext, 0, sizeof(ekt_plaintext));
            memset(ekt_ciphertext, 0, sizeof(ekt_ciphertext));

            /************************************************
             * ENCRYPT
             ************************************************/

            printf("Encrypting using srtp_ekt_plaintext_encrypt\n");

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
                printf("Unexpected length: %u %u\n", expected_length, ekt_ciphertext_length);
                return (-1);
            }

            /************************************************
             * CHECK AGAINST KNOWN CIPHERTEXT
             ************************************************/

            /*
             * Check against the known ciphertext array where the
             * key is 192 bits and the text length is 20 octets
             */
            if ((key_length == 192) && (text_length == 20))
            {
                printf("Checking known ciphertext\n");

                if (ekt_ciphertext_length != sizeof(known_ciphertext))
                {
                    printf("Error: ciphertext length (%i) does not match "
                           "expected (%i)\n",
                           ekt_ciphertext_length,
                           (int)sizeof(known_ciphertext));
                    return (-1);
                }
                else
                {
                    printf("Encrypted lengths match\n");
                }

                for(i = 0, p1=known_ciphertext, p2=ekt_ciphertext;
                    i < ekt_ciphertext_length;
                    i++)
                {
                    if (*(p1++) != *(p2++))
                    {
                        printf ("Error: ciphertext does not match "
                                "expected (2)\n");
                        return (-1);
                    }
                }

                printf("Known ciphertext matches\n");
            }

            /************************************************
             * DECRYPT
             ************************************************/

            printf("Decrypting using srtp_ekt_ciphertext_decrypt\n");

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
             ************************************************/

            printf("Checking srtp_ekt_ciphertext_decrypt\n");

            if (ekt_plaintext_length != text_length)
            {
                printf("Error: Plaintext length (%i) does not match "
                       "expected (%i)\n",
                       ekt_plaintext_length, text_length);
                return (-1);
            }
            else
            {
                printf("Decrypted lengths match\n");
            }

            for(i = 0, p1=ekt_plaintext, p2=plaintext;
                i<ekt_plaintext_length;
                i++)
            {
                if (*(p1++) != *(p2++))
                {
                    printf ("Error: plaintext does not match expected (2)\n");
                    return (-1);
                }
            }

            printf("Encrypted / Decrypted strings match expected values\n");
        }
    }

    printf("Exiting exercise_key_and_plaintext_lengths()\n");

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
	printf("error: srtp initialization failed with error code %d\n", stat);
	exit(1);
    }

#if 0
    /*
     * Test RFC 3394 using published test vectors
     */
    if (rfc3394_test())
    {
        printf("There was a problem!\n");
        exit(1);
    }
#endif

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

