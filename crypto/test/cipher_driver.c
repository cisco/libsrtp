/*
 * cipher_driver.c
 *
 * A driver for the generic cipher type
 *
 * David A. McGrew
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

#include "getopt_s.h"
#include "cipher.h"
#include "cipher_priv.h"
#include "datatypes.h"
#include "alloc.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>

#define PRINT_DEBUG 0

void cipher_driver_test_throughput(srtp_cipher_t *c);

srtp_err_status_t cipher_driver_self_test(srtp_cipher_type_t *ct);

srtp_err_status_t cipher_driver_test_api(srtp_cipher_type_t *ct,
                                         size_t key_len,
                                         size_t tag_len);

srtp_err_status_t cipher_driver_test_multi_aes_icm_128(void);
#ifdef GCM
srtp_err_status_t cipher_driver_test_multi_aes_gcm_128(void);
#endif

/*
 * cipher_driver_test_buffering(ct) tests the cipher's output
 * buffering for correctness by checking the consistency of successive
 * calls
 */

srtp_err_status_t cipher_driver_test_buffering(srtp_cipher_t *c);

/*
 * functions for testing cipher cache thrash
 */
srtp_err_status_t cipher_driver_test_array_throughput(srtp_cipher_type_t *ct,
                                                      size_t klen,
                                                      size_t num_cipher);

void cipher_array_test_throughput(srtp_cipher_t *ca[], size_t num_cipher);

uint64_t cipher_array_bits_per_second(srtp_cipher_t *cipher_array[],
                                      size_t num_cipher,
                                      size_t octets_in_buffer,
                                      size_t num_trials);

srtp_err_status_t cipher_array_delete(srtp_cipher_t *cipher_array[],
                                      size_t num_cipher);

srtp_err_status_t cipher_array_alloc_init(srtp_cipher_t ***cipher_array,
                                          size_t num_ciphers,
                                          srtp_cipher_type_t *ctype,
                                          size_t klen);

void usage(char *prog_name)
{
    printf("usage: %s [ -t | -v | -a ]\n", prog_name);
    exit(255);
}

/*
 * null_cipher and srtp_aes_icm are the cipher meta-objects
 * defined in the files in crypto/cipher subdirectory.  these are
 * declared external so that we can use these cipher types here
 */

extern srtp_cipher_type_t srtp_null_cipher;
extern srtp_cipher_type_t srtp_aes_icm_128;
extern srtp_cipher_type_t srtp_aes_icm_256;
#ifdef GCM
extern srtp_cipher_type_t srtp_aes_icm_192;
extern srtp_cipher_type_t srtp_aes_gcm_128;
extern srtp_cipher_type_t srtp_aes_gcm_256;
#endif

int main(int argc, char *argv[])
{
    srtp_cipher_t *c = NULL;
    srtp_err_status_t status;
    /* clang-format off */
    uint8_t test_key[48] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    };
    /* clang-format on */
    int q;
    bool do_timing_test = false;
    bool do_validation = false;
    bool do_array_timing_test = false;

    /* process input arguments */
    while (1) {
        q = getopt_s(argc, argv, "tva");
        if (q == -1) {
            break;
        }
        switch (q) {
        case 't':
            do_timing_test = true;
            break;
        case 'v':
            do_validation = true;
            break;
        case 'a':
            do_array_timing_test = true;
            break;
        default:
            usage(argv[0]);
        }
    }

    printf("cipher test driver\n"
           "David A. McGrew\n"
           "Cisco Systems, Inc.\n");

    if (!do_validation && !do_timing_test && !do_array_timing_test) {
        usage(argv[0]);
    }

    /* array timing (cache thrash) test */
    if (do_array_timing_test) {
        size_t max_num_cipher = 1 << 16; /* number of ciphers in cipher_array */
        size_t num_cipher;

        for (num_cipher = 1; num_cipher < max_num_cipher; num_cipher *= 8) {
            cipher_driver_test_array_throughput(&srtp_null_cipher, 0,
                                                num_cipher);
        }

        for (num_cipher = 1; num_cipher < max_num_cipher; num_cipher *= 8) {
            cipher_driver_test_array_throughput(
                &srtp_aes_icm_128, SRTP_AES_ICM_128_KEY_LEN_WSALT, num_cipher);
        }

        for (num_cipher = 1; num_cipher < max_num_cipher; num_cipher *= 8) {
            cipher_driver_test_array_throughput(
                &srtp_aes_icm_256, SRTP_AES_ICM_256_KEY_LEN_WSALT, num_cipher);
        }

#ifdef GCM
        for (num_cipher = 1; num_cipher < max_num_cipher; num_cipher *= 8) {
            cipher_driver_test_array_throughput(
                &srtp_aes_icm_192, SRTP_AES_ICM_192_KEY_LEN_WSALT, num_cipher);
        }

        for (num_cipher = 1; num_cipher < max_num_cipher; num_cipher *= 8) {
            cipher_driver_test_array_throughput(
                &srtp_aes_gcm_128, SRTP_AES_GCM_128_KEY_LEN_WSALT, num_cipher);
        }

        for (num_cipher = 1; num_cipher < max_num_cipher; num_cipher *= 8) {
            cipher_driver_test_array_throughput(
                &srtp_aes_gcm_256, SRTP_AES_GCM_256_KEY_LEN_WSALT, num_cipher);
        }
#endif
    }

    if (do_validation) {
        cipher_driver_self_test(&srtp_null_cipher);
        cipher_driver_self_test(&srtp_aes_icm_128);
        cipher_driver_self_test(&srtp_aes_icm_256);
#ifdef GCM
        cipher_driver_self_test(&srtp_aes_icm_192);
        cipher_driver_self_test(&srtp_aes_gcm_128);
        cipher_driver_self_test(&srtp_aes_gcm_256);
#endif
        cipher_driver_test_api(&srtp_aes_icm_128,
                               SRTP_AES_ICM_128_KEY_LEN_WSALT, 0);
#ifdef GCM
        cipher_driver_test_api(&srtp_aes_gcm_128,
                               SRTP_AES_GCM_128_KEY_LEN_WSALT, 16);
#endif
        cipher_driver_test_multi_aes_icm_128();
#ifdef GCM
        cipher_driver_test_multi_aes_gcm_128();
#endif
    }

    /* do timing and/or buffer_test on srtp_null_cipher */
    status = srtp_cipher_type_alloc(&srtp_null_cipher, &c, 0, 0);
    CHECK_OK(status);

    status = srtp_cipher_init(c, NULL);
    CHECK_OK(status);

    if (do_timing_test) {
        cipher_driver_test_throughput(c);
    }
    if (do_validation) {
        status = cipher_driver_test_buffering(c);
        CHECK_OK(status);
    }
    status = srtp_cipher_dealloc(c);
    CHECK_OK(status);

    /* run the throughput test on the aes_icm cipher (128-bit key) */
    status = srtp_cipher_type_alloc(&srtp_aes_icm_128, &c,
                                    SRTP_AES_ICM_128_KEY_LEN_WSALT, 0);
    if (status) {
        fprintf(stderr, "error: can't allocate cipher\n");
        exit(status);
    }

    status = srtp_cipher_init(c, test_key);
    CHECK_OK(status);

    if (do_timing_test) {
        cipher_driver_test_throughput(c);
    }

    if (do_validation) {
        status = cipher_driver_test_buffering(c);
        CHECK_OK(status);
    }

    status = srtp_cipher_dealloc(c);
    CHECK_OK(status);

    /* repeat the tests with 256-bit keys */
    status = srtp_cipher_type_alloc(&srtp_aes_icm_256, &c,
                                    SRTP_AES_ICM_256_KEY_LEN_WSALT, 0);
    if (status) {
        fprintf(stderr, "error: can't allocate cipher\n");
        exit(status);
    }

    status = srtp_cipher_init(c, test_key);
    CHECK_OK(status);

    if (do_timing_test) {
        cipher_driver_test_throughput(c);
    }

    if (do_validation) {
        status = cipher_driver_test_buffering(c);
        CHECK_OK(status);
    }

    status = srtp_cipher_dealloc(c);
    CHECK_OK(status);

#ifdef GCM
    /* run the throughput test on the aes_gcm_128 cipher */
    status = srtp_cipher_type_alloc(&srtp_aes_gcm_128, &c,
                                    SRTP_AES_GCM_128_KEY_LEN_WSALT, 8);
    if (status) {
        fprintf(stderr, "error: can't allocate GCM 128 cipher\n");
        exit(status);
    }
    status = srtp_cipher_init(c, test_key);
    CHECK_OK(status);
    if (do_timing_test) {
        cipher_driver_test_throughput(c);
    }

    // GCM ciphers don't do buffering; they're "one shot"

    status = srtp_cipher_dealloc(c);
    CHECK_OK(status);

    /* run the throughput test on the aes_gcm_256 cipher */
    status = srtp_cipher_type_alloc(&srtp_aes_gcm_256, &c,
                                    SRTP_AES_GCM_256_KEY_LEN_WSALT, 16);
    if (status) {
        fprintf(stderr, "error: can't allocate GCM 256 cipher\n");
        exit(status);
    }
    status = srtp_cipher_init(c, test_key);
    CHECK_OK(status);
    if (do_timing_test) {
        cipher_driver_test_throughput(c);
    }

    // GCM ciphers don't do buffering; they're "one shot"

    status = srtp_cipher_dealloc(c);
    CHECK_OK(status);
#endif

    return 0;
}

void cipher_driver_test_throughput(srtp_cipher_t *c)
{
    size_t min_enc_len = 32;
    size_t max_enc_len = 2048; /* should be a power of two */
    size_t num_trials = 1000000;

    printf("timing %s throughput, key length %zu:\n", c->type->description,
           c->key_len);
    fflush(stdout);
    for (size_t i = min_enc_len; i <= max_enc_len; i = i * 2) {
        uint64_t bits_per_second =
            srtp_cipher_bits_per_second(c, i, num_trials);
        if (bits_per_second == 0) {
            printf("error: throughput test failed\n");
            exit(1);
        }
        printf("msg len: %zu\tgigabits per second: %f\n", i,
               bits_per_second / 1e9);
    }
}

srtp_err_status_t cipher_driver_self_test(srtp_cipher_type_t *ct)
{
    srtp_err_status_t status;

    printf("running cipher self-test for %s...", ct->description);
    status = srtp_cipher_type_self_test(ct);
    CHECK_OK(status);
    printf("passed\n");

    return srtp_err_status_ok;
}

void reint_cipher(srtp_cipher_t *c,
                  uint8_t *test_key,
                  uint8_t *iv,
                  srtp_cipher_direction_t direction)
{
    srtp_err_status_t status = srtp_cipher_init(c, test_key);
    CHECK_OK(status);

    status = srtp_cipher_set_iv(c, iv, direction);
    CHECK_OK(status);
}

srtp_err_status_t cipher_driver_test_api(srtp_cipher_type_t *ct,
                                         size_t key_len,
                                         size_t tag_len)
{
    srtp_err_status_t status;
    srtp_cipher_t *c = NULL;

    /* clang-format off */
    uint8_t test_key[48] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    };
    uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t plaintext[64] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    };
    uint8_t encrypted[96] = {0};
    uint8_t decrypted[96] = {0};
    /* clang-format on */

    printf("testing cipher api for %s...", ct->description);
    fflush(stdout);

    if (key_len > sizeof(test_key)) {
        return srtp_err_status_bad_param;
    }

    status = srtp_cipher_type_alloc(ct, &c, key_len, tag_len);
    CHECK_OK(status);

    status = srtp_cipher_init(c, test_key);
    CHECK_OK(status);

    status = srtp_cipher_set_iv(c, iv, srtp_direction_encrypt);
    CHECK_OK(status);

    size_t src_len;
    size_t dst_len;

    // test dst len zero
    src_len = sizeof(plaintext);
    dst_len = 0;
    status = srtp_cipher_encrypt(c, plaintext, src_len, encrypted, &dst_len);
    CHECK_RETURN(status, srtp_err_status_buffer_small);

    reint_cipher(c, test_key, iv, srtp_direction_encrypt);

    // test dst len smaller than expected
    src_len = sizeof(plaintext);
    dst_len = src_len + tag_len - 1;
    status = srtp_cipher_encrypt(c, plaintext, src_len, encrypted, &dst_len);
    CHECK_RETURN(status, srtp_err_status_buffer_small);

    reint_cipher(c, test_key, iv, srtp_direction_encrypt);

    // test dst len exact size
    src_len = sizeof(plaintext);
    dst_len = src_len + tag_len;
    status = srtp_cipher_encrypt(c, plaintext, src_len, encrypted, &dst_len);
    CHECK_OK(status);
    CHECK(dst_len == src_len + tag_len);

    reint_cipher(c, test_key, iv, srtp_direction_encrypt);

    // dst len larger than src len
    src_len = sizeof(plaintext);
    dst_len = sizeof(encrypted);
    status = srtp_cipher_encrypt(c, plaintext, src_len, encrypted, &dst_len);
    CHECK_OK(status);
    CHECK(dst_len == src_len + tag_len);

    reint_cipher(c, test_key, iv, srtp_direction_encrypt);

    size_t encrypted_len = dst_len;

    // init for decrypt
    status = srtp_cipher_init(c, test_key);
    CHECK_OK(status);

    status = srtp_cipher_set_iv(c, iv, srtp_direction_decrypt);
    CHECK_OK(status);

    if (tag_len != 0) {
        // test src less than tag len
        src_len = tag_len - 1;
        dst_len = sizeof(decrypted);
        status =
            srtp_cipher_decrypt(c, encrypted, src_len, decrypted, &dst_len);
        CHECK_RETURN(status, srtp_err_status_bad_param);

        reint_cipher(c, test_key, iv, srtp_direction_decrypt);
    }

    // test dst len zero
    src_len = encrypted_len;
    dst_len = 0;
    status = srtp_cipher_decrypt(c, encrypted, src_len, decrypted, &dst_len);
    CHECK_RETURN(status, srtp_err_status_buffer_small);

    reint_cipher(c, test_key, iv, srtp_direction_decrypt);

    // test dst len smaller than expected
    src_len = encrypted_len;
    dst_len = src_len - tag_len - 1;
    status = srtp_cipher_decrypt(c, encrypted, src_len, decrypted, &dst_len);
    CHECK_RETURN(status, srtp_err_status_buffer_small);

    reint_cipher(c, test_key, iv, srtp_direction_decrypt);

    // test dst len exact
    src_len = encrypted_len;
    dst_len = src_len - tag_len;
    status = srtp_cipher_decrypt(c, encrypted, src_len, decrypted, &dst_len);
    CHECK_OK(status);
    CHECK(dst_len == sizeof(plaintext));
    CHECK_BUFFER_EQUAL(plaintext, decrypted, sizeof(plaintext));

    reint_cipher(c, test_key, iv, srtp_direction_decrypt);

    // dst len larger than src len
    src_len = encrypted_len;
    dst_len = sizeof(decrypted);
    status = srtp_cipher_decrypt(c, encrypted, src_len, decrypted, &dst_len);
    CHECK_OK(status);
    CHECK(dst_len == sizeof(plaintext));
    CHECK_BUFFER_EQUAL(plaintext, decrypted, sizeof(plaintext));

    reint_cipher(c, test_key, iv, srtp_direction_decrypt);

    status = srtp_cipher_dealloc(c);
    CHECK_OK(status);

    printf("passed\n");

    return srtp_err_status_ok;
}

srtp_err_status_t cipher_driver_test_multi_aes_icm_128(void)
{
    /* clang-format off */
    uint8_t key[30] = {
        0xc6, 0x1e, 0x7a, 0x93, 0x74, 0x4f, 0x39, 0xee,
        0x10, 0x73, 0x4a, 0xfe, 0x3f, 0xf7, 0xa0, 0x87,
        0x30, 0xcb, 0xbc, 0x08, 0x86, 0x3d, 0x8c, 0x85,
        0xd4, 0x9d, 0xb3, 0x4a, 0x9a, 0xe1
    };
    uint8_t iv_0[16] = {
        0x00, 0x00, 0x00, 0x00, 0xca, 0xfe, 0xba, 0xbe,
        0x00, 0x00, 0x00, 0x00, 0x12, 0x35, 0x00, 0x00
    };
    uint8_t plain_text_0[] = {
        0x51, 0x00, 0x02, 0x00, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab
    };
    uint8_t cipher_text_0[] = {
        0xeb, 0x92, 0x36, 0x52, 0x51, 0xc3, 0xe0, 0x36,
        0xf8, 0xde, 0x27, 0xe9, 0xc2, 0x7e, 0xe3, 0xe0,
        0xb4, 0x65, 0x1d, 0x9f
    };
    uint8_t iv_1[16] = {
        0x00, 0x00, 0x00, 0x00, 0xca, 0xfe, 0xba, 0xbe,
        0x00, 0x00, 0x00, 0x00, 0x12, 0x36, 0x00, 0x00
    };
    uint8_t plain_text_1[] = {
        0x05, 0x02, 0x00, 0x02, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab
    };
    uint8_t cipher_text_1[] = {
        0x4e, 0xd9, 0xcc, 0x4e, 0x6a, 0x71, 0x2b, 0x30,
        0x96, 0xc5, 0xca, 0x77, 0x33, 0x9d, 0x42, 0x04,
        0xce, 0x0d, 0x77, 0x39
    };
    uint8_t iv_2[16] = {
        0x00, 0x00, 0x00, 0x00, 0xca, 0xfe, 0xba, 0xbe,
        0x00, 0x00, 0x00, 0x00, 0x12, 0x38, 0x00, 0x00
    };
    uint8_t plain_text_2[] = {
        0x00, 0x01, 0xe2, 0x40, 0x00, 0x00, 0xb2, 0x6e,
        0x51, 0x00, 0x02, 0x00, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab
    };
    uint8_t cipher_text_2[] = {
        0x8b, 0xb6, 0xe1, 0x2b, 0x5c, 0xff, 0x16, 0xdd,
        0x92, 0x83, 0x8c, 0x8c, 0x09, 0xe5, 0x83, 0x93,
        0xe1, 0xde, 0x3a, 0x9a, 0x74, 0x73, 0x4d, 0x67,
        0x45, 0x67, 0x13, 0x38
    };
    uint8_t iv_3[16] = {
        0x00, 0x00, 0x00, 0x00, 0xca, 0xfe, 0xba, 0xbe,
        0x00, 0x00, 0x00, 0x00, 0x12, 0x39, 0x00, 0x00
    };
    uint8_t plain_text_3[] = {
        0x00, 0x01, 0xe2, 0x40, 0x00, 0x00, 0xb2, 0x6e,
        0x05, 0x02, 0x00, 0x02, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab
    };
    uint8_t cipher_text_3[] = {
        0xf7, 0x0e, 0x51, 0x3e, 0xb9, 0x0b, 0x9b, 0x25,
        0xbb, 0xed, 0x48, 0x48, 0xfa, 0xa6, 0x44, 0x66,
        0x5f, 0x3d, 0x7f, 0x34, 0x12, 0x59, 0x14, 0xe9,
        0xf4, 0xd0, 0xae, 0x92
    };
    uint8_t iv_4[16] = {
        0x00, 0x00, 0x00, 0x00, 0xca, 0xfe, 0xba, 0xbe,
        0x00, 0x00, 0x00, 0x00, 0x12, 0x3a, 0x00, 0x00
    };
    uint8_t plain_text_4[] = {
        0x00, 0x01, 0xe2, 0x40, 0x00, 0x00, 0xb2, 0x6e,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab
    };
    uint8_t cipher_text_4[] = {
        0x71, 0x30, 0xb6, 0xab, 0xfe, 0x2a, 0xb0, 0xe3,
        0xe3, 0xd9, 0xf6, 0x4b, 0x25, 0xc9, 0xe7, 0x4c,
        0xb4, 0xcf, 0x8e, 0x43, 0xfb, 0x92, 0xe3, 0x78
    };
    uint8_t iv_5[16] = {
        0x00, 0x00, 0x00, 0x00, 0xca, 0xfe, 0xba, 0xbe,
        0x00, 0x00, 0x00, 0x00, 0x12, 0x3b, 0x00, 0x00
    };
    uint8_t plain_text_5[] = {
        0x00, 0x01, 0xe2, 0x40, 0x00, 0x00, 0xb2, 0x6e,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab
    };
    uint8_t cipher_text_5[] = {
        0xcb, 0xf2, 0x4c, 0x12, 0x43, 0x30, 0xe1, 0xc8,
        0x59, 0x9d, 0xd4, 0x5b, 0xc9, 0xd6, 0x87, 0xb6,
        0x03, 0xe8, 0xb5, 0x9d, 0x77, 0x1f, 0xd3, 0x8e
    };

    uint8_t *ivs[] = {
        iv_0, iv_1, iv_2, iv_3, iv_4, iv_5
    };
    uint8_t *plain_texts[] = {
        plain_text_0, plain_text_1, plain_text_2,
        plain_text_3, plain_text_4, plain_text_5
    };
    size_t plain_text_lengths[] = {
        sizeof(plain_text_0), sizeof(plain_text_1),
        sizeof(plain_text_2), sizeof(plain_text_3),
        sizeof(plain_text_4), sizeof(plain_text_5)
    };
    uint8_t *cipher_texts[] = {
        cipher_text_0, cipher_text_1, cipher_text_2,
        cipher_text_3, cipher_text_4, cipher_text_5
    };
    size_t cipher_text_lengths[] = {
        sizeof(cipher_text_0), sizeof(cipher_text_1),
        sizeof(cipher_text_2), sizeof(cipher_text_3),
        sizeof(cipher_text_4), sizeof(cipher_text_5)
    };
    size_t num_tests = sizeof(plain_texts) / sizeof(plain_texts[0]);
    /* clang-format on */

    srtp_cipher_type_t *ct = &srtp_aes_icm_128;
    srtp_cipher_t *c = NULL;

    printf("testing cipher multi for %s e[", ct->description);

    CHECK_OK(srtp_cipher_type_alloc(ct, &c, 30, 0));
    CHECK_OK(srtp_cipher_init(c, key));
    for (size_t i = 0; i < num_tests; ++i) {
        printf("%zu,", i);
        CHECK_OK(srtp_cipher_set_iv(c, ivs[i], srtp_direction_encrypt));
        uint8_t dst[1024] = { 0 };
        size_t dst_len = sizeof(dst);
        CHECK_OK(srtp_cipher_encrypt(c, plain_texts[i], plain_text_lengths[i],
                                     dst, &dst_len));
        CHECK(dst_len == cipher_text_lengths[i]);
        CHECK_BUFFER_EQUAL(cipher_texts[i], dst, dst_len);
    }
    CHECK_OK(srtp_cipher_dealloc(c));

    printf("] d[");

    CHECK_OK(srtp_cipher_type_alloc(ct, &c, 30, 0));
    CHECK_OK(srtp_cipher_init(c, key));
    for (size_t i = 0; i < num_tests; ++i) {
        printf("%zu,", i);
        CHECK_OK(srtp_cipher_set_iv(c, ivs[i], srtp_direction_decrypt));
        uint8_t dst[1024] = { 0 };
        size_t dst_len = sizeof(dst);
        CHECK_OK(srtp_cipher_decrypt(c, cipher_texts[i], cipher_text_lengths[i],
                                     dst, &dst_len));
        CHECK(dst_len == plain_text_lengths[i]);
        CHECK_BUFFER_EQUAL(plain_texts[i], dst, dst_len);
    }
    CHECK_OK(srtp_cipher_dealloc(c));

    printf("]...passed\n");

    return srtp_err_status_ok;
}

#ifdef GCM
srtp_err_status_t cipher_driver_test_multi_aes_gcm_128(void)
{
    /* clang-format off */
    uint8_t key[16] = {
        0x07, 0x7c, 0x61, 0x43, 0xcb, 0x22, 0x1b, 0xc3,
        0x55, 0xff, 0x23, 0xd5, 0xf9, 0x84, 0xa1, 0x6e
    };
    uint8_t iv_0[16] = {
        0x9a, 0xf3, 0x23, 0xad, 0xde, 0x55, 0xac, 0x9c,
        0x99, 0xc5, 0xb5, 0xf1
    };
    uint8_t aad_0[] = {
        0x90, 0x0f, 0x12, 0x35, 0xde, 0xca, 0xfb, 0xad,
        0xca, 0xfe, 0xba, 0xbe, 0xc0, 0xde, 0x00, 0x01
    };
    uint8_t plain_text_0[] = {
        0x51, 0x00, 0x02, 0x00, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab
    };
    uint8_t cipher_text_0[] = {
        0x39, 0x97, 0x2d, 0xc9, 0x57, 0x2c, 0x4d, 0x99,
        0xe8, 0xfc, 0x35, 0x5d, 0xe7, 0x43, 0xfb, 0x2e,
        0x94, 0xf9, 0xd8, 0xff, 0x54, 0xe7, 0x2f, 0x41,
        0x93, 0xbb, 0xc5, 0xc7, 0x4f, 0xfa, 0xb0, 0xfa,
        0x9f, 0xa0, 0xfb, 0xeb
    };
    uint8_t iv_1[16] = {
        0x9a, 0xf3, 0x23, 0xad, 0xde, 0x55, 0xac, 0x9c,
        0x99, 0xc5, 0xb5, 0xf2
    };
    uint8_t aad_1[] = {
        0x90, 0x0f, 0x12, 0x36, 0xde, 0xca, 0xfb, 0xad,
        0xca, 0xfe, 0xba, 0xbe, 0xc2, 0xde, 0x00, 0x01
    };
    uint8_t plain_text_1[] = {
        0x05, 0x02, 0x00, 0x02, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab
    };
    uint8_t cipher_text_1[] = {
        0xbb, 0x75, 0xa4, 0xc5, 0x45, 0xcd, 0x1f, 0x41,
        0x3b, 0xdb, 0x7d, 0xaa, 0x2b, 0x1e, 0x32, 0x63,
        0xde, 0x31, 0x36, 0x67, 0xc9, 0x63, 0x24, 0x90,
        0x81, 0xb3, 0x5a, 0x65, 0xf5, 0xcb, 0x6c, 0x88,
        0xb3, 0x94, 0x23, 0x5f
    };
    uint8_t iv_2[16] = {
        0x9a, 0xf3, 0x23, 0xad, 0xde, 0x55, 0xac, 0x9c,
        0x99, 0xc5, 0xb5, 0xfc
    };
    uint8_t aad_2[] = {
        0x92, 0x0f, 0x12, 0x38, 0xde, 0xca, 0xfb, 0xad,
        0xca, 0xfe, 0xba, 0xbe, 0xc0, 0xde, 0x00, 0x01
    };
    uint8_t plain_text_2[] = {
        0x00, 0x01, 0xe2, 0x40, 0x00, 0x00, 0xb2, 0x6e,
        0x51, 0x00, 0x02, 0x00, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab
    };
    uint8_t cipher_text_2[] = {
        0x63, 0xbb, 0xcc, 0xc4, 0xa7, 0xf6, 0x95, 0xc4,
        0x8a, 0xd7, 0xc7, 0x1f, 0xac, 0x70, 0xa8, 0x0c,
        0x92, 0x86, 0x6b, 0x4c, 0x6b, 0xa9, 0x85, 0x46,
        0xef, 0x91, 0x35, 0x86, 0xe9, 0x5f, 0xfa, 0xaf,
        0xfe, 0x95, 0x68, 0x85, 0xbb, 0x06, 0x47, 0xa8,
        0xbc, 0x09, 0x4a, 0xc8
    };
    uint8_t iv_3[16] = {
        0x9a, 0xf3, 0x23, 0xad, 0xde, 0x55, 0xac, 0x9c,
        0x99, 0xc5, 0xb5, 0xfd
    };
    uint8_t aad_3[] = {
        0x92, 0x0f, 0x12, 0x39, 0xde, 0xca, 0xfb, 0xad,
        0xca, 0xfe, 0xba, 0xbe, 0xc2, 0xde, 0x00, 0x01
    };
    uint8_t plain_text_3[] = {
        0x00, 0x01, 0xe2, 0x40, 0x00, 0x00, 0xb2, 0x6e,
        0x05, 0x02, 0x00, 0x02, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab
    };
    uint8_t cipher_text_3[] = {
        0x36, 0x80, 0x52, 0x4f, 0x8d, 0x31, 0x2b, 0x00,
        0xc7, 0x8d, 0x12, 0x00, 0x38, 0x42, 0x2b, 0xc1,
        0x11, 0xa7, 0x18, 0x7a, 0x18, 0x24, 0x6f, 0x98,
        0x0c, 0x05, 0x9c, 0xc6, 0xbc, 0x9d, 0xf8, 0xb6,
        0x26, 0x39, 0x4e, 0xca, 0x34, 0x4e, 0x4b, 0x05,
        0xd8, 0x0f, 0xea, 0x83
    };
    uint8_t iv_4[16] = {
        0x9a, 0xf3, 0x23, 0xad, 0xde, 0x55, 0xac, 0x9c,
        0x99, 0xc5, 0xb5, 0xfe
    };
    uint8_t aad_4[] = {
        0x92, 0x0f, 0x12, 0x3a, 0xde, 0xca, 0xfb, 0xad,
        0xca, 0xfe, 0xba, 0xbe, 0xc0, 0xde, 0x00, 0x00
    };
    uint8_t plain_text_4[] = {
        0x00, 0x01, 0xe2, 0x40, 0x00, 0x00, 0xb2, 0x6e,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab
    };
    uint8_t cipher_text_4[] = {
        0x15, 0xb6, 0xbb, 0x43, 0x37, 0x90, 0x6f, 0xff,
        0xb7, 0xb9, 0x64, 0x53, 0x7a, 0x2b, 0x03, 0xab,
        0x7b, 0xa5, 0x38, 0x9c, 0xe9, 0x33, 0x17, 0x12,
        0x6b, 0x5d, 0x97, 0x4d, 0xf3, 0x0c, 0x68, 0x84,
        0xdc, 0xb6, 0x51, 0xc5, 0xe1, 0x20, 0xc1, 0xda
    };
    uint8_t iv_5[16] = {
        0x9a, 0xf3, 0x23, 0xad, 0xde, 0x55, 0xac, 0x9c,
        0x99, 0xc5, 0xb5, 0xff
    };
    uint8_t aad_5[] = {
        0x92, 0x0f, 0x12, 0x3b, 0xde, 0xca, 0xfb, 0xad,
        0xca, 0xfe, 0xba, 0xbe, 0xc2, 0xde, 0x00, 0x00
    };
    uint8_t plain_text_5[] = {
        0x00, 0x01, 0xe2, 0x40, 0x00, 0x00, 0xb2, 0x6e,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab
    };
    uint8_t cipher_text_5[] = {
        0xdc, 0xb3, 0x8c, 0x9e, 0x48, 0xbf, 0x95, 0xf4,
        0x61, 0xee, 0x43, 0x2c, 0xf9, 0x20, 0x31, 0x70,
        0x76, 0x61, 0x32, 0x58, 0xd3, 0xce, 0x42, 0x36,
        0xc0, 0x6a, 0xc4, 0x29, 0x68, 0x1a, 0xd0, 0x84,
        0x13, 0x51, 0x2d, 0xc9, 0x8b, 0x52, 0x07, 0xd8
    };

    uint8_t *ivs[] = {
        iv_0, iv_1, iv_2, iv_3, iv_4, iv_5
    };
    uint8_t *aads[] = {
        aad_0, aad_1, aad_2, aad_3, aad_4, aad_5
    };
    size_t aad_lengths[] = {
        sizeof(aad_0), sizeof(aad_1),
        sizeof(aad_2), sizeof(aad_3),
        sizeof(aad_4), sizeof(aad_5)
    };
    uint8_t *plain_texts[] = {
        plain_text_0, plain_text_1, plain_text_2,
        plain_text_3, plain_text_4, plain_text_5
    };
    size_t plain_text_lengths[] = {
        sizeof(plain_text_0), sizeof(plain_text_1),
        sizeof(plain_text_2), sizeof(plain_text_3),
        sizeof(plain_text_4), sizeof(plain_text_5)
    };
    uint8_t *cipher_texts[] = {
        cipher_text_0, cipher_text_1, cipher_text_2,
        cipher_text_3, cipher_text_4, cipher_text_5
    };
    size_t cipher_text_lengths[] = {
        sizeof(cipher_text_0), sizeof(cipher_text_1),
        sizeof(cipher_text_2), sizeof(cipher_text_3),
        sizeof(cipher_text_4), sizeof(cipher_text_5)
    };
    size_t num_tests = sizeof(plain_texts) / sizeof(plain_texts[0]);
    /* clang-format on */

    srtp_cipher_type_t *ct = &srtp_aes_gcm_128;
    srtp_cipher_t *c = NULL;

    printf("testing cipher multi for %s e[", ct->description);

    CHECK_OK(srtp_cipher_type_alloc(ct, &c, 28, 16));
    CHECK_OK(srtp_cipher_init(c, key));
    for (size_t i = 0; i < num_tests; ++i) {
        printf("%zu,", i);
        CHECK_OK(srtp_cipher_set_iv(c, ivs[i], srtp_direction_encrypt));
        CHECK_OK(srtp_cipher_set_aad(c, aads[i], aad_lengths[i]));
        uint8_t dst[1024] = { 0 };
        size_t dst_len = sizeof(dst);
        CHECK_OK(srtp_cipher_encrypt(c, plain_texts[i], plain_text_lengths[i],
                                     dst, &dst_len));
        CHECK(dst_len == cipher_text_lengths[i]);
        CHECK_BUFFER_EQUAL(cipher_texts[i], dst, dst_len);
    }
    CHECK_OK(srtp_cipher_dealloc(c));

    printf("] d[");

    CHECK_OK(srtp_cipher_type_alloc(ct, &c, 28, 16));
    CHECK_OK(srtp_cipher_init(c, key));
    for (size_t i = 0; i < num_tests; ++i) {
        printf("%zu,", i);
        CHECK_OK(srtp_cipher_set_iv(c, ivs[i], srtp_direction_decrypt));
        CHECK_OK(srtp_cipher_set_aad(c, aads[i], aad_lengths[i]));
        uint8_t dst[1024] = { 0 };
        size_t dst_len = sizeof(dst);
        CHECK_OK(srtp_cipher_decrypt(c, cipher_texts[i], cipher_text_lengths[i],
                                     dst, &dst_len));
        CHECK(dst_len == plain_text_lengths[i]);
        CHECK_BUFFER_EQUAL(plain_texts[i], dst, dst_len);
    }
    CHECK_OK(srtp_cipher_dealloc(c));

    printf("]...passed\n");

    return srtp_err_status_ok;
}
#endif

/*
 * cipher_driver_test_buffering(ct) tests the cipher's output
 * buffering for correctness by checking the consistency of successive
 * calls
 */

#define INITIAL_BUFLEN 1024
srtp_err_status_t cipher_driver_test_buffering(srtp_cipher_t *c)
{
    size_t num_trials = 1000;
    size_t len, buflen = INITIAL_BUFLEN;
    uint8_t buffer0[INITIAL_BUFLEN], buffer1[INITIAL_BUFLEN], *current, *end;
    uint8_t idx[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34 };
    srtp_err_status_t status;

    printf("testing output buffering for cipher %s...", c->type->description);

    for (size_t i = 0; i < num_trials; i++) {
        /* set buffers to zero */
        for (size_t j = 0; j < buflen; j++) {
            buffer0[j] = buffer1[j] = 0;
        }

        /* initialize cipher  */
        status = srtp_cipher_set_iv(c, idx, srtp_direction_encrypt);
        if (status) {
            return status;
        }

        /* generate 'reference' value by encrypting all at once */
        status = srtp_cipher_encrypt(c, buffer0, buflen, buffer0, &buflen);
        if (status) {
            return status;
        }

        /* re-initialize cipher */
        status = srtp_cipher_set_iv(c, idx, srtp_direction_encrypt);
        if (status) {
            return status;
        }

        /* now loop over short lengths until buffer1 is encrypted */
        current = buffer1;
        end = buffer1 + buflen;
        while (current < end) {
            /* choose a short length */
            len = srtp_cipher_rand_u32_for_tests() & 0x01f;

            /* make sure that len doesn't cause us to overreach the buffer */
            if (current + len > end) {
                len = end - current;
            }

            status = srtp_cipher_encrypt(c, current, len, current, &len);
            if (status) {
                return status;
            }

            /* advance pointer into buffer1 to reflect encryption */
            current += len;

            /* if buffer1 is all encrypted, break out of loop */
            if (current == end) {
                break;
            }
        }

        /* compare buffers */
        CHECK_BUFFER_EQUAL(buffer0, buffer1, buflen);
    }

    printf("passed\n");

    return srtp_err_status_ok;
}

/*
 * The function cipher_test_throughput_array() tests the effect of CPU
 * cache thrash on cipher throughput.
 *
 * cipher_array_alloc_init(ctype, array, num_ciphers) creates an array
 * of srtp_cipher_t of type ctype
 */

srtp_err_status_t cipher_array_alloc_init(srtp_cipher_t ***ca,
                                          size_t num_ciphers,
                                          srtp_cipher_type_t *ctype,
                                          size_t klen)
{
    srtp_err_status_t status;
    uint8_t *key = NULL;
    srtp_cipher_t **cipher_array;
    /* pad klen allocation, to handle aes_icm reading 16 bytes for the
       14-byte salt */
    size_t klen_pad = ((klen + 15) >> 4) << 4;

    /* allocate array of pointers to ciphers */
    cipher_array = (srtp_cipher_t **)srtp_crypto_alloc(sizeof(srtp_cipher_t *) *
                                                       num_ciphers);
    if (cipher_array == NULL) {
        return srtp_err_status_alloc_fail;
    }

    /* set ca to location of cipher_array */
    *ca = cipher_array;

    /* allocate key , allow zero key for example null cipher */
    if (klen_pad > 0) {
        key = srtp_crypto_alloc(klen_pad);
        if (key == NULL) {
            srtp_crypto_free(cipher_array);
            return srtp_err_status_alloc_fail;
        }
    }

    /* allocate and initialize an array of ciphers */
    for (size_t i = 0; i < num_ciphers; i++) {
        /* allocate cipher */
        status = srtp_cipher_type_alloc(ctype, cipher_array, klen, 16);
        if (status) {
            return status;
        }

        /* generate random key and initialize cipher */
        srtp_cipher_rand_for_tests(key, klen);
        for (size_t j = klen; j < klen_pad; j++) {
            key[j] = 0;
        }
        status = srtp_cipher_init(*cipher_array, key);
        if (status) {
            return status;
        }

        /*     printf("%dth cipher is at %p\n", i, *cipher_array); */
        /*     printf("%dth cipher description: %s\n", i,  */
        /* 	   (*cipher_array)->type->description); */

        /* advance cipher array pointer */
        cipher_array++;
    }

    srtp_crypto_free(key);

    return srtp_err_status_ok;
}

srtp_err_status_t cipher_array_delete(srtp_cipher_t *cipher_array[],
                                      size_t num_cipher)
{
    for (size_t i = 0; i < num_cipher; i++) {
        srtp_cipher_dealloc(cipher_array[i]);
    }

    srtp_crypto_free(cipher_array);

    return srtp_err_status_ok;
}

/*
 * cipher_array_bits_per_second(c, l, t) computes (an estimate of) the
 * number of bits that a cipher implementation can encrypt in a second
 * when distinct keys are used to encrypt distinct messages
 *
 * c is a cipher (which MUST be allocated an initialized already), l
 * is the length in octets of the test data to be encrypted, and t is
 * the number of trials
 *
 * if an error is encountered, the value 0 is returned
 */

uint64_t cipher_array_bits_per_second(srtp_cipher_t *cipher_array[],
                                      size_t num_cipher,
                                      size_t octets_in_buffer,
                                      size_t num_trials)
{
    v128_t nonce;
    clock_t timer;
    uint8_t *enc_buf;

    /* Constrain the number of ciphers */
    if (num_cipher > UINT32_MAX) {
        num_cipher = UINT32_MAX;
    }
    size_t cipher_index = srtp_cipher_rand_u32_for_tests() % num_cipher;

    /* Over-alloc, for NIST CBC padding */
    enc_buf = srtp_crypto_alloc(octets_in_buffer + 17);
    if (enc_buf == NULL) {
        return 0; /* indicate bad parameters by returning null */
    }

    /* time repeated trials */
    v128_set_to_zero(&nonce);
    timer = clock();
    for (size_t i = 0; i < num_trials; i++, nonce.v32[3] = (uint32_t)i) {
        /* length parameter to srtp_cipher_encrypt is in/out -- out is total,
         * padded
         * length -- so reset it each time. */
        size_t octets_to_encrypt = octets_in_buffer;

        /* encrypt buffer with cipher */
        srtp_cipher_set_iv(cipher_array[cipher_index], (uint8_t *)&nonce,
                           srtp_direction_encrypt);
        srtp_cipher_encrypt(cipher_array[cipher_index], enc_buf,
                            octets_to_encrypt, enc_buf, &octets_to_encrypt);

        /* choose a cipher at random from the array*/
        cipher_index = (*((size_t *)enc_buf)) % num_cipher;
    }
    timer = clock() - timer;

    srtp_crypto_free(enc_buf);

    if (timer == 0) {
        /* Too fast! */
        return 0;
    }

    return (uint64_t)CLOCKS_PER_SEC * num_trials * 8 * octets_in_buffer / timer;
}

void cipher_array_test_throughput(srtp_cipher_t *ca[], size_t num_cipher)
{
    size_t min_enc_len = 16;
    size_t max_enc_len = 2048; /* should be a power of two */
    size_t num_trials = 1000000;

    printf("timing %s throughput with key length %zu, array size %zu:\n",
           (ca[0])->type->description, (ca[0])->key_len, num_cipher);
    fflush(stdout);
    for (size_t i = min_enc_len; i <= max_enc_len; i = i * 4) {
        printf("msg len: %zd\tgigabits per second: %f\n", i,
               cipher_array_bits_per_second(ca, num_cipher, i, num_trials) /
                   1e9);
    }
}

srtp_err_status_t cipher_driver_test_array_throughput(srtp_cipher_type_t *ct,
                                                      size_t klen,
                                                      size_t num_cipher)
{
    srtp_cipher_t **ca = NULL;
    srtp_err_status_t status;

    status = cipher_array_alloc_init(&ca, num_cipher, ct, klen);
    if (status) {
        printf("error: cipher_array_alloc_init() failed with error code %d\n",
               status);
        return status;
    }

    cipher_array_test_throughput(ca, num_cipher);

    cipher_array_delete(ca, num_cipher);

    return srtp_err_status_ok;
}
