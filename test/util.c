/*
 * util.c
 *
 * Utilities used by the test apps
 *
 * John A. Foley
 * Cisco Systems, Inc.
 */
/*
 *
 * Copyright (c) 2014-2017, Cisco Systems, Inc.
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

#include "config.h"
#include "util.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* include space for null terminator */
static char bit_string[MAX_PRINT_STRING_LEN + 1];

#define ERR_STATUS_STRING(STATUS)                                              \
    case srtp_err_status_##STATUS:                                             \
        return #STATUS

const char *err_status_string(srtp_err_status_t status)
{
    switch (status) {
        ERR_STATUS_STRING(ok);
        ERR_STATUS_STRING(fail);
        ERR_STATUS_STRING(bad_param);
        ERR_STATUS_STRING(alloc_fail);
        ERR_STATUS_STRING(dealloc_fail);
        ERR_STATUS_STRING(init_fail);
        ERR_STATUS_STRING(terminus);
        ERR_STATUS_STRING(auth_fail);
        ERR_STATUS_STRING(cipher_fail);
        ERR_STATUS_STRING(replay_fail);
        ERR_STATUS_STRING(replay_old);
        ERR_STATUS_STRING(algo_fail);
        ERR_STATUS_STRING(no_such_op);
        ERR_STATUS_STRING(no_ctx);
        ERR_STATUS_STRING(cant_check);
        ERR_STATUS_STRING(key_expired);
        ERR_STATUS_STRING(socket_err);
        ERR_STATUS_STRING(signal_err);
        ERR_STATUS_STRING(nonce_bad);
        ERR_STATUS_STRING(read_fail);
        ERR_STATUS_STRING(write_fail);
        ERR_STATUS_STRING(parse_err);
        ERR_STATUS_STRING(encode_err);
        ERR_STATUS_STRING(semaphore_err);
        ERR_STATUS_STRING(pfkey_err);
        ERR_STATUS_STRING(bad_mki);
        ERR_STATUS_STRING(pkt_idx_old);
        ERR_STATUS_STRING(pkt_idx_adv);
        ERR_STATUS_STRING(buffer_small);
    }
    return "unkown srtp_err_status";
}

void check_ok_impl(srtp_err_status_t status, const char *file, int line)
{
    if (status != srtp_err_status_ok) {
        fprintf(stderr,
                "\nerror at %s:%d, unexpected srtp failure: %d (\"%s\")\n",
                file, line, status, err_status_string(status));
        exit(1);
    }
}

void check_return_impl(srtp_err_status_t status,
                       srtp_err_status_t expected,
                       const char *file,
                       int line)
{
    if (status != expected) {
        fprintf(stderr,
                "\nerror at %s:%d, unexpected srtp status: %d != %d (\"%s\" != "
                "\"%s\")\n",
                file, line, status, expected, err_status_string(status),
                err_status_string(expected));
        exit(1);
    }
}

void check_impl(bool condition,
                const char *file,
                int line,
                const char *condition_str)
{
    if (!condition) {
        fprintf(stderr, "\nerror at %s:%d, %s)\n", file, line, condition_str);
        exit(1);
    }
}

#define OVERRUN_CHECK_BYTE 0xf1

void overrun_check_prepare(uint8_t *buffer, size_t offset, size_t buffer_len)
{
    memset(buffer + offset, OVERRUN_CHECK_BYTE, buffer_len - offset);
}

void check_buffer_equal_impl(const uint8_t *buffer1,
                             const uint8_t *buffer2,
                             size_t buffer_length,
                             const char *file,
                             int line)
{
    for (size_t i = 0; i < buffer_length; i++) {
        if (buffer1[i] != buffer2[i]) {
            fprintf(stderr,
                    "\nerror at %s:%d, buffer1 != buffer2 at index: %zu (%x != "
                    "%x)\n",
                    file, line, i, buffer1[i], buffer2[i]);
            fprintf(stderr, "buffer1 = %s\n",
                    octet_string_hex_string(buffer1, buffer_length));
            fprintf(stderr, "buffer2 = %s\n",
                    octet_string_hex_string(buffer2, buffer_length));
            exit(1);
        }
    }
}

void check_overrun_impl(const uint8_t *buffer,
                        size_t offset,
                        size_t buffer_length,
                        const char *file,
                        int line)
{
    for (size_t i = offset; i < buffer_length; i++) {
        if (buffer[i] != OVERRUN_CHECK_BYTE) {
            printf("\nerror at %s:%d, overrun detected in buffer at index %zu "
                   "(expected %x, found %x)\n",
                   file, line, i, OVERRUN_CHECK_BYTE, buffer[i]);
            exit(1);
        }
    }
}

static inline int hex_char_to_nibble(char c)
{
    switch (c) {
    case ('0'):
        return 0x0;
    case ('1'):
        return 0x1;
    case ('2'):
        return 0x2;
    case ('3'):
        return 0x3;
    case ('4'):
        return 0x4;
    case ('5'):
        return 0x5;
    case ('6'):
        return 0x6;
    case ('7'):
        return 0x7;
    case ('8'):
        return 0x8;
    case ('9'):
        return 0x9;
    case ('a'):
        return 0xa;
    case ('A'):
        return 0xa;
    case ('b'):
        return 0xb;
    case ('B'):
        return 0xb;
    case ('c'):
        return 0xc;
    case ('C'):
        return 0xc;
    case ('d'):
        return 0xd;
    case ('D'):
        return 0xd;
    case ('e'):
        return 0xe;
    case ('E'):
        return 0xe;
    case ('f'):
        return 0xf;
    case ('F'):
        return 0xf;
    default:
        return -1; /* this flags an error */
    }
}

char nibble_to_hex_char(uint8_t nibble)
{
    char buf[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    return buf[nibble & 0xF];
}

/*
 * hex_string_to_octet_string converts a hexadecimal string
 * of length 2 * len to a raw octet string of length len
 */
size_t hex_string_to_octet_string(uint8_t *raw, const char *hex, size_t len)
{
    uint8_t x;
    int tmp;
    size_t hex_len;

    hex_len = 0;
    while (hex_len < len) {
        tmp = hex_char_to_nibble(hex[0]);
        if (tmp == -1) {
            return hex_len;
        }
        x = (uint8_t)(tmp << 4);
        hex_len++;
        tmp = hex_char_to_nibble(hex[1]);
        if (tmp == -1) {
            return hex_len;
        }
        x |= (tmp & 0xff);
        hex_len++;
        *raw++ = x;
        hex += 2;
    }
    return hex_len;
}

const char *octet_string_hex_string(const uint8_t *str, size_t length)
{
    size_t i;

    /* double length, since one octet takes two hex characters */
    length *= 2;

    /* truncate string if it would be too long */
    if (length > MAX_PRINT_STRING_LEN) {
        length = MAX_PRINT_STRING_LEN;
    }

    for (i = 0; i < length; i += 2) {
        bit_string[i] = nibble_to_hex_char(*str >> 4);
        bit_string[i + 1] = nibble_to_hex_char(*str++ & 0xF);
    }
    bit_string[i] = 0; /* null terminate string */
    return bit_string;
}

static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               "abcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t base64_block_to_octet_triple(uint8_t *out, const char *in)
{
    uint8_t sextets[4] = { 0 };
    size_t j = 0;
    size_t i;

    for (i = 0; i < 4; i++) {
        char *p = strchr(b64chars, in[i]);
        if (p != NULL) {
            sextets[i] = (uint8_t)(p - b64chars);
        } else {
            j++;
        }
    }

    out[0] = (sextets[0] << 2) | (sextets[1] >> 4);
    if (j < 2) {
        out[1] = (sextets[1] << 4) | (sextets[2] >> 2);
    }
    if (j < 1) {
        out[2] = (sextets[2] << 6) | sextets[3];
    }
    return j;
}

size_t base64_string_to_octet_string(uint8_t *out,
                                     int *pad,
                                     const char *in,
                                     size_t len)
{
    size_t k = 0;
    size_t i = 0;
    size_t j = 0;

    if (len % 4 != 0) {
        return 0;
    }

    while (i < len && j == 0) {
        j = base64_block_to_octet_triple(out + k, in + i);
        k += 3;
        i += 4;
    }
    *pad = (int)j;
    return i;
}
