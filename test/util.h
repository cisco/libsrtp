/*
 * util.h
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
#ifndef SRTP_TEST_UTIL_H
#define SRTP_TEST_UTIL_H

#include "srtp.h"

// test check macros and functions
void check_ok_impl(srtp_err_status_t status, const char *file, int line);
void check_return_impl(srtp_err_status_t status,
                       srtp_err_status_t expected,
                       const char *file,
                       int line);
void check_impl(bool condition,
                const char *file,
                int line,
                const char *condition_str);
void check_overrun_impl(const uint8_t *buffer,
                        size_t offset,
                        size_t buffer_length,
                        const char *file,
                        int line);
void overrun_check_prepare(uint8_t *buffer, size_t offset, size_t buffer_len);

#define CHECK_OK(status) check_ok_impl((status), __FILE__, __LINE__)
#define CHECK_RETURN(status, expected)                                         \
    check_return_impl((status), (expected), __FILE__, __LINE__)
#define CHECK(condition) check_impl((condition), __FILE__, __LINE__, #condition)
#define CHECK_OVERRUN(buffer, offset, length)                                  \
    check_overrun_impl((buffer), (offset), (length), __FILE__, __LINE__)

#define MAX_PRINT_STRING_LEN 1024

size_t hex_string_to_octet_string(uint8_t *raw, const char *hex, size_t len);
const char *octet_string_hex_string(const uint8_t *str, size_t length);
size_t base64_string_to_octet_string(uint8_t *raw,
                                     int *pad,
                                     const char *base64,
                                     size_t len);

#endif
