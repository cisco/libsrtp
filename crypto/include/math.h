/*
 * math.h
 *
 * crypto math operations and data types
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 */
/*
 *	
 * Copyright (c) 2001-2005 Cisco Systems, Inc.
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

#ifndef MATH_H
#define MATH_H

#include "datatypes.h"

inline int
octet_get_weight(octet_t octet);

unsigned char
v32_weight(v32_t a);

unsigned char
v32_distance(v32_t x, v32_t y);

unsigned int
v32_dot_product(v32_t a, v32_t b);

char *
octet_bit_string(octet_t x);

char *
v16_bit_string(v16_t x);

char *
v32_bit_string(v32_t x);

char *
v64_bit_string(v64_t x);

char *
v128_bit_string(v128_t x);

octet_t
nibble_to_hex_char(octet_t nibble);

char *
octet_hex_string(octet_t x);

char *
octet_string_hex_string(const octet_t *str, int length);

char *
v16_hex_string(v16_t x);

char *
v32_hex_string(v32_t x);

char *
v64_hex_string(v64_t x);

char *
v128_hex_string(v128_t x);

char *
char_to_hex_string(char *x, int num_char);

int
hex_char_to_nibble(octet_t c);

int
is_hex_string(char *s);

octet_t
hex_string_to_octet(char *s);

/*
 * hex_string_to_octet_string converts a hexadecimal string
 * of length 2 * len to a raw octet string of length len
 */

int
hex_string_to_octet_string(char *raw, char *hex, int len); 

v16_t
hex_string_to_v16(char *s);

v32_t
hex_string_to_v32(char *s);

v64_t
hex_string_to_v64(char *s);

v128_t
hex_string_to_v128(char *s);

/* the matrix A[] is stored in column format, i.e., A[i] is
   the ith column of the matrix */

octet_t 
A_times_x_plus_b(octet_t A[8], octet_t x, octet_t b);

void
v16_copy_octet_string(v16_t *x, const octet_t s[2]);

void
v32_copy_octet_string(v32_t *x, const octet_t s[4]);

void
v64_copy_octet_string(v64_t *x, const octet_t s[8]);

void
v128_copy_octet_string(v128_t *x, const octet_t s[16]);

void
v128_add(v128_t *z, v128_t *x, v128_t *y);

int
octet_string_is_eq(octet_t *a, octet_t *b, int len);

void
octet_string_set_to_zero(octet_t *s, int len);



/* 
 * the matrix A[] is stored in column format, i.e., A[i] is the ith
 * column of the matrix
*/
octet_t 
A_times_x_plus_b(octet_t A[8], octet_t x, octet_t b);

void
v128_copy_octet_string(v128_t *x, const octet_t s[16]);

void
v128_left_shift(v128_t *x, int index);

void
v128_right_shift(v128_t *x, int index);

/*
 * the following macros define the data manipulation functions
 * 
 * If DATATYPES_USE_MACROS is defined, then these macros are used
 * directly (and function call overhead is avoided).  Otherwise,
 * the macros are used through the functions defined in datatypes.c
 * (and the compiler provides better warnings).
 */

#define _v128_set_to_zero(x)     \
(                               \
  (x)->v32[0] = 0,              \
  (x)->v32[1] = 0,              \
  (x)->v32[2] = 0,              \
  (x)->v32[3] = 0               \
)

#define _v128_copy(x, y)          \
(                                \
  (x)->v32[0] = (y)->v32[0],     \
  (x)->v32[1] = (y)->v32[1],     \
  (x)->v32[2] = (y)->v32[2],     \
  (x)->v32[3] = (y)->v32[3]      \
)

#define _v128_xor(z, x, y)                       \
(                                               \
   (z)->v32[0] = (x)->v32[0] ^ (y)->v32[0],     \
   (z)->v32[1] = (x)->v32[1] ^ (y)->v32[1],     \
   (z)->v32[2] = (x)->v32[2] ^ (y)->v32[2],     \
   (z)->v32[3] = (x)->v32[3] ^ (y)->v32[3]      \
)

#define _v128_and(z, x, y)                       \
(                                               \
   (z)->v32[0] = (x)->v32[0] & (y)->v32[0],     \
   (z)->v32[1] = (x)->v32[1] & (y)->v32[1],     \
   (z)->v32[2] = (x)->v32[2] & (y)->v32[2],     \
   (z)->v32[3] = (x)->v32[3] & (y)->v32[3]      \
)

#define _v128_or(z, x, y)                        \
(                                               \
   (z)->v32[0] = (x)->v32[0] | (y)->v32[0],     \
   (z)->v32[1] = (x)->v32[1] | (y)->v32[1],     \
   (z)->v32[2] = (x)->v32[2] | (y)->v32[2],     \
   (z)->v32[3] = (x)->v32[3] | (y)->v32[3]      \
)

#define _v128_complement(x)        \
(                                  \
   (x)->v32[0] = ~(x)->v32[0],     \
   (x)->v32[1] = ~(x)->v32[1],     \
   (x)->v32[2] = ~(x)->v32[2],     \
   (x)->v32[3] = ~(x)->v32[3]      \
)

/* ok for NO_64BIT_MATH if it can compare uint64_t's (even as structures) */
#define _v128_is_eq(x, y)                                        \
  (((x)->v64[0] == (y)->v64[0]) && ((x)->v64[1] == (y)->v64[1]))


#if (HAVE_U_LONG_LONG == 0)
#define _v128_xor_eq(z, x)         \
(                                  \
   (z)->v32[0] ^= (x)->v32[0],     \
   (z)->v32[1] ^= (x)->v32[1],     \
   (z)->v32[2] ^= (x)->v32[2],     \
   (z)->v32[3] ^= (x)->v32[3]      \
)
#else
#define _v128_xor_eq(z, x)         \
(                                  \
   (z)->v64[0] ^= (x)->v64[0],     \
   (z)->v64[1] ^= (x)->v64[1]      \
)
#endif


#if 0
#define _v128_get_bit(x, bit)                     \
(                                                 \
   (((x)->v32[3-((bit) >> 5)] >> ((bit) & 31)) & 1)       \
)

#define _v128_set_bit(x, bit)                                    \
(                                                                \
  (((x)->v32[3-((bit) >> 5)]) |= ((uint32_t)1 << ((bit) & 31))) \
)

#define _v128_clear_bit(x, bit)                                   \
(                                                                 \
  (((x)->v32[3-((bit) >> 5])) &= ~((uint32_t)1 << ((bit) & 31))) \
)
#endif

#define _v128_set_bit_to(x, bit, value)   \
(                                         \
   (value) ? _v128_set_bit(x, bit) :      \
             _v128_clear_bit(x, bit)      \
)


#if OLD

#define _v128_get_bit(x, bit)                     \
(                                                 \
  ((((x)->v32[(bit) >> 5]) >> ((bit) & 31)) & 1)  \
)

#define _v128_set_bit(x, bit)                                    \
(                                                                \
  (((x)->v32[(bit) >> 5]) |= ((unsigned long)1 << ((bit) & 31))) \
)

#define _v128_clear_bit(x, bit)                                   \
(                                                                 \
  (((x)->v32[(bit) >> 5]) &= ~((unsigned long)1 << ((bit) & 31))) \
)

#define _v128_set_bit_to(x, bit, value)   \
(                                         \
   (value) ? _v128_set_bit(x, bit) :      \
             _v128_clear_bit(x, bit)      \
)

#endif /* OLD */

#if 0
#if WORDS_BIGENDIAN

#define _v128_add(z, x, y) {                    \
  uint64_t tmp;					\
    						\
  tmp = x->v32[3] + y->v32[3];                  \
  z->v32[3] = (uint32_t) tmp;			\
  						\
  tmp =  x->v32[2] + y->v32[2] + (tmp >> 32);	\
  z->v32[2] = (uint32_t) tmp;                   \
						\
  tmp =  x->v32[1] + y->v32[1] + (tmp >> 32);	\
  z->v32[1] = (uint32_t) tmp;			\
                                                \
  tmp =  x->v32[0] + y->v32[0] + (tmp >> 32);	\
  z->v32[0] = (uint32_t) tmp;			\
}

#else /* assume little endian architecture */

#define _v128_add(z, x, y) {                    \
  uint64_t tmp;					\
						\
  tmp = htonl(x->v32[3]) + htonl(y->v32[3]);	\
  z->v32[3] = ntohl((uint32_t) tmp);		\
  						\
  tmp =  htonl(x->v32[2]) + htonl(y->v32[2])	\
       + htonl(tmp >> 32);			\
  z->v32[2] = ntohl((uint32_t) tmp);		\
                                                \
  tmp =  htonl(x->v32[1]) + htonl(y->v32[1])	\
       + htonl(tmp >> 32);			\
  z->v32[1] = ntohl((uint32_t) tmp);		\
  						\
  tmp =  htonl(x->v32[0]) + htonl(y->v32[0])	\
       + htonl(tmp >> 32);			\
  z->v32[0] = ntohl((uint32_t) tmp);		\
}
						
#endif /* WORDS_BIGENDIAN */                      
#endif

#ifdef DATATYPES_USE_MACROS  /* little functions are really macros */

#define v128_set_to_zero(z)       _v128_set_to_zero(z)
#define v128_copy(z, x)           _v128_copy(z, x)
#define v128_xor(z, x, y)         _v128_xor(z, x, y)
#define v128_and(z, x, y)         _v128_and(z, x, y)
#define v128_or(z, x, y)          _v128_or(z, x, y)
#define v128_complement(x)        _v128_complement(x) 
#define v128_is_eq(x, y)          _v128_is_eq(x, y)
#define v128_xor_eq(x, y)         _v128_xor_eq(x, y)
#define v128_get_bit(x, i)        _v128_get_bit(x, i)
#define v128_set_bit(x, i)        _v128_set_bit(x, i)
#define v128_clear_bit(x, i)      _v128_clear_bit(x, i)
#define v128_set_bit_to(x, i, y)  _v128_set_bit_to(x, i, y)

#else

void
v128_set_to_zero(v128_t *x);

int
v128_is_eq(const v128_t *x, const v128_t *y);

void
v128_copy(v128_t *x, const v128_t *y);

void
v128_xor(v128_t *z, v128_t *x, v128_t *y);

void
v128_and(v128_t *z, v128_t *x, v128_t *y);

void
v128_or(v128_t *z, v128_t *x, v128_t *y); 

void
v128_complement(v128_t *x);

int
v128_get_bit(const v128_t *x, int i);

void
v128_set_bit(v128_t *x, int i) ;     

void
v128_clear_bit(v128_t *x, int i);    

void
v128_set_bit_to(v128_t *x, int i, int y);

#endif /* DATATYPES_USE_MACROS */

/*
 * octet_string_is_eq(a,b, len) returns 1 if the length len strings a
 * and b are not equal, returns 0 otherwise
 */

int
octet_string_is_eq(octet_t *a, octet_t *b, int len);

void
octet_string_set_to_zero(octet_t *s, int len);


/*
 * functions manipulating bit_vector_t 
 *
 * A bitvector_t consists of an array of words and an integer
 * representing the number of significant bits stored in the array.
 * The bits are packed as follows: the least significant bit is that
 * of word[0], while the most significant bit is the nth most
 * significant bit of word[m], where length = bits_per_word * m + n.
 * 
 */

#define bits_per_word  32
#define bytes_per_word 4

typedef struct {
  uint32_t length;   
  uint32_t *word;
} bitvector_t;

#include <stdio.h>

int
bitvector_alloc(bitvector_t *v, unsigned long length);

void
bitvector_set_bit(bitvector_t *v, int bit_index);

int
bitvector_get_bit(const bitvector_t *v, int bit_index);

int
bitvector_print_hex(const bitvector_t *v, FILE *stream);

int
bitvector_set_from_hex(bitvector_t *v, char *string);

#endif /* MATH_H */



