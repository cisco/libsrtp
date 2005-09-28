/*
 * config_in.h
 *
 * template for header config file for Secure RTP and libcryptomodule
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 */


#ifndef CONFIG_H
#define CONFIG_H

/* if we're on a big endian machine, we need to define this */

#define WORDS_BIGENDIAN      0

/* if we're on an intel x86, define this to use inlined asm */

#define HAVE_X86 0

/* check for <stdint.h> or <machine/types.h>              */

#define HAVE_STDINT_H        0
#define HAVE_INTTYPES_H      0
#define HAVE_MACHINE_TYPES_H 0
#define HAVE_SYS_INT_TYPES_H 0

/* check if an unsigned 64-bit integer is supported natively */

#define HAVE_U_LONG_LONG 0

/* check for microsoft integer definitions (e.g., cygwin) */

#define HAVE_MS_TYPES        1

/* if we don't have uio.h, we'll need to define struct iovec */

#define HAVE_SYS_UIO_H       0

/* <unistd.h> is used by some test/ apps                  */

#define HAVE_UNISTD_H        0

/* test apps should use inet_aton(), if it's available */

#define HAVE_INET_ATON       0

/* check if we have syslog functions                      */

#define HAVE_SYSLOG_H        0

/* check to see if the user has requested the use of syslog */

#define USE_SYSLOG           0

#define ERR_REPORTING_STDOUT 0

#define ERR_REPORTING_SYSLOG (HAVE_SYSLOG_H & USE_SYSLOG)

/* define ERR_REPORTING_FILE to have messages sent to file */

#define ERR_REPORTING_FILE ""

#define USE_ERR_REPORTING_FILE 0

/* 
 * set ENABLE_DEBUGGING to 1 to compile in dynamic debugging system,
 * set it to 0 to not compile in dynamic debugging (for a slight
 * performance improvement)
 */

#define ENABLE_DEBUGGING     0

/* if we're going to use GDOI, define SRTP_GDOI to 1      */

#define SRTP_GDOI            0

/*
 * CPU_type is defined as 1 if the host processor is of that type.
 * Note that more than one type can be defined at once; this is so
 * that special instructions and other optimizations can be handled
 * independently.
 * 
 * CPU_RISC     RISC machines (assume slow byte access)
 * CPU_CISC     CISC machines (e.g. Intel)
 * CPU_ALTIVEC  Motorola's SIMD instruction set
 * 
 */

#define CPU_RISC     0
#define CPU_CISC     0
#define CPU_ALTIVEC  0

/*
 * /dev/urandom is a (true) random number generator which is
 * implemented in many modern operating systems
 */

#define DEV_URANDOM 0

/* check for stdlib.h - we use it for alloc() and free() */

#define HAVE_STDLIB_H 0

/* whether to use ismacryp code */
#define GENERIC_AESICM 0

#endif /* CONFIG_H */




