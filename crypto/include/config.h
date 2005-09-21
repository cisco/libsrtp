/* include/config.h.  Generated automatically by configure.  */
/*
 * config.h
 *
 * template for header config file for Secure RTP and UST implementation
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 */


#ifndef CONFIG_H
#define CONFIG_H

/* if we're on a big endian machine, we need to define this */

#include <sys/types.h>
#if (BYTE_ORDER == BIG_ENDIAN)
#define WORDS_BIGENDIAN      1
#else
#define WORDS_BIGENDIAN      0
#endif

/* check for <stdint.h> or <machine/types.h>              */

#define HAVE_STDINT_H        1
#define HAVE_MACHINE_TYPES_H 1
#define HAVE_SYS_INT_TYPES_H 0

/* check for microsoft integer definitions (e.g., cygwin) */

#define HAVE_MS_TYPES        1

/* if we don't have uio.h, we'll need to define struct iovec */

#define HAVE_SYS_UIO_H       1

/* <unistd.h> is used by some test/ apps                  */

#define HAVE_UNISTD_H        1

/* test apps should use inet_aton(), if it's available */

#define HAVE_INET_ATON       1

/* check if we have syslog functions                      */

#define HAVE_SYSLOG_H        1

/* check to see if the user has requested the use of syslog */

#define USE_SYSLOG           0

#define ERR_REPORTING_STDOUT 1

#define ERR_REPORTING_SYSLOG (HAVE_SYSLOG_H & USE_SYSLOG)

/* define ERR_REPORTING_FILE to have messages sent to file */

#define ERR_REPORTING_FILE 

/* 
 * set ENABLE_DEBUGGING to 1 to compile in dynamic debugging system,
 * set it to 0 to not compile in dynamic debugging (for a slight
 * performance improvement)
 */

#define ENABLE_DEBUGGING     1

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
 * 
 */

#if WORDS_BIGENDIAN
#define CPU_RISC     1
#else
#define CPU_CISC     1
#endif

/*
 * define CPU_16 if cryptoalgorithms should use 16-bit operations -
 * this is probably only the case on very low-end devices
 */
#define CPU_16       0

/* 
 * define CPU_ALTIVEC in order to use the G4/G5 processor's AltiVec
 * SIMD instruction set where possible
 */
#define CPU_ALTIVEC  0


/*
 * if /dev/random is available, then DEV_RANDOM == 1
 *
 * /dev/random is a (true) random number generator which is
 * implemented in many modern operating systems
 */

#define DEV_RANDOM 0

/* check for stdlib.h - we use it for alloc() and free() */

#define HAVE_STDLIB_H 1

#endif /* CONFIG_H */




