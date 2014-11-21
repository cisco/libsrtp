/*
 * err.c
 *
 * error status reporting functions
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 */
/*
 *	
 * Copyright(c) 2001-2006 Cisco Systems, Inc.
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

#include "err.h"


/*  err_level reflects the level of errors that are reported  */

err_reporting_level_t err_level = err_level_none;

/* err_file is the FILE to which errors are reported */

static FILE *err_file = NULL;

srtp_err_status_t
err_reporting_init(const char *ident) {
  
  /*
   * Believe it or not, openlog doesn't return an error on failure.
   * But then, neither does the syslog() call...
   */

#ifdef ERR_REPORTING_STDOUT
  err_file = stdout;
#elif defined(USE_ERR_REPORTING_FILE)
  /* open file for error reporting */
  err_file = fopen(ERR_REPORTING_FILE, "w");
  if (err_file == NULL)
    return srtp_err_status_init_fail;
#endif

  return srtp_err_status_ok;
}

void
err_report(int priority, const char *format, ...) {
  va_list args;

  if (priority <= err_level) {

    va_start(args, format);
    if (err_file != NULL) {
      vfprintf(err_file, format, args);
	  /*      fprintf(err_file, "\n"); */
    }
    va_end(args);
  }
}

void
err_reporting_set_level(err_reporting_level_t lvl) { 
  err_level = lvl;
}
