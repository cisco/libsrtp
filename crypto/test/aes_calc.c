/*
 * aes_calc.c
 * 
 * A simple AES calculator for generating AES encryption values
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 */

/*
  
 Example usage (with first NIST FIPS 197 test case):
 
[sh]$ test/aes_calc 000102030405060708090a0b0c0d0e0f 00112233445566778899aabbccddeeff -v
 plaintext:      00112233445566778899aabbccddeeff
 key:            000102030405060708090a0b0c0d0e0f
 ciphertext:     69c4e0d86a7b0430d8cdb78070b4c55a

 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "aes.h"
#include <stdio.h>
#include <string.h>

static void
usage(char *prog_name) {
  printf("usage: %s <key> <plaintext> [-v]\n", prog_name);
  exit(255);
}

#define AES_MAX_KEY_LEN 32

int
main (int argc, char *argv[]) {
  v128_t data;
  uint8_t key[AES_MAX_KEY_LEN];
  aes_expanded_key_t exp_key;
  int key_len, len;
  int verbose = 0;
  err_status_t status;

  if (argc == 3) {
    /* we're not in verbose mode */
    verbose = 0;
  } else if (argc == 4) {
    if (strncmp(argv[3], "-v", 2) == 0) {
      /* we're in verbose mode */
      verbose = 1;
    } else {
      /* unrecognized flag, complain and exit */
      usage(argv[0]);
    }
  } else {
    /* we've been fed the wrong number of arguments - compain and exit */
    usage(argv[0]);
  }
  
  /* read in key, checking length */
  if (strlen(argv[1]) > AES_MAX_KEY_LEN*2) {
    fprintf(stderr, 
	    "error: too many digits in key "
	    "(should be at most %d hexadecimal digits, found %u)\n",
	    AES_MAX_KEY_LEN*2, (unsigned)strlen(argv[1]));
    exit(1);    
  }
  len = hex_string_to_octet_string((char*)key, argv[1], AES_MAX_KEY_LEN*2);
  /* check that hex string is the right length */
  if (len != 32 && len != 48 && len != 64) {
    fprintf(stderr, 
	    "error: bad number of digits in key "
	    "(should be 32/48/64 hexadecimal digits, found %d)\n",
	    len);
    exit(1);    
  } 
  key_len = len/2;
      
  /* read in plaintext, checking length */
  if (strlen(argv[2]) > 16*2) {
    fprintf(stderr, 
	    "error: too many digits in plaintext "
	    "(should be %d hexadecimal digits, found %u)\n",
	    16*2, (unsigned)strlen(argv[2]));
    exit(1);    
  }
  len = hex_string_to_octet_string((char *)(&data), argv[2], 16*2);
  /* check that hex string is the right length */
  if (len < 16*2) {
    fprintf(stderr, 
	    "error: too few digits in plaintext "
	    "(should be %d hexadecimal digits, found %d)\n",
	    16*2, len);
    exit(1);    
  }

  if (verbose) {
    /* print out plaintext */
    printf("plaintext:\t%s\n", octet_string_hex_string((uint8_t *)&data, 16));
  }

  /* encrypt plaintext */
  status = aes_expand_encryption_key(key, key_len, &exp_key);
  if (status) {
    fprintf(stderr,
	    "error: AES key expansion failed.\n");
    exit(1);
  }

  aes_encrypt(&data, &exp_key);

  /* write ciphertext to output */
  if (verbose) {
    printf("key:\t\t%s\n", octet_string_hex_string(key, key_len));
    printf("ciphertext:\t");
  }
  printf("%s\n", v128_hex_string(&data));

  return 0;
}

