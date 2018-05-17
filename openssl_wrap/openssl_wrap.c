#include <stdio.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/err.h>

uint8_t test_key_128[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
};

uint8_t test_key_256[32] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
};

//////////

uint8_t test_pt_1[1] = {
  0xff
};

uint8_t test_pt_16[16] = {
  0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
  0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
};

uint8_t test_pt_20[20] = {
  0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
  0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
  0x80, 0x81, 0x82, 0x83,
};

//////////

uint8_t test_ct_1[16];
uint8_t test_ct_16[24];
uint8_t test_ct_20[32];

//////////

char bit_string[1024];

char *octet_string_hex_string(const void *s, int length)
{
    const uint8_t *str = (const uint8_t *)s;
    int i;

    for (i = 0; i < length; i += 1) {
        sprintf(bit_string + 2*i, "%02x", str[i]);
    }
    bit_string[2*i] = 0; /* null terminate string */
    return bit_string;
}

int encrypt(const char *label, const EVP_CIPHER *cipher, uint8_t *key,
            uint8_t *pt, int pt_len, uint8_t *ct) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return 0;
  }

  EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

  if (!EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL)) {
    return 0;
  }

  int ct_len = pt_len;
  if (1 != EVP_EncryptUpdate(ctx, ct, &ct_len, pt, pt_len)) {
    return 0;
  }

  printf("%s [%d]: %s\n", label, ct_len, octet_string_hex_string(ct, ct_len));
  return 1;
}

int main() {
  const EVP_CIPHER *kw128 = EVP_aes_128_wrap_pad();
  if (!kw128) {
    printf("error getting cipher \n");
    ERR_print_errors_fp(stderr);
    return 1;
  }

  const EVP_CIPHER *kw256 = EVP_aes_256_wrap_pad();
  if (!kw256) {
    printf("error getting cipher \n");
    ERR_print_errors_fp(stderr);
    return 1;
  }

  encrypt("t_128_1", kw128, test_key_128, test_pt_1, 1, test_ct_1);
  encrypt("t_128_16", kw128, test_key_128, test_pt_16, 16, test_ct_16);
  encrypt("t_128_20", kw128, test_key_128, test_pt_20, 20, test_ct_20);

  encrypt("t_256_1", kw256, test_key_256, test_pt_1, 1, test_ct_1);
  encrypt("t_256_16", kw256, test_key_256, test_pt_16, 16, test_ct_16);
  encrypt("t_256_20", kw256, test_key_256, test_pt_20, 20, test_ct_20);
}
