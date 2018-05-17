#include <nss.h>
#include <pk11pub.h>
#include <secerr.h>
#include <nspr.h>
#include <stdio.h>

// gcc -I../../nss/dist/public/nss -I../../nss/dist/Debug/include/nspr -L../../nss/dist/Debug/lib -lnss3 -lnspr4 nss_incremental.c

void hexdump(unsigned char *buf, unsigned int len) {
  for (unsigned int i = 0; i < len; ++i) {
    printf("%02x", buf[i]);
  }
  printf("\n");
}

#define BUFLEN 128

int main() {
  NSS_NoDB_Init(NULL);

  CK_ATTRIBUTE_TYPE operation = CKA_ENCRYPT;
  PK11Origin origin = PK11_OriginUnwrap;
  unsigned char key[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                           0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  unsigned char iv[16] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                          0x28, 0x29, 0x2a, 0x2b};
  unsigned char aad[2] = {0x30, 0x31};
  int keyLen = 16;

  unsigned char in[4] = {0x00, 0x01, 0x02, 0x03};
  int inLen = 0;
  unsigned char enc[BUFLEN];
  unsigned int encLen = 0;
  unsigned char dec[BUFLEN];
  unsigned int decLen = 0;
  unsigned int tempLen = 0;
  int maxOut = BUFLEN;

  char errstr[BUFLEN];
  memset(errstr, 0, BUFLEN);

  CK_MECHANISM_TYPE mechanism = CKM_AES_GCM;
  CK_GCM_PARAMS param;
  param.pAAD = aad;
  param.ulAADLen = 2;
  param.pIv = iv;
  param.ulIvLen = 12;
  param.ulTagBits = 64;
  SECItem paramItem = { siBuffer, (unsigned char*) &param, sizeof(CK_GCM_PARAMS) };

  /////
  PK11SlotInfo *slot = PK11_GetInternalSlot();
  if (!slot) {
    printf("Failed to get slot\n");
    return 1;
  }

  SECItem keyItem = { siBuffer, key, keyLen };
  PK11SymKey *symKey = PK11_ImportSymKey(slot, mechanism, PK11_OriginUnwrap, CKA_ENCRYPT, &keyItem, NULL);
  if (!symKey) {
    printf("Failed to get symKey\n");
    return 1;
  }

  int rv = PK11_Encrypt(symKey, CKM_AES_GCM, &paramItem,
                        NULL, &encLen, maxOut,
                        in, inLen);

  printf("inLen=%d encLen=%d\n", inLen, encLen);

  /////

  /*
  {

    PK11Context *ctx = PK11_CreateContextBySymKey(mechanism, CKA_ENCRYPT, symKey, &paramItem);
    if (!ctx) {
      printf("Failed to get context\n");
      return 1;
    }

    PK11_FreeSymKey(symKey);
    PK11_FreeSlot(slot);

    SECStatus rv = PK11_CipherOp(ctx, enc, (int*) &tempLen, maxOut, in, inLen);
    if (rv != SECSuccess) {
      printf("Failure in CipherOp\n");
      return 1;
    }
    encLen += tempLen;

    printf("after enc op : [%d]", encLen);
    hexdump(enc, encLen);

    rv = PK11_CipherFinal(ctx, enc + encLen, &tempLen, maxOut - encLen);
    if (rv != SECSuccess) {
      printf("Failure in CipherFinal\n");
      return 1;
    }
    encLen += tempLen;

    printf("after enc fin: [%d]", encLen);
    hexdump(enc, encLen);

    PK11_DestroyContext(ctx, PR_TRUE);
  }

  {
    PK11SlotInfo *slot = PK11_GetInternalSlot();
    if (!slot) {
      printf("Failed to get slot\n");
      return 1;
    }

    SECItem keyItem = { siBuffer, key, keyLen };
    PK11SymKey *symKey = PK11_ImportSymKey(slot, mechanism, PK11_OriginUnwrap, CKA_ENCRYPT, &keyItem, NULL);
    if (!symKey) {
      printf("Failed to get symKey\n");
      return 1;
    }

    PK11Context *ctx = PK11_CreateContextBySymKey(mechanism, CKA_DECRYPT, symKey, &paramItem);
    if (!ctx) {
      printf("Failed to get context\n");
      return 1;
    }

    SECStatus rv = PK11_CipherOp(ctx, dec, (int*) &tempLen, maxOut, enc, encLen);
    if (rv != SECSuccess) {
      printf("Failure in CipherOp\n");
      return 1;
    }
    decLen += tempLen;

    printf("after dec op : [%d]", decLen);
    hexdump(dec, decLen);

    rv = PK11_CipherFinal(ctx, dec + decLen, &tempLen, maxOut - decLen);
    if (rv != SECSuccess) {
      printf("Failure in CipherFinal\n");
      return 1;
    }
    decLen += tempLen;

    printf("after dec fin: [%d]", decLen);
    hexdump(dec, decLen);

    PK11_DestroyContext(ctx, PR_TRUE);
  }
  */

  return 0;
}
