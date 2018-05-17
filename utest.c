#include <stdio.h>

#define SEC_ERROR_BASE (-0x2000)

int main() {
  printf("%08x\n", SEC_ERROR_BASE);
  return 0;
}
