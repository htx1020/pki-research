#include "Certificate.h"
#include "constr_TYPE.h"
#include "easyasn1.h"
#include "log.h"
#include <stdio.h>

int main(int argc, char *argv[]) {
  struct Certificate cert;
  FILE *fp = fopen("./sample-Certificate-1.der", "rb");
  if (NULL == fp) {
    printf("not find file");
    return -2;
  }
  uint8_t buf[4096];
  int ret = fread(buf, 1, sizeof(buf), fp);
  if (ret <= 0) {
    printf("failed %d", ret);
    return -1;
  }
  hexdump("cert", buf, ret);
  Certificate_t *pcert = NULL;
  derDecode(&asn_DEF_Certificate, buf, ret, (void **)&pcert);
  hexdump("signature", pcert->signature.buf, (int)pcert->signature.size);
  asn_fprint(NULL, &asn_DEF_Certificate, pcert);
}
