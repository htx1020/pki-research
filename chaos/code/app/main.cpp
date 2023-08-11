#include "cert_gen.h"
#include "cert_req.h"
#include "easy_pem.h"
#include "p12parse.h"
#include <atop/llog.hpp>
#include <iostream>
#include <mcheck.h>
#include <vector>

int main() {
  mtrace();

#ifdef TEST_P12
  /* testP12Pase(); */
#endif

#ifdef TEST_REQ
  TestCertReq();
  TestCertGen();
#endif

  std::vector<uint8_t> prikey = pem::ReadPrikey("./tmp/prikey.pem");
  pem::WritePrikey("./tmp/sss.pem", prikey);
  std::cerr << atop::ByteToHexString(prikey.data(), prikey.size());

  muntrace();
}

#ifdef TEST_API
int testp12() {

  FILE *fp;
  PKCS12 *p12 = NULL;
  PKCS7 *p7 = NULL, *one;
  unsigned char buf[10000], *p;
  int len, i, num, j, count, ret;
  STACK_OF(PKCS7) * p7s;
  STACK_OF(PKCS12_SAFEBAG) * bags;
  PKCS12_SAFEBAG *bag;
  PBEPARAM *pbe = 0;
  BIO *bp;
  char pass[100];
  int passlen;
  X509 *cert = NULL;
  STACK_OF(X509) *ca = NULL;
  EVP_PKEY *pkey = NULL;

  unsigned char bufCert[2000];
  unsigned char bufPkey[2000];
  unsigned int bufCertLen = sizeof(bufCert);
  unsigned int bufPkeyLen = sizeof(bufPkey);

  // bp=BIO_new(BIO_s_file());
  // BIO_set_fp(bp,stdout,BIO_NOCLOSE);

  // bufPkeyLen=BN_bn2bin(rsa->n,bufPkey);

  HEXDUMP("cert", bufCert, bufCertLen);

  // decodeDerData("./tmp/extCert.der");
  decodeDerPrikey("./tmp/extPrikey.der");

  return 0;
}
#endif
