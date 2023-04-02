#include "log.h"
#include "p12parse.h"
#include "reqgen.h"
#include <iostream>
#include <mcheck.h>

int main() {
    mtrace();

#ifdef TEST_P12
    testP12Pase();
#endif

#ifdef TEST_REQ
    testReqGen();
#endif

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
