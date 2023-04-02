#include "log.h"
// #include "xtl/Certificate.h"
// #include "xtl/RSAPrivateKey.h"
// #include "xtl/asn1.h"
// #include "xtl/untils.h"
#include <iostream>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <string.h>
#include <unistd.h>

int p12FileParse(const char *file, const char *password, unsigned char *derCert,
                 unsigned int *derCertLen, unsigned char *derPkey,
                 unsigned int *derPkeyLen) {
    PKCS12 *p12 = NULL;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *p = NULL;
    unsigned int len = 0;
    int ret = 0;
    do {
        FILE *fp = fopen(file, "rb");
        if (NULL != fp) {
            p12 = d2i_PKCS12_fp(fp, NULL);
        }
        fclose(fp);

        if (NULL == p12) {
            ret = -1;
            break;
        }

        if (1 != PKCS12_parse(p12, password, &pkey, &cert, NULL)) {
            printf("err %s %s\n", ERR_lib_error_string(ERR_get_error()),
                   ERR_reason_error_string(ERR_get_error()));
            ret = -2;
            break;
        }

        /* 私钥文件 */
        len = i2d_PrivateKey(pkey, NULL);
        if (len > *derPkeyLen) {
            ret = -3;
            break;
        }
        p = derPkey;
        *derPkeyLen = i2d_PrivateKey(pkey, &p);

        /* 证书文件 */
        len = i2d_X509(cert, NULL);
        if (len > *derCertLen) {
            ret = -4;
            break;
        }
        p = derCert;
        *derCertLen = i2d_X509(cert, &p);
    } while (0);

    if (p12) {
        PKCS12_free(p12);
    }
    X509_free(cert);

    return 0;
}

// void decodeDerData(const char *f) {
//     unsigned char xbuf[2048];
//     unsigned int xbuflen = sizeof(xbuf);
//     int ret = untils::readFile(f, xbuf, (int *)&xbuflen);
//     // HEXDUMP("read", xbuf, xbuflen);
//     Certificate_t *cert = NULL;
//     ret = asn1::derDecode(&asn_DEF_Certificate, xbuf, xbuflen, (void
//     **)&cert); if (ret) {
//         LOG_E("%d\n", ret);
//         return;
//     }
//     asn_fprint(NULL, &asn_DEF_Certificate, cert);
//     memset(xbuf, 0, sizeof(xbuf));
//     ret = asn1::derEncode(&asn_DEF_Certificate, cert, xbuf, sizeof(xbuf),
//                           &xbuflen);
//     if (ret) {
//         LOG_E("%d\n", ret);
//         return;
//     }
//     HEXDUMP("encode", xbuf, xbuflen);
// }
