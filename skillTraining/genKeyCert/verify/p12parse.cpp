#include "p12parse.h"

CP12parse::CP12parse(const char *file, const char *password)
    : _file(file), _pw(password), _isValid(false) {
    int ret = open(file);
    if (ret == 0)
        _isValid = true;
}

int CP12parse::open(const char *file) {
    int ret = 0;
    do {
        FILE *fp = fopen(file, "rb");
        if (NULL != fp) {
            _p12 = d2i_PKCS12_fp(fp, NULL);
        } else {
            ret = errOpenFile;
        }
        fclose(fp);

        if (NULL == _p12) {
            ret = errD2iP12File;
            break;
        }

        if (1 != PKCS12_parse(_p12, _pw.c_str(), &_pkey, &_cert, NULL)) {
            printf("err %s %s\n", ERR_lib_error_string(ERR_get_error()),
                   ERR_reason_error_string(ERR_get_error()));
            ret = errD2iP12File;
            break;
        }
    } while (0);
    return ret;
}

void CP12parse::close() {
    if (_p12)
        PKCS12_free(_p12);
    if (_cert)
        X509_free(_cert);
    if (_pkey)
        EVP_PKEY_free(_pkey);
}

bool CP12parse::isValid() { return _isValid; }

int CP12parse::getCert(unsigned char *derCert, int *derCertLen) {
    /* 证书文件 */
    int len = i2d_X509(_cert, NULL);
    if (len > *derCertLen) {
        return errNoSapceToStoreData;
    }
    unsigned char *p = derCert;
    *derCertLen = i2d_X509(_cert, &p);
    return errNone;
}

int CP12parse::getRsaKey(RsaPubkey_t *pubkey, RsaPrikey_t *prikey) {
    if (!pubkey || !prikey)
        return errParameter;
    int ret = errNone;
    do {
        RSA *rsa = EVP_PKEY_get1_RSA(_pkey);
        if (!rsa) {
            ret = errGetRsaKey;
            break;
        }
#if 0
        RSA_print_fp(stdout, rsa, 11);
#endif
        // 获取密钥因子
        int rl = 0;
        const BIGNUM *tb = NULL;
        unsigned char e[20];
        tb = RSA_get0_e(rsa);
        rl = BN_bn2bin(tb, e);
        pubkey->e = *(unsigned int *)e;

        tb = RSA_get0_n(rsa);
        rl = BN_bn2bin(tb, pubkey->m);
        tb = RSA_get0_p(rsa);
        rl = BN_bn2bin(tb, prikey->p);
        tb = RSA_get0_q(rsa);
        rl = BN_bn2bin(tb, prikey->q);
        tb = RSA_get0_dmp1(rsa);
        rl = BN_bn2bin(tb, prikey->dp);
        tb = RSA_get0_dmq1(rsa);
        rl = BN_bn2bin(tb, prikey->dq);
        tb = RSA_get0_iqmp(rsa);
        rl = BN_bn2bin(tb, prikey->ce);
        pubkey->bits = RSA_bits(rsa);
    } while (0);
    return ret;
}

char p12file[] = "../user1_cert.p12";
char p12ExtPrikey[] = "./tmp/extPrikey.der";
char p12ExtCert[] = "./tmp/extCert.der";

#include <string.h>
//int testP12Pase() {
int main() {
    CP12parse p12(p12file, "1234");
    if (false == p12.isValid()) {
        printf("load p12 file file");
    }
    printf("xxx\n");
    RsaPrikey_t pri;
    RsaPubkey_t pub;
    memset(&pri, 0, sizeof(pri));
    memset(&pub, 0, sizeof(pub));
    unsigned char tbuff[2048];
    int tbufflen = sizeof(tbuff);
    p12.getCert(tbuff, &tbufflen);
//    hexdump("cert", tbuff, tbufflen);
    p12.getRsaKey(&pub, &pri);
 //   hexdump("pubkey", pub.m, (int)sizeof(pub.m));
  //  hexdump("prikey", pri.p, (int)sizeof(pri.p));
   // return 0;

    /*  证书写入文件 */
    FILE *fp = fopen(p12ExtCert, "wb");
    fwrite(tbuff, 1, tbufflen, fp);
    fclose(fp);
    return 0;
}
