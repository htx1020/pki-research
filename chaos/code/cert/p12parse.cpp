/** -------------------------------------------------------------------------
 *  |                               _     _____    _____                    |
 *  |                       /\     | |   / ___/   / ___/                    |
 *  |                      /  \    | |  / /      / /                        |
 *  |                     / /\ \   | | ( (      ( (                         |
 *  |                    / / _\ \  | |  \ \___   \ \___                     |
 *  |                   /_/ /____\ |_|   \____/   \____/                    |
 *  |                                                                       |
 *  -------------------------------------------------------------------------
 *
 * @file p12parse.cpp
 * @brief PKCS12文件解析
 * @details 将PKCS12文件内部的文件解析为指定格式
 * @author HuangTingxuan<huangtingxuan@china-aicc.cn>
 * @date 2023-07-05
 * Copyright 2023-2025 AICC Inc.
 *
 * These materials and the intellectual property rights associated therewith
 * (“Materials”) are proprietary to AICC Inc. Any and all rights in
 * the Materials are reserved by AICC Inc. Nothing contained in
 * these Materials shall grant or be deemed to grant to you or anyone else, by
 * implication, estoppel or otherwise, any rights in these Materials.
 *
 */
#include "p12parse.h"

#include "llog.h"
#include "openssl/pkcs12.h"
#include "openssl/rsa.h"
#include "rsa.h"

P12Parser::P12Parser(const char *file, const char *password) : _file(file), _pw(password), _isValid(false)
{
    int ret = open(file);
    if (ret == 0)
        _isValid = true;
}

int P12Parser::open(const char *file)
{
    PKCS12 *_p12 = NULL;
    int ret      = 0;
    do
    {
        FILE *fp = fopen(file, "rb");
        if (NULL != fp)
        {
            _p12 = d2i_PKCS12_fp(fp, NULL);
        }
        else
        {
            ret = errOpenFile;
        }
        fclose(fp);

        if (NULL == _p12)
        {
            ret = errD2iP12File;
            break;
        }

        if (1 != PKCS12_parse(_p12, _pw.c_str(), &_pkey, &_cert, NULL))
        {
            printf("err %s %s\n", ERR_lib_error_string(ERR_get_error()), ERR_reason_error_string(ERR_get_error()));
            ret = errD2iP12File;
            break;
        }
    } while (0);
    if (NULL != _p12)
    {
        PKCS12_free(_p12);
    }
    return ret;
}

void P12Parser::close()
{
    if (_cert)
        X509_free(_cert);
    if (_pkey)
        EVP_PKEY_free(_pkey);
}

bool P12Parser::isValid()
{
    return _isValid;
}

int P12Parser::getCert(unsigned char *derCert, int *derCertLen)
{
    /* 证书文件 */
    int len = i2d_X509(_cert, NULL);
    if (len > *derCertLen)
    {
        return errNoSapceToStoreData;
    }
    unsigned char *p = derCert;
    *derCertLen      = i2d_X509(_cert, &p);
    return errNone;
}

int P12Parser::getRsaKey(RsaPubkey_t *pubkey, RsaPrikey_t *prikey)
{
    if (!pubkey || !prikey)
        return errParameter;
    int ret = errNone;
    do
    {
        RSA *rsa = EVP_PKEY_get1_RSA(_pkey);
        if (!rsa)
        {
            ret = errGetRsaKey;
            break;
        }
#if 1
        RSA_print_fp(stdout, rsa, 11);
#endif
        // 获取密钥因子
        int rl           = 0;
        const BIGNUM *tb = NULL;
        unsigned char e[20];
        tb        = RSA_get0_e(rsa);
        rl        = BN_bn2bin(tb, e);
        pubkey->e = *(unsigned int *)e;

        tb           = RSA_get0_n(rsa);
        rl           = BN_bn2bin(tb, pubkey->m);
        tb           = RSA_get0_p(rsa);
        rl           = BN_bn2bin(tb, prikey->p);
        tb           = RSA_get0_q(rsa);
        rl           = BN_bn2bin(tb, prikey->q);
        tb           = RSA_get0_dmp1(rsa);
        rl           = BN_bn2bin(tb, prikey->dp);
        tb           = RSA_get0_dmq1(rsa);
        rl           = BN_bn2bin(tb, prikey->dq);
        tb           = RSA_get0_iqmp(rsa);
        rl           = BN_bn2bin(tb, prikey->ce);
        pubkey->bits = RSA_bits(rsa);
    } while (0);
    return ret;
}

int P12Parser::GetCertData(std::vector<uint8_t> &cert)
{
    /* 证书文件 */
    int len = i2d_X509(_cert, NULL);
    cert.resize(len);
    uint8_t *buf = cert.data();
    i2d_X509(_cert, &buf);
    return errNone;
}

int P12Parser::GetKeyData(std::vector<uint8_t> &prikey, std::vector<uint8_t> &pubkey)
{
    RSA *rsa = EVP_PKEY_get1_RSA(_pkey);
    if (!rsa)
    {
        return errGetRsaKey;
    }
    prikey = algo_rsa::PrikeyToDER(rsa);
    pubkey = algo_rsa::PubkeyToDER(rsa);
    RSA_free(rsa);
    if (prikey.size() && pubkey.size())
    {
        return errGetRsaKey;
    }
    return errNone;
}

#if 0
char p12file[] = "../sample/one.p12.pfx";
char p12ExtPrikey[] = "./tmp/extPrikey.der";
char p12ExtCert[] = "./tmp/extCert.der";

#include <string.h>
int testP12Pase() {
    P12Parser p12(p12file, "1234");
    if (false == p12.isValid()) {
        printf("load p12 file file");
    }
    RsaPrikey_t pri;
    RsaPubkey_t pub;
    memset(&pri, 0, sizeof(pri));
    memset(&pub, 0, sizeof(pub));
    unsigned char tbuff[2048];
    int tbufflen = sizeof(tbuff);
    p12.getCert(tbuff, &tbufflen);
    // hexdumpP("cert", tbuff, tbufflen);
    p12.getRsaKey(&pub, &pri);
    // hexdumpP("pubkey", pub.m, (int)sizeof(pub.m));
    // hexdumpP("prikey", pri.p, (int)sizeof(pri.p));
    return 0;

    /*  证书写入文件 */
    FILE *fp = fopen(p12ExtCert, "wb");
    fwrite(tbuff, 1, tbufflen, fp);
    fclose(fp);
    return 0;
}
#endif
