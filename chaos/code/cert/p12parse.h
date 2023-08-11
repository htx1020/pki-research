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
 * @file p12parse.h
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
#ifndef LIC_COMM_P12PARSE_H_
#define LIC_COMM_P12PARSE_H_

#include <openssl/err.h>
#include <openssl/pkcs12.h>

#include <cstdint>
#include <iostream>
#include <vector>

#define MAX_CARD_RSA_LEN 512
#define MIN_CARD_PRIME_LEN 256
/// RSA公钥结构
typedef struct _XDJA_RSA_PUB_KEY {
    unsigned int bits;                  // 公钥模数长度，1024或2048
    unsigned char m[MAX_CARD_RSA_LEN];  // 长度256字节，不足靠前存储
    unsigned int e;                     // 可能取值65537
} RsaPubkey_t;

/// RSA私钥结构
typedef struct _XDJA_RSA_PRI_KEY {
    unsigned int bits;                     // 公钥模数长度1024或者2048
    unsigned char p[MIN_CARD_PRIME_LEN];   // 长度128字节，不足靠前存储
    unsigned char q[MIN_CARD_PRIME_LEN];   // 长度128字节，不足靠前存储
    unsigned char dp[MIN_CARD_PRIME_LEN];  // 长度128字节，不足靠前存储
    unsigned char dq[MIN_CARD_PRIME_LEN];  // 长度128字节，不足靠前存储
    unsigned char ce[MIN_CARD_PRIME_LEN];  // 长度128字节，不足靠前存储

} RsaPrikey_t;

class P12Parser {
    enum {
        errNone,
        errParameter,
        errOpenFile,
        errD2iP12File,
        errParseP12File,
        errGetRsaKey,
        errNoSapceToStoreData,
    };

   public:
    P12Parser(const char *file, const char *password);
    ~P12Parser() { close(); }
    bool isValid();

    int GetCertData(std::vector<uint8_t> &cert);
    int GetKeyData(std::vector<uint8_t> &prikey, std::vector<uint8_t> &pubkey);

    int getCert(unsigned char *derCert, int *derCertLen);
    int getRsaKey(RsaPubkey_t *pubkey, RsaPrikey_t *prikey);

   private:
    int open(const char *file);
    void close();

    std::string _file;
    std::string _pw;
    /* PKCS12 *_p12 = NULL; */
    X509 *_cert = NULL;
    EVP_PKEY *_pkey = NULL;
    bool _isValid;
};

int testP12Pase();

#endif
