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
 * @file rsa.cpp
 * @brief RSA接口
 * @details 基于openssl封装RSA加解密接口
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
#include "rsa.h"

#include <openssl/bn.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <assert.h>
#include <cstdint>
#include <iostream>
#include <sstream>

#include "sha256.hpp"

namespace algo_rsa {
std::vector<uint8_t> PubkeyToDER(RSA *rsa)
{
    // 将公钥转换为 DER 格式
    int public_key_length = i2d_RSAPublicKey(rsa, nullptr);
    std::vector<uint8_t> public_key_der(public_key_length);
    unsigned char *ptr = public_key_der.data();
    i2d_RSAPublicKey(rsa, &ptr);
    return public_key_der;
}

std::vector<uint8_t> PrikeyToDER(RSA *rsa)
{
    // 将公钥转换为 DER 格式
    int public_key_length = i2d_RSAPrivateKey(rsa, nullptr);
    std::vector<uint8_t> public_key_der(public_key_length);
    unsigned char *ptr = public_key_der.data();
    i2d_RSAPrivateKey(rsa, &ptr);
    return public_key_der;
}

RSA *LoadPubkeyFromDER(const std::vector<uint8_t> &der_pubkey)
{
    const uint8_t *data = der_pubkey.data();
    RSA *key            = d2i_RSAPublicKey(nullptr, &data, (long)der_pubkey.size());
    return key;
}

RSA *LoadPrikeyFromDER(const std::vector<uint8_t> &der_pubkey)
{
    const uint8_t *data = der_pubkey.data();
    RSA *key            = d2i_RSAPrivateKey(nullptr, &data, (long)der_pubkey.size());
    return key;
}

// 生成RSA密钥对
void GenerateKey(unsigned int numBits, std::vector<uint8_t> &private_key, std::vector<uint8_t> &public_key)
{
    RSA *rsa   = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, 65537);
    RSA_generate_key_ex(rsa, numBits, bn, NULL);

    public_key  = PubkeyToDER(rsa);
    private_key = PrikeyToDER(rsa);
    RSA_free(rsa);
    BN_free(bn);
}

// RSA签名
std::string Sign(const std::string &msg, const std::vector<uint8_t> &private_key)
{
    std::string signature;
    // 读取私钥
    RSA *rsa       = LoadPrikeyFromDER(private_key);
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);

    // 计算消息哈希
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(md_ctx, msg.c_str(), msg.length());
    EVP_DigestFinal_ex(md_ctx, md_value, &md_len);

    // 签名
    EVP_MD_CTX *md_ctx_sign = EVP_MD_CTX_create();
    EVP_SignInit(md_ctx_sign, EVP_sha256());
    EVP_SignUpdate(md_ctx_sign, md_value, md_len);
    unsigned char sign_buf[8192];
    unsigned int sign_len;
    EVP_SignFinal(md_ctx_sign, sign_buf, &sign_len, pkey);

    signature.assign(sign_buf, sign_buf + sign_len);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_destroy(md_ctx);
    EVP_MD_CTX_destroy(md_ctx_sign);
    return signature;
}

// RSA验签
bool Verify(const std::string &msg, const std::string &signature, const std::vector<uint8_t> &public_key)
{
    // 读取公钥
    RSA *rsa       = LoadPubkeyFromDER(public_key);
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);
    assert(rsa != NULL);
    assert(pkey != NULL);

    // 计算消息哈希
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(md_ctx, msg.c_str(), msg.length());
    EVP_DigestFinal_ex(md_ctx, md_value, &md_len);

    ///< 验签
    EVP_MD_CTX *md_ctx_verify = EVP_MD_CTX_create();
    EVP_VerifyInit(md_ctx_verify, EVP_sha256());
    EVP_VerifyUpdate(md_ctx_verify, md_value, md_len);
    int auth_result =
        EVP_VerifyFinal(md_ctx_verify, (unsigned char *)signature.c_str(), (unsigned int)signature.length(), pkey);
    ///< 资源释放
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_destroy(md_ctx_verify);
    EVP_MD_CTX_destroy(md_ctx);
    return (auth_result == 1) ? true : false;
}

} // namespace algo_rsa
