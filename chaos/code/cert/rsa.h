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
 * @file rsa.h
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
#ifndef LIC_COMM_RSA_H_
#define LIC_COMM_RSA_H_

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <iostream>
#include <vector>

namespace algo_rsa {

std::vector<uint8_t> PubkeyToDER(RSA *rsa);

std::vector<uint8_t> PrikeyToDER(RSA *rsa);
// 生成RSA密钥对
void GenerateKey(unsigned int numBits, std::vector<uint8_t> &private_key,
                 std::vector<uint8_t> &public_key);
// RSA签名
std::string Sign(const std::string &msg, const std::vector<uint8_t> &private_key);
// RSA验签
bool Verify(const std::string &msg, const std::string &signature,
            const std::vector<uint8_t> &public_key);
};  // namespace algo_rsa

#endif  // LIC_COMM_RSA_H_
