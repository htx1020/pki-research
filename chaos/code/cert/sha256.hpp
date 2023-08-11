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
 * @file sha256.hpp
 * @brief SHA256算法封装
 * @details 基于openssl封装SHA256算法
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

#ifndef LIC_COMM_SHA256_H_
#define LIC_COMM_SHA256_H_

#include <openssl/sha.h>

#include <cstdint>
#include <iostream>

class Sha256 {
   public:
    Sha256() { SHA256_Init(&ctx); }

    void Update(const std::string &str) { SHA256_Update(&ctx, str.c_str(), str.size()); }
    void Update(const uint8_t *data, size_t len) { SHA256_Update(&ctx, data, len); }

    std::string Final() {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256_Final(digest, &ctx);

        std::string result((char *)digest, sizeof(digest));
        return result;
    }

   private:
    SHA256_CTX ctx;
};

#endif  // LIC_COMM_SHA256_H_
