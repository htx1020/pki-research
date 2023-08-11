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
 * @file cipher.h
 * @brief 加解密抽象
 * @details 加解密抽象
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
#ifndef LIC_COMM_CIPHER_H_
#define LIC_COMM_CIPHER_H_

#include <openssl/aes.h>
#include <openssl/evp.h>

#include <iostream>
#include <vector>

#define AES_BLOCK_SIZE 16

class Cipher {
   public:
    virtual ~Cipher() {}

    virtual std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& plain_text) = 0;
    virtual std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& cipher_text) = 0;
};

static std::vector<uint8_t> idle_result(0);

class CipherAes : public Cipher {
   public:
    CipherAes(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
        /* 建立AES算法上下文 */
        _ctx = EVP_CIPHER_CTX_new();
        this->key_ = key;
        this->iv_ = iv;
    }

    virtual ~CipherAes() { EVP_CIPHER_CTX_free(_ctx); }

    // 对输入数据进行加密
    std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& plain_text) override {
        const uint8_t* in = plain_text.data();
        int len = (int)plain_text.size();   ///< openssl长度类型为int
        std::vector<uint8_t> result(len + AES_BLOCK_SIZE);
        uint8_t* out = result.data();
        int outlen = 0;
        int len1;

        if (EVP_EncryptInit_ex(_ctx, EVP_aes_128_ctr(), NULL, key_.data(), iv_.data()) != 1)
            return idle_result;

        if (EVP_EncryptUpdate(_ctx, out, &len1, in, len) != 1) return idle_result;
        outlen += len1;

        if (EVP_EncryptFinal_ex(_ctx, out + len1, &len1) != 1) return idle_result;
        outlen += len1;

        result.resize(outlen);
        return result;
    }

    // 对密文数据进行解密
    std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& cipher_text) override {
        const uint8_t* in = cipher_text.data();
        int len = (int)cipher_text.size(); ///< openssl长度类型为int
        std::vector<uint8_t> result(len);
        uint8_t* out = result.data();
        int outlen = 0;
        int len1;

        if (EVP_DecryptInit_ex(_ctx, EVP_aes_128_ctr(), NULL, key_.data(), iv_.data()) != 1)
            return idle_result;

        if (EVP_DecryptUpdate(_ctx, out, &len1, in, len) != 1) {
            std::cerr << "update failed \n";
            return idle_result;
        }
        outlen += len1;

        if (EVP_DecryptFinal_ex(_ctx, out + len1, &len1) != 1) {
            std::cerr << "final failed \n";
            return idle_result;
        }
        outlen += len1;

        result.resize(outlen);
        return result;
    }

   private:
    EVP_CIPHER_CTX* _ctx;
    std::vector<uint8_t> key_;
    std::vector<uint8_t> iv_;
};

#endif  // LIC_COMM_CIPHER_H_
