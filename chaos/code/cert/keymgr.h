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
 * @file keymgr.cpp
 * @brief 密钥管理
 * @details 用于密钥存取，及配套的运算
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
#ifndef LIC_COMM_KEYMGR_H_
#define LIC_COMM_KEYMGR_H_

#include <mutex>
#include <vector>

#include "cipher.hpp"
#include "kvdb.hpp"
#include "rsa.h"

class KeyMgr {
public:
  enum {
    kErrorNone = 0,
    kErrorInitDataBase,
    kErrorCreateCipher,
    kErrorGetDataFromDB,
    kErrorSignatureVerifyFailed,
  };
  ~KeyMgr();
  static KeyMgr &GetInstance() {
    if (nullptr == instance_) {
      static std::mutex mutex;
      mutex.lock();
      if (nullptr == instance_) {
        instance_ = new KeyMgr();
      }
      mutex.unlock();
    }
    return *instance_;
  }

  int Open(const std::string &dbpath, const std::string &pin);
  int SaveData(int keyid, const std::vector<uint8_t> &value, int rdflag = 0);
  std::vector<uint8_t> GetData(int keyid);
  int RSASignatureGen(int keyid, const std::string &msg, std::string &sign);
  int RSASignatureVerify(int keyid, const std::string &msg,
                         const std::string &signature);
  int Close();

private:
  KeyMgr() : kvdb_(nullptr), cipher_(nullptr), path_("") {}

private:
  static KeyMgr *instance_;
  KvDatabase *kvdb_;
  Cipher *cipher_;
  std::string path_;
};

#endif // LIC_COMM_KEYMGR_H_
