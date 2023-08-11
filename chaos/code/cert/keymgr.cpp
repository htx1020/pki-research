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
#include "keymgr.h"

#include <cassert>
#include <iostream>

#include "kvdb.hpp"
#include "rsa.h"
#include "utils.h"

// Key,IV初值
static struct {
  std::vector<uint8_t> key;
  std::vector<uint8_t> iv;
} KeyMgrInfo = {{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32,
                 0x33, 0x34, 0x35, 0x36, 0x37, 0x38},
                {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32,
                 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}};

KvDatabase *kvdb_ = nullptr;
KeyMgr *KeyMgr::instance_ = nullptr;
/* std::mutex mutex_; */

///< 是否加密
#define IS_CIPHER(a) ((a) > 0x0100)

KeyMgr::~KeyMgr() {
  std::cerr << __func__ << " destructor\n";
  Close();
}
int KeyMgr::Open(const std::string &dbpath, const std::string &pin) {
  KvDatabase *db = nullptr;
  this->path_ = dbpath;
  try {
    db = new KvDatabase(this->path_);
  } catch (...) {
    std::cerr << "Creat KvDatabase fail " << this->path_ << std::endl;
    return kErrorInitDataBase;
  }
  this->kvdb_ = db;

  Cipher *cipher = nullptr;
  try {
    cipher = new CipherAes(KeyMgrInfo.key, KeyMgrInfo.iv);
  } catch (...) {
    std::cerr << "Creat Cipher fail " << std::endl;
    return kErrorCreateCipher;
  }
  this->cipher_ = cipher;
  return kErrorNone;
}

int KeyMgr::Close() {
  if (nullptr != this->kvdb_) {
    delete this->kvdb_;
    this->kvdb_ = nullptr;
  }
  if (nullptr != this->cipher_) {
    delete this->cipher_;
    this->cipher_ = nullptr;
  }
  return kErrorNone;
}

int KeyMgr::SaveData(int keyid, const std::vector<uint8_t> &value, int rdflag) {
  assert(nullptr != this->cipher_);
  assert(nullptr != this->kvdb_);
  if (keyid > 0x0100) {
    std::vector<uint8_t> enc_val = cipher_->Encrypt(value);
    kvdb_->put(keyid, enc_val);
  } else {
    kvdb_->put(keyid, value);
  }
  return kErrorNone;
}

std::vector<uint8_t> KeyMgr::GetData(int keyid) {
  assert(nullptr != cipher_);
  assert(nullptr != this->kvdb_);
  std::vector<uint8_t> value = this->kvdb_->get(keyid);
  if (0 == value.size()) {
    /* std::cerr << "Get From KV error" << std::endl; */
    return value;
  }

  if (IS_CIPHER(keyid)) {
    value = cipher_->Decrypt(value);
  }
  return value;
}

int KeyMgr::RSASignatureGen(int keyid, const std::string &msg,
                            std::string &sign) {
  std::vector<uint8_t> prikey = GetData(keyid);
  sign = algo_rsa::Sign(msg, prikey);
  return kErrorNone;
}

int KeyMgr::RSASignatureVerify(int keyid, const std::string &msg,
                               const std::string &signature) {
  std::vector<uint8_t> pubkey = GetData(keyid);
  bool rc = algo_rsa::Verify(msg, signature, pubkey);
  if (true != rc) {
    return kErrorSignatureVerifyFailed;
  }
  return kErrorNone;
}
