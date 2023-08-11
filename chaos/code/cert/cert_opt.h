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
 * @file cert_opt.h
 * @brief 证书操作
 * @details 证书操作集合
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
#ifndef LICCLI_COMM_CERT_OPT_H_
#define LICCLI_COMM_CERT_OPT_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

typedef struct S_CertInfo {
  time_t ts_start;
  time_t ts_end;
  std::string start;
  std::string end;
  std::string subject;
  std::string username;
} CertInfo;

namespace cert_opt {
enum {
  kErrNone = 0,
  kErrLoadCa,
  kErrLoadCert,
  kErrVerify,

};

int VerifyCertificate(const uint8_t *cert_data, size_t cert_len,
                      const uint8_t *ca_data, size_t ca_len);

bool GetCertificateInfo(const unsigned char *certificate_data, size_t size,
                        CertInfo *info);

std::string GetCertificateValidity(const unsigned char *certificate_data,
                                   size_t size);

std::vector<uint8_t> GetPubkeyOfCert(const uint8_t *cert_data, size_t cert_len);
} // namespace cert_opt
#endif // !LICCLI_VHSM_CERT_VERIFY_H_
