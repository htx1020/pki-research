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
 * @file cert_opt.cpp
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
#include "cert_opt.h"

#include <assert.h>
#include <cstring>
#include <iostream>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <regex>

#include "rsa.h"
#include "utils.h"

namespace cert_opt {
int VerifyCertificate(const uint8_t *cert_data, size_t cert_len,
                      const uint8_t *ca_data, size_t ca_len) {
  X509_STORE *store = NULL;
  X509 *cert = NULL;
  X509 *ca_cert = NULL;
  int ret = 0;
  do {
    store = X509_STORE_new();
    if (!store) {
      std::cout << "Failed to create X509 store." << std::endl;
      ret = kErrLoadCa;
      break;
    }
    ca_cert = d2i_X509(&ca_cert, &ca_data, (long)ca_len);
    if (!ca_cert) {
      std::cout << "Failed to read ca certificate." << std::endl;
      ret = kErrLoadCa;
      break;
    }
    cert = d2i_X509(&cert, &cert_data, (long)cert_len);
    if (!cert) {
      std::cout << "Failed to read certificate." << std::endl;
      ret = kErrLoadCert;
      break;
    }
    X509_STORE_add_cert(store, ca_cert);

    X509_STORE_CTX *ctx = X509_STORE_CTX_new(); // 证书上下文k
    X509_STORE_CTX_init(ctx, store, cert, NULL);

    X509_STORE_CTX_set_verify(ctx, NULL);
    if (X509_verify_cert(ctx) != 1) {
      ret = kErrVerify; ///< 验证失败
    } else {
      ret = kErrNone; ///< 验证成功
    }
    X509_STORE_CTX_free(ctx);

  } while (0);
  if (NULL != store) {
    X509_STORE_free(store);
  }
  if (NULL != ca_cert) {
    X509_free(ca_cert);
  }
  if (NULL != cert) {
    X509_free(cert);
  }
  return ret;
}

bool GetCertificateInfo(const unsigned char *certificate_data, size_t size,
                        CertInfo *info) {
  assert(NULL != certificate_data);
  assert(0 != size);
  assert(NULL != info);

  X509 *cert = NULL;
  cert = d2i_X509(&cert, &certificate_data, (long)size);
  if (!cert) {
    std::cout << "Failed to read certificate." << std::endl;
    return false;
  }

  ///< 时间获取
  ASN1_TIME *notBefore = X509_get_notBefore(cert);
  ASN1_TIME *notAfter = X509_get_notAfter(cert);
  struct tm t;
  ASN1_TIME_to_tm(notBefore, &t);
  info->ts_start = utils::UTCToTimeStamp(t);
  info->start =
      utils::ToTimeString(utils::CSTFromTimeStamp(info->ts_start)) + "CST8";
  ASN1_TIME_to_tm(notAfter, &t);
  info->ts_end = utils::UTCToTimeStamp(t);
  info->end =
      utils::ToTimeString(utils::CSTFromTimeStamp(info->ts_end)) + "CST8";

  ///< Subject获取
  char buf[1024];
  X509_NAME *x509_name = X509_get_subject_name(cert);
  X509_NAME_oneline(x509_name, buf, sizeof(buf));
  /*X509_NAME_free(x509_name);*/
  info->subject = buf;
  ///< Name获取
  std::regex r("/O=([^/]*)");
  std::smatch m;
  if (std::regex_search(info->subject, m, r)) {
    info->username = m[1].str();
  }

  X509_free(cert);
  return true;
}

std::string GetCertificateValidity(const unsigned char *certificate_data,
                                   size_t size) {
  CertInfo info;
  GetCertificateInfo(certificate_data, size, &info);
  char result[64];
  sprintf(result, "START %s | END %s", info.start.c_str(), info.end.c_str());
  return result;
}

std::vector<uint8_t> GetPubkeyOfCert(const uint8_t *cert_data,
                                     size_t cert_len) {
  X509 *cert = NULL;
  cert = d2i_X509(&cert, &cert_data, (long)cert_len);
  if (!cert) {
    std::cout << "Failed to read certificate." << std::endl;
    return {};
  }
  EVP_PKEY *pkey = X509_get_pubkey(cert);
  RSA *rsa = NULL;
  int ptype = EVP_PKEY_base_id(pkey);
  if (EVP_PKEY_RSA == ptype) {
    rsa = EVP_PKEY_get1_RSA(pkey);
  }
  std::vector<uint8_t> rval = algo_rsa::PubkeyToDER(rsa);
  X509_free(cert);
  if (NULL != pkey) {
    EVP_PKEY_free(pkey);
  }
  if (NULL != rsa) {
    RSA_free(rsa);
  }
  return rval;
}

} // namespace cert_opt
