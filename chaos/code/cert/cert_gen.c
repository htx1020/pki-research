#include "openssl/bio.h"
#include "openssl/evp.h"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

int GenCertificate(const char *req_file, const char *prikey,
                   const char *cert_file) {
  ///< read request file
  BIO *in = BIO_new_file(req_file, "r");
  X509_REQ *req = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL);

  ///< read private key
  BIO *key = BIO_new_file(prikey, "r");
  EVP_PKEY *rsa = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);

  // 3. 生成证书
  X509 *cert = X509_new();
  X509_set_version(cert, 2);

  X509_set_subject_name(cert, X509_REQ_get_subject_name(req));
  X509_set_issuer_name(cert, X509_REQ_get_subject_name(req));

  X509_gmtime_adj(X509_get_notBefore(cert), 0);
  X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);

  X509_set_pubkey(cert, rsa);

  X509_sign(cert, rsa, EVP_sha256());

  // 4. 输出证书
  BIO *out = BIO_new_file(cert_file, "wb");
  PEM_write_bio_X509(out, cert);
  X509_print_fp(stdout, cert);

  // 释放内存
  BIO_free(in);
  BIO_free(out);
  BIO_free(key);
  EVP_PKEY_free(rsa);
  X509_REQ_free(req);
  X509_free(cert);

  return 0;
}

int TestCertGen() {

  GenCertificate("./tmp/req.pem", "./tmp/prikey.pem", "./tmp/cert.pem");
  return 0;
}
