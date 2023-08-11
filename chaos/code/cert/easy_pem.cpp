#include "easy_pem.h"
#include "openssl/bio.h"
#include "openssl/dsa.h"
#include "openssl/ec.h"
#include <assert.h>
#include <ato/log.h>
#include <cstdint>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace pem {

std::vector<uint8_t> ReadPrikey(const char *file) {
  BIO *in = BIO_new_file(file, "r");
  EVP_PKEY *key = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
  int der_len = i2d_PrivateKey(key, NULL);
  unsigned char *der_buf = (unsigned char *)malloc(der_len + 1);
  unsigned char *p = der_buf;
  i2d_PrivateKey(key, &p);
  std::vector<uint8_t> out(der_buf, der_buf + der_len);
  free(der_buf);
  BIO_free(in);
  EVP_PKEY_free(key);
  return out;
}

///< 未验证
void WritePrikey(const char *file, const std::vector<uint8_t> &key) {
  const uint8_t *dat_buf = key.data();
  EVP_PKEY *pkey = d2i_AutoPrivateKey(NULL, &dat_buf, key.size());
  BIO *wd = BIO_new_file(file, "Wb");
  i2d_PKCS8PrivateKey_bio(wd, pkey, NULL, NULL, 0, NULL, NULL);
  EVP_PKEY_free(pkey);
  BIO_free(wd);
}

} // namespace pem
