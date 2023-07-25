
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <openssl/err.h>
#include <openssl/ssl.h>
// int (*X509_STORE_CTX_verify_fn)(X509_STORE_CTX *);

int verify_callback(X509_STORE_CTX *ctx) {
  printf("verify callback\n");
#if 0
    // 遍历证书链，获取每个证书的信息进行验证
    X509* cert = X509_STORE_CTX_get_current_cert(ctx);
    if (!cert)
    {
        return 0;
    }

    // 处理第一个证书时，检查是否由特定的CA证书签名
    if (X509_STORE_CTX_get_error_depth(ctx) == 0)
    {
        X509_NAME* subj = X509_get_subject_name(cert);
        if (!subj)
        {
            return 0;
        }
        BIO* bio = BIO_new(BIO_s_mem());
        X509_NAME_print_ex(bio, subj, 0, XN_FLAG_ONELINE);
        char* name = NULL;
        long len = BIO_get_mem_data(bio, &name);
        if (name && len > 0 && strstr(name, "CN=MyCA"))
        {
            std::cout << "CA certificate is valid" << std::endl;
            return 1;
        }
    }
#endif

  // 在这里添加其它证书的验证逻辑，例如检查证书的过期状态、签名是否正确等等
  // TODO

  return 1; // 返回1表示验证通过
}
int VerifyCert(const uint8_t *cert, size_t cert_len, const uint8_t *ca,
               size_t ca_len) {
  X509_STORE *store = X509_STORE_new();
  if (!store) {
    std::cout << "Failed to create X509 store." << std::endl;
    return false;
  }

  BIO *certBio = BIO_new_mem_buf((void *)ca, ca_len);
  if (!certBio) {
    std::cout << "Failed to create certificate BIO." << std::endl;
    X509_STORE_free(store);
    return false;
  }

  X509 *pcert = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
  if (!pcert) {
    std::cout << "Failed to read certificate." << std::endl;
    BIO_free(certBio);
    X509_STORE_free(store);
    return false;
  }

  /* X509_STORE_load_locations(store, caFile, NULL); */
  X509_STORE_add_cert(store, pcert);

  // 读取客户端证书文件
  const char *clientCertFile = "./cli.crt";
  X509 *cert = NULL;
  BIO *bio = BIO_new_file(clientCertFile, "r");
  if (bio) {
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free_all(bio);
  }
  if (!cert) {
    std::cerr << "Failed to load client certificate" << std::endl;
    return 1;
  }

  X509_STORE_CTX *ctx = X509_STORE_CTX_new(); // 证书上下文k
  X509_STORE_CTX_init(ctx, store, pcert, NULL);

  // X509_STORE_CTX_set_verify(ctx, X509_V_FLAG_CRL_CHECK |
  // X509_V_FLAG_CRL_CHECK_ALL, NULL); X509_STORE_CTX_set_verify(ctx,
  // verify_callback);
  X509_STORE_CTX_set_verify(ctx, NULL);
  if (X509_verify_cert(ctx) != 1) {
    printf("Faut\n");
    // 验证失败
  } else {
    printf("Pass\n");
    // 验证成功
  }

  //// 读取客户端私钥文件
  // const char* clientKeyFile = "client.key";
  // EVP_PKEY* pkey = NULL;
  // bio = BIO_new_file(clientKeyFile, "r");
  // if (bio)
  //{
  //     pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  //     BIO_free_all(bio);
  // }
  // if (!pkey)
  //{
  //     std::cerr << "Failed to load client private key" << std::endl;
  //     X509_free(cert);
  //     return 1;
  // }

  // 创建SSL上下文
  // SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  // SSL_CTX_use_certificate(ctx, cert);
  // SSL_CTX_use_PrivateKey(ctx, pkey);
  // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  // SSL_CTX_set_verify_depth(ctx, 4);
  // SSL_CTX_set_cert_store(ctx, store);

  // 释放客户端证书和私钥
  X509_free(cert);
  // EVP_PKEY_free(pkey);

  // 创建SSL套接字并连接服务器
  // TODO

  // 在SSL通道上发送和接收数据
  // TODO

  X509_STORE_free(store);
  X509_STORE_CTX_free(ctx); // 证书上下文k
  // 关闭SSL通道和套接字
  // SSL_CTX_free(ctx);
  return 0;
}
int main() {
  // 初始化OpenSSL库
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();

  // 读取CA证书文件
  const char *caFile = "ca/ca.crt";
  X509_STORE *store = X509_STORE_new();
  X509_STORE_load_locations(store, caFile, NULL);

  // 读取客户端证书文件
  const char *clientCertFile = "./cli.crt";
  X509 *cert = NULL;
  BIO *bio = BIO_new_file(clientCertFile, "r");
  if (bio) {
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free_all(bio);
  }
  if (!cert) {
    std::cerr << "Failed to load client certificate" << std::endl;
    return 1;
  }

  X509_STORE_CTX *ctx = X509_STORE_CTX_new(); // 证书上下文k
  X509_STORE_CTX_init(ctx, store, cert, NULL);

  // X509_STORE_CTX_set_verify(ctx, X509_V_FLAG_CRL_CHECK |
  // X509_V_FLAG_CRL_CHECK_ALL, NULL); X509_STORE_CTX_set_verify(ctx,
  // verify_callback);
  X509_STORE_CTX_set_verify(ctx, NULL);
  if (X509_verify_cert(ctx) != 1) {
    printf("Faut\n");
    // 验证失败
  } else {
    printf("Pass\n");
    // 验证成功
  }

  //// 读取客户端私钥文件
  // const char* clientKeyFile = "client.key";
  // EVP_PKEY* pkey = NULL;
  // bio = BIO_new_file(clientKeyFile, "r");
  // if (bio)
  //{
  //     pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  //     BIO_free_all(bio);
  // }
  // if (!pkey)
  //{
  //     std::cerr << "Failed to load client private key" << std::endl;
  //     X509_free(cert);
  //     return 1;
  // }

  // 创建SSL上下文
  // SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  // SSL_CTX_use_certificate(ctx, cert);
  // SSL_CTX_use_PrivateKey(ctx, pkey);
  // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  // SSL_CTX_set_verify_depth(ctx, 4);
  // SSL_CTX_set_cert_store(ctx, store);

  // 释放客户端证书和私钥
  X509_free(cert);
  // EVP_PKEY_free(pkey);

  // 创建SSL套接字并连接服务器
  // TODO

  // 在SSL通道上发送和接收数据
  // TODO

  X509_STORE_free(store);
  X509_STORE_CTX_free(ctx); // 证书上下文k
  // 关闭SSL通道和套接字
  // SSL_CTX_free(ctx);
  return 0;
}
