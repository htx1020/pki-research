#include "stdio.h"
#include <net/if.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>

const unsigned short u16Port = 10001;

// const char *const certificate_path = "./CA/server/server.crt";
// const char *const private_key_path = "./CA/server/server.key";
// const char *const pCAPath = "./CA/demoCA/cacert.pem";

const char *const certificate_path = "./certsvr/one.pem";
const char *const private_key_path = "./certsvr/pri.pem";
const char *const pCAPath = "../certServ/alg_global/ca/demoCA/cacert.pem";

const char *const pRetStr = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
int main(int argc, char *argv[]) {

    /*SSL库初始化（一个进程只初始化一次）*/
    SSL_library_init();
    /*载入所有ssl错误消息*/
    SSL_load_error_strings();
    /*载入所有ssl算法*/
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *pMethod = TLSv1_2_method();
    SSL_CTX *pCtx = NULL;
    SSL *pSSl = NULL;

    int iRet = -1;
    int listen_socket = -1;
    int client_socket = -1;
    struct sockaddr_in serverAddr;
    struct sockaddr_in clientAddr;
    char szBuf[1024] = {0};
    int iClientLen = 0;
    do {
        /*初始化SSL上下文环境变量函数*/
        pCtx = SSL_CTX_new(pMethod);

        if (NULL == pCtx) {
            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet,
                   ERR_error_string(ERR_get_error(), NULL));
            break;
        }

        /* 载入用户的数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */
        if (SSL_CTX_use_certificate_file(pCtx, certificate_path,
                                         SSL_FILETYPE_PEM) <= 0) {
            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet,
                   ERR_error_string(ERR_get_error(), NULL));
            break;
        }
#if 1
        /*设置私钥的解锁密码*/
        SSL_CTX_set_default_passwd_cb_userdata(pCtx, "123456");
#endif
        /* 载入用户私钥 */
        if (SSL_CTX_use_PrivateKey_file(pCtx, private_key_path,
                                        SSL_FILETYPE_PEM) <= 0) {
            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet,
                   ERR_error_string(ERR_get_error(), NULL));
            break;
        }

        /* 检查用户私钥是否正确 */
        if (SSL_CTX_check_private_key(pCtx) <= 0) {
            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet,
                   ERR_error_string(ERR_get_error(), NULL));
            break;
        }

        /*证书验证*/
        SSL_CTX_set_verify(pCtx, SSL_VERIFY_NONE, NULL);

        SSL_CTX_set_options(pCtx,
                            SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
        SSL_CTX_set_mode(pCtx, SSL_MODE_AUTO_RETRY);

        listen_socket = socket(AF_INET, SOCK_STREAM, 0); /* Open the socket */
        if (listen_socket < 0) {
            printf("%s %d errno=%d\n", __func__, __LINE__, errno);
            break;
        }

        memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(u16Port);

        if (bind(listen_socket, (struct sockaddr *)&serverAddr,
                 sizeof(serverAddr)) < 0) {
            printf("%s %d errno=%d\n", __func__, __LINE__, errno);
            break;
        }

        if (listen(listen_socket, 5) < 0) {
            printf("%s %d errno=%d\n", __func__, __LINE__, errno);
            break;
        }
        while (1) {
            iClientLen = sizeof(clientAddr);
            printf("start listen!!!\n");
            /*等待客户端连接*/
            client_socket = accept(listen_socket,
                                   (struct sockaddr *)&clientAddr, &iClientLen);
            if (client_socket < 0) {
                printf("%s %d errno=%d\n", __func__, __LINE__, errno);
                break;
            }

            /*基于pCtx产生一个新的ssl*/
            pSSl = SSL_new(pCtx);
            if (NULL == pSSl) {
                printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet,
                       ERR_error_string(ERR_get_error(), NULL));
                break;
            }
            /*将连接的socket加入到ssl*/
            SSL_set_fd(pSSl, client_socket);

            /*建立ssl连接（握手）*/
            if (SSL_accept(pSSl) <= 0) {
                printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet,
                       ERR_error_string(ERR_get_error(), NULL));
                break;
            }

            /*接收客户端的消息*/
            iRet = SSL_read(pSSl, szBuf, sizeof(szBuf));
            if (iRet > 0) {
                printf("server recv text :%s \n", szBuf);
            }

            /*发送消息给客户端*/
            SSL_write(pSSl, pRetStr, strlen(pRetStr));
            printf("%s %d \n", __func__, __LINE__);

            /*关闭ssl连接*/
            SSL_shutdown(pSSl);
            close(client_socket);
        }
    } while (0);

    if (pSSl) {
        SSL_free(pSSl);
        pSSl = NULL;
    }
    if (pCtx) {
        /*释放SSL上下文环境变量函数*/
        SSL_CTX_free(pCtx);
        pCtx = NULL;
    }

    if (client_socket > 0) {
        close(client_socket);
    }

    if (listen_socket > 0) {
        close(client_socket);
    }
}
