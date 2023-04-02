#include "stdio.h"
#include <net/if.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <string.h>

const char *pHostAddr = "127.0.0.1";
const unsigned short u16Port = 10001;
const char *const pCAPath = "../certServ/alg_global/ca/demoCA/cacert.pem";

#define VIRIFY_SERVER_CA 1
int main(int argc, char *argv[]) {
    /*SSL库初始化（一个进程只初始化一次）*/
    SSL_library_init();
    /*载入所有ssl错误消息*/
    SSL_load_error_strings();
    /*载入所有ssl算法*/
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *pMethod = SSLv23_method();
    SSL_CTX *pCtx = NULL;
    SSL *pSSl = NULL;

    int iRet = -1;
    int remote_socket = -1;
    struct sockaddr_in remoteDevAddr;
    X509 *pX509Cert = NULL;
    X509_NAME *pX509Subject = NULL;
    char szBuf[256] = {0};
    char szSubject[1024] = {0};
    char szIssuer[256] = {0};
    do {
        /*初始化SSL上下文环境变量函数*/
        pCtx = SSL_CTX_new(pMethod);
        if (NULL == pCtx) {
            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet,
                   ERR_error_string(ERR_get_error(), NULL));
            break;
        }
#if VIRIFY_SERVER_CA
        /*加载CA证书（对端证书需要用CA证书来验证）*/
        if (SSL_CTX_load_verify_locations(pCtx, pCAPath, NULL) != 1) {
            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet,
                   ERR_error_string(SSL_get_error(pSSl, iRet), NULL));
            break;
        }
        /*设置对端证书验证*/
        SSL_CTX_set_verify(pCtx, SSL_VERIFY_PEER, NULL);
#endif
#if 0
		if (!SSL_CTX_set_cipher_list (pCtx, "ALL"))
		{
			printf("%s %d iRet=%d %s\n",__func__,__LINE__,iRet,ERR_error_string(SSL_get_error(pSSl, iRet), NULL));
			break;
 
		}
#endif
        memset(&remoteDevAddr, 0, sizeof(remoteDevAddr));
        remoteDevAddr.sin_addr.s_addr = inet_addr(pHostAddr);
        remoteDevAddr.sin_family = AF_INET;
        remoteDevAddr.sin_port = htons(u16Port);

        remote_socket = socket(AF_INET, SOCK_STREAM, 0); /* Open the socket */
        if (remote_socket < 0) {
            printf("%s %d errno=%d\n", __func__, __LINE__, errno);
            break;
        }
        if (connect(remote_socket, (struct sockaddr *)&remoteDevAddr,
                    sizeof(remoteDevAddr)) < 0) {
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
        SSL_set_fd(pSSl, remote_socket);

        /*ssl握手*/
        iRet = SSL_connect(pSSl);
        if (iRet < 0) {
            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet,
                   ERR_error_string(SSL_get_error(pSSl, iRet), NULL));
            break;
        }
#if VIRIFY_SERVER_CA
        /*获取验证对端证书的结果*/
        if (X509_V_OK != SSL_get_verify_result(pSSl)) {
            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet,
                   ERR_error_string(ERR_get_error(), NULL));
            break;
        }

        /*获取对端证书*/
        pX509Cert = SSL_get_peer_certificate(pSSl);

        if (NULL == pX509Cert) {
            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet,
                   ERR_error_string(ERR_get_error(), NULL));
            break;
        }

        /*获取证书使用者属性*/
        pX509Subject = X509_get_subject_name(pX509Cert);
        if (NULL == pX509Subject) {
            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet,
                   ERR_error_string(SSL_get_error(pSSl, iRet), NULL));
            break;
        }

        X509_NAME_oneline(pX509Subject, szSubject, sizeof(szSubject) - 1);
        X509_NAME_oneline(X509_get_issuer_name(pX509Cert), szIssuer,
                          sizeof(szIssuer) - 1);
        X509_NAME_get_text_by_NID(pX509Subject, NID_commonName, szBuf,
                                  sizeof(szBuf) - 1);
        printf("szSubject =%s \nszIssuer =%s\n  commonName =%s\n", szSubject,
               szIssuer, szBuf);
#endif
        SSL_write(pSSl, "hello ssl", strlen("hello ssl"));
        printf("client send text:\"hello ssl\" to server\n");
        SSL_shutdown(pSSl);
    } while (0);
#if VIRIFY_SERVER_CA

    if (pX509Cert) {
        X509_free(pX509Cert);
    }
#endif
    if (pSSl) {
        SSL_free(pSSl);
        pSSl = NULL;
    }
    if (pCtx) {
        SSL_CTX_free(pCtx);
        pCtx = NULL;
    }

    if (remote_socket > 0) {
        close(remote_socket);
    }
}
