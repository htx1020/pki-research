#ifndef P12PARSE_H
#define P12PARSE_H

#include <iostream>
#include <openssl/pkcs12.h>
#include <openssl/err.h>

#define MAX_CARD_RSA_LEN        512
#define MIN_CARD_PRIME_LEN      256
///RSA公钥结构
typedef struct _RSA_PUB_KEY
{
    unsigned int  bits;							//公钥模数长度，1024或2048
    unsigned char m[MAX_CARD_RSA_LEN];			//长度256字节，不足靠前存储
    unsigned int  e;							//可能取值65537
} RsaPubkey_t;

///RSA私钥结构
typedef struct _RSA_PRI_KEY
{
    unsigned int bits;							//公钥模数长度1024或者2048
    unsigned char p[MIN_CARD_PRIME_LEN];		//长度128字节，不足靠前存储
    unsigned char q[MIN_CARD_PRIME_LEN];		//长度128字节，不足靠前存储
    unsigned char dp[MIN_CARD_PRIME_LEN];		//长度128字节，不足靠前存储
    unsigned char dq[MIN_CARD_PRIME_LEN];		//长度128字节，不足靠前存储
    unsigned char ce[MIN_CARD_PRIME_LEN];		//长度128字节，不足靠前存储
    
} RsaPrikey_t;


class CP12parse
{
    enum{
        errNone,
        errParameter,
        errOpenFile,
        errD2iP12File,
        errParseP12File,
        errGetRsaKey,
        errNoSapceToStoreData,
    };
public:
    CP12parse(const char *file, const char *password);
    ~CP12parse() {close();}
    bool isValid();

    int getCert(unsigned char *derCert, int *derCertLen);
    int getRsaKey(RsaPubkey_t *pubkey, RsaPrikey_t *prikey);

private:
    int open(const char *file);
    void close();

    std::string _file;
    std::string _pw;
    PKCS12          *_p12=NULL;
    X509            *_cert=NULL;
    EVP_PKEY        *_pkey=NULL;
    bool _isValid;
};

int testP12Pase();

#endif
