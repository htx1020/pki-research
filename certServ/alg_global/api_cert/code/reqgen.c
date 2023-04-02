#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>

char prikey[] = "tmp/prikey.pem";
char certreq[] = "tmp/req.pem";

typedef const EVP_MD *cbMD(void);

EVP_PKEY *gen_RSA()
{
    RSA             *rsa = RSA_new();
    BIGNUM          *bn = NULL;
    EVP_PKEY        *pkey = NULL;
        
    do {
        unsigned long   e = RSA_F4;
        int             bits = 2048;
        
        if ((bn = BN_new()) == NULL) {
            printf("BN_new err\n");
            return NULL;
        }

        if (!BN_set_word(bn, e) || !RSA_generate_key_ex(rsa, bits, bn, NULL)) {
            printf("BN_set_word or RSA_generate_key_ex err\n");
            RSA_free(rsa);
            break;
        }

        pkey = EVP_PKEY_new();
        if (!EVP_PKEY_assign_RSA(pkey,rsa)) {
            EVP_PKEY_free(pkey);
            break;
        }
    }while(0);

    if (bn) {
        BN_free(bn);
    }
    return pkey;
}


X509_REQ *generate_X509_REQ(EVP_PKEY *pkey, cbMD mdfunc)
{
    if(!pkey || !mdfunc)
        return NULL;

    X509_REQ *ret = NULL;
    BIO          *outbio = NULL;
    X509_REQ     *x509_req = NULL;
    X509_NAME    *x509_name = NULL;

    long         lVer = 0L;
    const char   *szCountry = "CN";
    const char   *szProvince = "BJ";
    const char   *szCity = "BJ";
    const char   *szOrganization = "AICC";
    const char   *szOrganizationUnit = "DATA-SEC";
    const char   *szCommon = "localhost";

    /* ---------------------------------------------------------- *
    * Create the Input/Output BIO's.                             *
    * ---------------------------------------------------------- */
    outbio = BIO_new(BIO_s_file());
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

    // 1. generate EC key

    do {
        // create x509_req object
        x509_req = X509_REQ_new();
        if (x509_req == NULL) {
            BIO_printf(outbio, "Error creating new X509_REQ object\n");
            break;
        }

        // 2. setup version number
        if (!X509_REQ_set_version(x509_req, lVer))
        {
            BIO_printf(outbio, "Error setting version to X509_REQ object\n");
            break;
        }

        //char tmp_buf[512] = { '\0' };
        //int tmpBufLen = sizeof(tmp_buf);
        //从CA证书中获取C,ST,O,OU

        // 3. set subject of x509 req
        x509_name = X509_REQ_get_subject_name(x509_req);
        //C
        if (!X509_NAME_add_entry_by_NID(x509_name, NID_countryName, MBSTRING_UTF8, (unsigned char *)szCountry, -1, -1, 0)) {
            BIO_printf(outbio, "Error adding entry [NID_countryName] to X509_REQ object\n");
            break;
        }
        //ST
        if (!X509_NAME_add_entry_by_NID(x509_name, NID_stateOrProvinceName, MBSTRING_UTF8, (unsigned char *)szProvince, -1, -1, 0)) {
            BIO_printf(outbio, "Error adding entry [NID_stateOrProvinceName] to X509_REQ object\n");
            break;
        }
        //L
        if (!X509_NAME_add_entry_by_NID(x509_name, NID_localityName, MBSTRING_UTF8, (unsigned char *)szCity, -1, -1, 0)) {
            BIO_printf(outbio, "Error adding entry [NID_localityName] to X509_REQ object\n");
            break;
        }
        //O
        if (!X509_NAME_add_entry_by_NID(x509_name, NID_organizationName, MBSTRING_UTF8, (unsigned char *)szOrganization, -1, -1, 0)) {
            BIO_printf(outbio, "Error adding entry [NID_organizationName] to X509_REQ object\n");
            break;
        }
        //OU   OU在openssl.conf中默认是可选的
        if (!X509_NAME_add_entry_by_NID(x509_name, NID_organizationalUnitName, MBSTRING_UTF8, (unsigned char *)szOrganizationUnit, -1, -1, 0)) {
            BIO_printf(outbio, "Error adding entry [NID_organizationalUnitName] to X509_REQ object\n");
            break;
        }
        //CN
        if (!X509_NAME_add_entry_by_NID(x509_name, NID_commonName, MBSTRING_UTF8, (unsigned char *)szCommon, -1, -1, 0)) {
            BIO_printf(outbio, "Error adding entry [NID_commonName] to X509_REQ object\n");
            break;
        }

        // 4. set public key of x509 req
        if (1 != (X509_REQ_set_pubkey(x509_req, pkey))){
            BIO_printf(outbio, "Error setting pubkey to X509_REQ object\n");
            break;
        }

        //加入一组可选的扩展属性
        //STACK_OF(X509_EXTENSION) *extlist = sk_X509_EXTENSION_new_null();
        //X509_EXTENSION*ext = X509V3_EXT_conf(NULL, NULL, REQ_SUBJECT_ALT_NAME, value); //生成扩展对象
        //sk_X509_EXTENSION_push(extlist, ext);
        //X509_REQ_add_extensions(x509_req, extlist); // 加入扩展项目。

        // 5. set sign key of x509 req
        int len = X509_REQ_sign(x509_req, pkey, mdfunc());  // return x509_req->signature->length
        if (len <= 0){
            unsigned long ulErr = ERR_get_error(); // 获取错误号
            char szErrMsg[1024] = { 0 };
            char *pTmp = NULL;
            pTmp = ERR_error_string(ulErr, szErrMsg); // 格式：error:errId:库:函数:原因
            printf("%s, %s\n", szErrMsg, pTmp);
            BIO_printf(outbio, "Error sign X509_REQ\n");
            break;
        }

        ret = x509_req;
        x509_req = NULL;
    } while(0);

    BIO_free_all(outbio);
    if (pkey)
    {
        EVP_PKEY_free(pkey);
    }
    if (x509_req)
    {
        X509_REQ_free(x509_req);
    }

    return ret;
}


int testReqGen()
{
    EVP_PKEY        *pkey=NULL;
    BIO             *b = BIO_new_file(certreq,"w");
    BIO             *k = BIO_new_file(prikey,"w");

    do {
        /* pub key */
        int is = 0;
        pkey = gen_RSA();
        if(NULL == pkey) {
            break;
        }

        X509_REQ *req = generate_X509_REQ(pkey, EVP_sha256);
        if(!req)
            break;

        /* 写入文件PEM格式 */
        is = PEM_write_bio_X509_REQ(b,req);
        if(1 != is)
            printf("write x509_req fail\n");

        if (!PEM_write_bio_PrivateKey(k, pkey, NULL, NULL, 0, 0, NULL))
        {
            printf("write x509_key fail\n");
            break;
            /* 错误处理代码 */
        }
    }while(0);

    EVP_PKEY_free(pkey);
    BIO_free(b);
    BIO_free(k);

    return 0;
}

