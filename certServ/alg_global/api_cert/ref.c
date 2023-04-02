#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ossl_typ.h>

#define CACERT "../ca/demoCA/ca/ca.pem"
#define CAKEY  "../ca/demoCA/private/prikey.pem"

RSA *gen_RSA()
{
	RSA				*ret = NULL;
	RSA				*rsa = NULL;
	BIGNUM			*bn = NULL;
	unsigned long	e = RSA_F4;
	int				bits = 2048;
	
	if ((bn = BN_new()) == NULL)
	{
		printf("BN_new err\n");
		return NULL;
	}
	if ((ret = RSA_new()) == NULL)
	{
		printf("RSA_new err\n");
		goto END;
	}

	if (!BN_set_word(bn, e) || !RSA_generate_key_ex(ret, bits, bn, NULL))
	{
		printf("BN_set_word or RSA_generate_key_ex err\n");
		goto END;
	}

	ret = rsa;
	rsa = NULL;

END:
	if (bn)
	{
		BN_free(bn);
	}
	if (rsa)
	{
		RSA_free(rsa);
	}
	return ret;
}

EC_KEY *gen_EC_KEY()
{ 
	EC_KEY *ret = NULL;

	///* 获取实现的椭圆曲线个数 */
	//EC_builtin_curve *curves = NULL;
	//int crv_len = 0;
	//int nid = 0;
	//crv_len = EC_get_builtin_curves(NULL, 0);
	//curves = (EC_builtin_curve *)malloc(sizeof(EC_builtin_curve) * crv_len);
	///* 获取椭圆曲线列表 */
	//EC_get_builtin_curves(curves, crv_len);
	//for (int i = 0; i < crv_len; i++) {
	//	printf("***** %d *****\n", i);
	//	printf("nid = %d\n", curves[i].nid);
	//	printf("comment = %s\n", curves[i].comment);
	//}
	///*
	//nid=curves[0].nid;会有错误，原因是密钥太短
	//*/
	///* 选取一种椭圆曲线 */
	//nid = curves[25].nid;

	//根据椭圆曲线参数 创建密钥结构
	//if (!(ret = EC_KEY_new_by_curve_name(NID_sm2p256v1))) {
	if (!(ret = EC_KEY_new_by_curve_name(NID_secp256k1))) {
		printf("EC_KEY_new_by_curve_name err!\n");
		return NULL;
	}

	/* 生成密钥 */
	if (!(EC_KEY_generate_key(ret)))
	{
		printf("EC_KEY_generate_key err.\n"); 
		EC_KEY_free(ret);
		return NULL;
	}

	return ret;
}

//
int Add_X509V3_extensions(X509 *cert, X509 * root, int nid, char *value)
{
	X509_EXTENSION *ex;
	//X509V3_CTX ctx = newX509V3_CTX;
	///* This sets the 'context' of the extensions. */
	///* No configuration database */
	////  X509V3_set_ctx_nodb(&ctx);      
	///* Issuer and subject certs: both the target since it is self signed,
	//* no request and no CRL
	//*/
	//X509V3_set_ctx(&ctx, root, cert, NULL, NULL, 0);
	//ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	//if (!ex)
	//	return 0;

	//X509_add_ext(cert, ex, -1);
	//X509_EXTENSION_free(ex);
	return 1;
}

X509_REQ *generate_X509_REQ()
{
	X509_REQ *ret = NULL;

	BIO          *outbio = NULL;
	EC_KEY       *eckey = NULL;
	X509_REQ     *x509_req = NULL;
	X509_NAME    *x509_name = NULL;
	EVP_PKEY		*pKey = NULL;

	long         lVer = 0L;
	const char   *szCountry = "CA";
	const char	 *szProvince = "HUNAN";
	const char	 *szCity = "ChangSha";
	const char	 *szOrganization = "AHdms";
	const char	 *szOrganizationUnit = "KFB";
	const char	 *szCommon = "localhost";

	/* ---------------------------------------------------------- *
	* Create the Input/Output BIO's.                             *
	* ---------------------------------------------------------- */
	outbio = BIO_new(BIO_s_file());
	outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

	// 1. generate EC key
	eckey = gen_EC_KEY();
	if (eckey == NULL)
	{
		BIO_printf(outbio, "Error generate EC_KEY\n");
		goto free_all;
	}
	
	// create x509_req object
	x509_req = X509_REQ_new();
	if (x509_req == NULL) {
		BIO_printf(outbio, "Error creating new X509_REQ object\n");
		goto free_all;
	}

	// 2. setup version number
	if (!X509_REQ_set_version(x509_req, lVer))
	{
		BIO_printf(outbio, "Error setting version to X509_REQ object\n");
		goto free_all;
	}

	char tmp_buf[512] = { '\0' };
	int tmpBufLen = sizeof(tmp_buf);
	//从CA证书中获取C,ST,O,OU

	// 3. set subject of x509 req
	x509_name = X509_REQ_get_subject_name(x509_req);
	//C
	if (!X509_NAME_add_entry_by_NID(x509_name, NID_countryName, MBSTRING_UTF8, (unsigned char *)szCountry, -1, -1, 0)) {
		BIO_printf(outbio, "Error adding entry [NID_countryName] to X509_REQ object\n");
		goto free_all;
	}
	//ST
	if (!X509_NAME_add_entry_by_NID(x509_name, NID_stateOrProvinceName, MBSTRING_UTF8, (unsigned char *)szProvince, -1, -1, 0)) {
		BIO_printf(outbio, "Error adding entry [NID_stateOrProvinceName] to X509_REQ object\n");
		goto free_all;
	}
	//L
	if (!X509_NAME_add_entry_by_NID(x509_name, NID_localityName, MBSTRING_UTF8, (unsigned char *)szCity, -1, -1, 0)) {
		BIO_printf(outbio, "Error adding entry [NID_localityName] to X509_REQ object\n");
		goto free_all;
	}
	//O
	if (!X509_NAME_add_entry_by_NID(x509_name, NID_organizationName, MBSTRING_UTF8, (unsigned char *)szOrganization, -1, -1, 0)) {
		BIO_printf(outbio, "Error adding entry [NID_organizationName] to X509_REQ object\n");
		goto free_all;
	}
	//OU   OU在openssl.conf中默认是可选的
	if (!X509_NAME_add_entry_by_NID(x509_name, NID_organizationalUnitName, MBSTRING_UTF8, (unsigned char *)szOrganizationUnit, -1, -1, 0)) {
		BIO_printf(outbio, "Error adding entry [NID_organizationalUnitName] to X509_REQ object\n");
		goto free_all;
	}
	//CN
	if (!X509_NAME_add_entry_by_NID(x509_name, NID_commonName, MBSTRING_UTF8, (unsigned char *)szCommon, -1, -1, 0)) {
		BIO_printf(outbio, "Error adding entry [NID_commonName] to X509_REQ object\n");
		goto free_all;
	}

	// 4. set public key of x509 req
	pKey = EVP_PKEY_new();
	if (!EVP_PKEY_assign_EC_KEY(pKey, eckey)) {
		BIO_printf(outbio, "Error EVP_PKEY_assign_EC_KEY operation\n");
		EC_KEY_free(eckey);
		goto free_all;
	}
	eckey = NULL;	// will be free eckey when EVP_PKEY_free(pKey)

	if (1 != (X509_REQ_set_pubkey(x509_req, pKey))){
		BIO_printf(outbio, "Error setting pubkey to X509_REQ object\n");
		goto free_all;
	}

	//加入一组可选的扩展属性
	//STACK_OF(X509_EXTENSION) *extlist = sk_X509_EXTENSION_new_null();
	//X509_EXTENSION*ext = X509V3_EXT_conf(NULL, NULL, REQ_SUBJECT_ALT_NAME, value); //生成扩展对象
	//sk_X509_EXTENSION_push(extlist, ext);
	//X509_REQ_add_extensions(x509_req, extlist); // 加入扩展项目。

	// 5. set sign key of x509 req
	int len = X509_REQ_sign(x509_req, pKey, EVP_sm3());	// return x509_req->signature->length
	if (len <= 0){
		unsigned long ulErr = ERR_get_error(); // 获取错误号
		char szErrMsg[1024] = { 0 };
		char *pTmp = NULL;
		pTmp = ERR_error_string(ulErr, szErrMsg); // 格式：error:errId:库:函数:原因
		printf("%s\n", szErrMsg);
		BIO_printf(outbio, "Error sign X509_REQ\n");
		goto free_all;
	}

	ret = x509_req;
	x509_req = NULL;

free_all:
	BIO_free_all(outbio);
	if (pKey)
	{
		EVP_PKEY_free(pKey);
	}
	if (x509_req)
	{
		X509_REQ_free(x509_req);
	}

	return ret;
}


X509 *generate_X509()
{
	X509 *ret = NULL;

	BIO               *outbio = NULL;
	X509_REQ         *certreq = NULL;

	ASN1_INTEGER *aserial = NULL;
	EVP_PKEY *ca_privkey, *req_pubkey;
	X509 *cacert = NULL;
	X509 *newcert = NULL;
	X509_NAME                    *name;
	EVP_MD                       const *digest = NULL;
	FILE                         *fp;
	long                         valid_secs = 31536000;

	/* ---------------------------------------------------------- *
	* Create the Input/Output BIO's.                             *
	* ---------------------------------------------------------- */
	outbio = BIO_new(BIO_s_file());
	outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

	/* ---------------------------------------------------------- *
	* These function calls initialize openssl for correct work.  *
	* ---------------------------------------------------------- */
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	/* -------------------------------------------------------- *
	* Load the signing CA Certificate file                    *
	* ---------------------------------------------------------*/
	if (!(fp = fopen(CACERT, "r"))) {
		BIO_printf(outbio, "Error reading CA cert file\n");
		return NULL;
	}

	if (!(cacert = PEM_read_X509(fp, NULL, NULL, NULL))) {
		BIO_printf(outbio, "Error loading CA cert into memory\n");
		fclose(fp);
		return NULL;
	}

	fclose(fp);

	/* -------------------------------------------------------- *
	* Import CA private key file for signing                   *
	* ---------------------------------------------------------*/
	ca_privkey = EVP_PKEY_new();

	if (!(fp = fopen(CAKEY, "r"))) {
		BIO_printf(outbio, "Error reading CA private key file\n");
		goto END;
	}

	if (!(ca_privkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL))) {
		BIO_printf(outbio, "Error importing key content from file\n");
		fclose(fp);
		goto END;
	}

	fclose(fp);

	/* -------------------------------------------------------- *
	* generate x509_req                                        *
	* ---------------------------------------------------------*/
	if (!(certreq = generate_X509_REQ()))
	{
		BIO_printf(outbio, "Error generate X509_REQ\n");
		goto END;
	}

	/* --------------------------------------------------------- *
	* Build Certificate with data from request                  *
	* ----------------------------------------------------------*/
	if (!(newcert = X509_new())) {
		BIO_printf(outbio, "Error creating new X509 object\n");
		goto END;
	}

	if (X509_set_version(newcert, 2) != 1) {
		BIO_printf(outbio, "Error setting certificate version\n");
		goto END;
	}

	/* --------------------------------------------------------- *
	* set the certificate serial number here                    *
	* If there is a problem, the value defaults to '0'          *
	* ----------------------------------------------------------*/
	aserial = ASN1_INTEGER_new();
	ASN1_INTEGER_set(aserial, 0);

	if (!X509_set_serialNumber(newcert, aserial)) {
		BIO_printf(outbio, "Error setting serial number of the certificate\n");
		goto END;
	}

	/* --------------------------------------------------------- *
	* Extract the subject name from the request                 *
	* ----------------------------------------------------------*/
	if (!(name = X509_REQ_get_subject_name(certreq)))
		BIO_printf(outbio, "Error getting subject from cert request\n");

	/* --------------------------------------------------------- *
	* Set the new certificate subject name                      *
	* ----------------------------------------------------------*/
	if (X509_set_subject_name(newcert, name) != 1) {
		BIO_printf(outbio, "Error setting subject name of certificate\n");
		goto END;
	}

	/* --------------------------------------------------------- *
	* Extract the subject name from the signing CA cert         *
	* ----------------------------------------------------------*/
	if (!(name = X509_get_subject_name(cacert))) {
		BIO_printf(outbio, "Error getting subject from CA certificate\n");
		goto END;
	}

	/* --------------------------------------------------------- *
	* Set the new certificate issuer name                       *
	* ----------------------------------------------------------*/
	if (X509_set_issuer_name(newcert, name) != 1) {
		BIO_printf(outbio, "Error setting issuer name of certificate\n");
		goto END;
	}

	/* --------------------------------------------------------- *
	* Extract the public key data from the request              *
	* ----------------------------------------------------------*/
	if (!(req_pubkey = X509_REQ_get_pubkey(certreq))) {
		BIO_printf(outbio, "Error unpacking public key from request\n");
		goto END;
	}

	/* --------------------------------------------------------- *
	* Optionally: Use the public key to verify the signature    *
	* ----------------------------------------------------------*/
	if (X509_REQ_verify(certreq, req_pubkey) != 1) {
		BIO_printf(outbio, "Error verifying signature on request\n");
		goto END;
	}

	/* --------------------------------------------------------- *
	* Set the new certificate public key                        *
	* ----------------------------------------------------------*/
	if (X509_set_pubkey(newcert, req_pubkey) != 1) {
		BIO_printf(outbio, "Error setting public key of certificate\n");
		goto END;
	}

	/* ---------------------------------------------------------- *
	* Set X509V3 start date (now) and expiration date (+365 days)*
	* -----------------------------------------------------------*/
	if (!(X509_gmtime_adj(X509_get_notBefore(newcert), 0))) {
		BIO_printf(outbio, "Error setting start time\n");
		goto END;
	}

	if (!(X509_gmtime_adj(X509_get_notAfter(newcert), valid_secs))) {
		BIO_printf(outbio, "Error setting expiration time\n");
		goto END;
	}

	/* ----------------------------------------------------------- *
	* Add X509V3 extensions                                       *
	* ------------------------------------------------------------*/
	//使用者密钥标识
	Add_X509V3_extensions(newcert, cacert, NID_subject_key_identifier, "hash");
	//颁发者密钥标识
	Add_X509V3_extensions(newcert, cacert, NID_authority_key_identifier, "keyid,issuer");
	//密钥用途
	Add_X509V3_extensions(newcert, cacert, NID_key_usage, "Digital Signature, Key Encipherment, Data Encipherment");
	//增强型密钥用途
	Add_X509V3_extensions(newcert, cacert, NID_ext_key_usage, "critical,clientAuth");

	/* ----------------------------------------------------------- *
	* Set digest type, sign new certificate with CA's private key *
	* ------------------------------------------------------------*/
	digest = EVP_sm3();

	if (!X509_sign(newcert, ca_privkey, digest)) {
		BIO_printf(outbio, "Error signing the new certificate\n");
		goto END;
	}

	/* ------------------------------------------------------------ *
	*  print the certificate                                       *
	* -------------------------------------------------------------*/
	if (!PEM_write_bio_X509(outbio, newcert)) {
		BIO_printf(outbio, "Error printing the signed certificate\n");
	}

	ret = newcert;
	newcert = NULL;

END:
	/* ---------------------------------------------------------- *
	* Free up all structures                                     *
	* ---------------------------------------------------------- */
	EVP_PKEY_free(ca_privkey);
	X509_REQ_free(certreq);
	ASN1_INTEGER_free(aserial);
	X509_free(newcert);

	BIO_free_all(outbio);

	return ret;
}

int main(int argc, void* argv[])
{
	X509 *cert = generate_X509();
	if (cert != NULL)
	{
		BIO *out = NULL;
		int ret = 0;

		out = BIO_new_file("./newcert.cer", "w");
		ret = PEM_write_bio_X509(out, cert);
		
		BIO_free_all(out);
	}
	
	getchar();
	return 0;
}


