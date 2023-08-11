#pragma once
#ifdef __cplusplus
extern "C" {
#endif

int GenCertificate(const char *req_file, const char *prikey, const char *cert);
int TestCertGen();

#ifdef __cplusplus
}
#endif
