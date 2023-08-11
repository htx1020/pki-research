#pragma once

#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
  const char *country;
  const char *province;
  const char *city;
  const char *organization;
  const char *organizationUnit;
  const char *common;
} CertSubject;

int TestCertReq();

#ifdef __cplusplus
}
#endif
