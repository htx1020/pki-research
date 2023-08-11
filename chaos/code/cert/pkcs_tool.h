#pragma once

int p12FileParse(const char *file, const char *password, unsigned char *derCert,
                 unsigned int *derCertLen, unsigned char *derPkey,
                 unsigned int *derPkeyLen);

