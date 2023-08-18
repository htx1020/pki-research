#!/bin/bash
mkdir -p certs/subca
mkdir certs/subca/{newcerts,db,private,crl}
touch certs/subca/crl/crlnumber
echo 00 > certs/subca/crl/crlnumber
touch certs/subca/db/{index,serial}
echo 00 > certs/subca/db/serial

# 生成SM2私钥
/opt/tongsuo/bin/tongsuo genpkey -algorithm "ec" -out certs/subca/sm2.key -pkeyopt ec_paramgen_curve:sm2

# 生成CSR
/opt/tongsuo/bin/tongsuo req -batch -config subca.cnf -key certs/subca/sm2.key -new -nodes -out certs/subca/sm2.csr -sm3 -subj "/C=AB/ST=CD/L=EF/O=GH/OU=IJ/CN=SUBCA SM2"

# 使用CA证书签发中间CA证书
/opt/tongsuo/bin/tongsuo ca -batch -cert certs/ca/sm2.crt -config subca.cnf -days 365 -extensions "v3_intermediate_ca" -in certs/subca/sm2.csr -keyfile certs/ca/sm2.key -md sm3 -notext -out certs/subca/sm2.crt

