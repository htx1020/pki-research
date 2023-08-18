#!/bin/bash
mkdir -p certs/ca
mkdir certs/ca/{newcerts,db,private,crl}
touch certs/ca/crl/crlnumber
echo 00 >certs/ca/crl/crlnumber
touch certs/ca/db/{index,serial}
echo 00 >certs/ca/db/serial

# 生成SM2私钥
/opt/tongsuo/bin/tongsuo genpkey -algorithm ec -out certs/ca/sm2.key -pkeyopt ec_paramgen_curve:sm2

# 生成CSR
/opt/tongsuo/bin/tongsuo req -batch -config ca.cnf -key certs/ca/sm2.key -new -nodes -out certs/ca/sm2.csr -sm3 -subj "/C=AB/ST=CD/L=EF/O=GH/OU=IJ/CN=CA SM2"

# 自签发CA证书
/opt/tongsuo/bin/tongsuo ca -batch -config ca.cnf -days 365 -extensions v3_ca -in certs/ca/sm2.csr -keyfile certs/ca/sm2.key -md sm3 -notext -out certs/ca/sm2.crt -selfsign
