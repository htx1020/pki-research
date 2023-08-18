#!/bin/bash
mkdir certs/server

# 生成SM2签名私钥
/opt/tongsuo/bin/tongsuo genpkey -algorithm ec -out certs/server/sm2_sign.key -pkeyopt "ec_paramgen_curve:sm2"

# 生成CSR
/opt/tongsuo/bin/tongsuo req -batch -config subca.cnf -key certs/server/sm2_sign.key -new -nodes -out certs/server/sm2_sign.csr -sm3 -subj "/C=AB/ST=CD/L=EF/O=GH/OU=IJ/CN=SERVER Sign SM2"

# 使用中间CA证书签发签名证书
/opt/tongsuo/bin/tongsuo ca -batch -cert certs/subca/sm2.crt -config subca.cnf -days 365 -extensions server_sign_req -in certs/server/sm2_sign.csr -keyfile certs/subca/sm2.key -md sm3 -notext -out certs/server/sm2_sign.crt



# 生成SM2加密私钥
/opt/tongsuo/bin/tongsuo genpkey -algorithm ec -out certs/server/sm2_enc.key -pkeyopt "ec_paramgen_curve:sm2"

# 生成CSR
/opt/tongsuo/bin/tongsuo req -batch -config subca.cnf -key certs/server/sm2_enc.key -new -nodes -out certs/server/sm2_enc.csr -sm3 -subj "/C=AB/ST=CD/L=EF/O=GH/OU=IJ/CN=SERVER Enc SM2"

# 使用中间CA证书签发加密证书
/opt/tongsuo/bin/tongsuo ca -batch -cert certs/subca/sm2.crt -config subca.cnf -days 365 -extensions "server_enc_req" -in certs/server/sm2_enc.csr -keyfile certs/subca/sm2.key -md sm3 -notext -out certs/server/sm2_enc.crt


/opt/tongsuo/bin/tongsuo pkey -in certs/server/sm2_sign.key -text -noout
