#!/bin/bash
subjectCA="/C=CN/ST=BJ/L=Beijing/O=AICC/OU=rel/CN=china-aicc-datasec/emailAddress=ca@china-aicc.com"
rootDir=$PWD
mkdir ca
cd ca
# 生成CA密钥 
openssl genrsa -out ca.key 2048  

# 生成CA证书签名请求
openssl req -new -key ca.key -subj "$subjectCA" -out ca.csr  

# 自签CA证书,获得ca.crt
openssl x509 -req -days 365 -in ca.csr -signkey ca.key -out ca.crt

cd $rootDir

genUserCert() {
    name=$1
    mkdir user
    cd user
    subjectUSR="/C=CN/ST=BJ/L=Beijing/O=${name}/OU=dev/CN=china-aicc-datasec/emailAddress=user@china-aicc.com"
    # 生成服务器密钥  
    openssl genrsa -out user.key 2048
    
    # 生成服务器证书签名请求
    openssl req -new -key user.key -subj "$subjectUSR" -out user.csr  
    
    # 使用CA签发服务器证书,获得server.crt
    openssl x509 -req -in user.csr -CA ../ca/ca.crt -CAkey ../ca/ca.key -CAcreateserial -out user.crt
    cd -
}

genUserCert user1
openssl pkcs12 -export -in ./user/user.crt -inkey ./user/user.key -certfile ./ca/ca.crt -out user1_cert.p12 -password pass:1234
genUserCert user2
openssl pkcs12 -export -in ./user/user.crt -inkey ./user/user.key -certfile ./ca/ca.crt -out user2_cert.p12 -password pass:1234
genUserCert user3
openssl pkcs12 -export -in ./user/user.crt -inkey ./user/user.key -certfile ./ca/ca.crt -out user3_cert.p12 -password pass:1234



exit

