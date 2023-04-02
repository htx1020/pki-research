#!/bin/bash

dir=./tmp
key=$dir/pri.pem
csr=$dir/one.csr
cer=$dir/one.pem
runPATH=$PWD
caPATH=../ca
BakTime=$(date "+%Y%m%d_%H%M")

mkdir -p $dir
rm $key $csr $cer

echo "生成RSA密钥..."
openssl genrsa -out $key

echo "生成RSA证书请求..."
openssl req -new \
	-key $key \
	-out $csr \
	-subj "/C=CN/ST=BJ/L=CY/O=AICC/OU=dev/CN=china-aicc.com/emailAddress=cas@china-aicc.com"
#-subj "/C=CN/ST=BJ/L=CY/O=AICC/OU=dev/CN=china-aicc.com $BakTime/emailAddress=cas@china-aicc.com"

cd $caPATH
./req2cert.sh $runPATH/$csr $runPATH/$cer
cd $runPATH
