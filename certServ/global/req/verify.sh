#!/bin/bash
dir=./tmp
key=$dir/pri.pem
cer=$dir/one.pem
p12=$dir/one.p12.pfx
ext=$dir/extracted.pem
runPATH=$PWD
caPATH=../ca

openssl x509 -in $cer -text
openssl verify \
	-CAfile $caPATH/demoCA/cacert.pem \
	-verbose -purpose sslclient $runPATH/$cer

echo "--------------------------------------"
echo "--------------------------------------"
echo "--------------------------------------"

set -x
openssl pkcs12 \
	-export \
	-clcerts \
	-inkey $key \
	-in $cer \
	-out $p12

openssl pkcs12 \
	-in $p12 \
	-out $ext
