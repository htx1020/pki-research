#!/bin/bash
echo "is re-build, yes or no"
read isRebuild
if [ $isRebuild = "yes" ]
then
    rm ./demoCA -r
    mkdir -p ./demoCA/{private,newcerts}
    touch ./demoCA/index.txt
    echo 01 > ./demoCA/serial
    echo "unique_subject = no " > ./demoCA/index.txt.attr

    pri=demoCA/private/cakey.pem
    pub=demoCA/private/cakey.pub.pem
    req=demoCA/careq.pem
    cert=demoCA/cacert.pem
    
    openssl genrsa -out $pri 2048
    #openssl rsa -in $pri -pubout -out $pub
    openssl req -out $cert -new -x509 -days 3650 -key $pri  \
    -subj "/C=CN/ST=BJ/L=CY/O=AICC/OU=dev/CN=china-aicc.com/emailAddress=ca@china-aicc.com"
else
    echo "..."
fi


