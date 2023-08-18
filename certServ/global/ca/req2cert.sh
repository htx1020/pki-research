#!/bin/bash
if [ $# != 2 ]
then
    echo "lack parameter"
    exit
fi

in=$1
out=$2

openssl ca \
    -config ./openssl.cnf \
    -name CA_default \
    -in $in -out $out \
    -cert ./demoCA/cacert.pem \
    -keyfile ./demoCA/private/cakey.pem 

    #-policy policy_anything \
