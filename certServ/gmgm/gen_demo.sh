#!/bin/bash
mkdir tmp/ -p
gcc client.c  -I/opt/tongsuo/include/ -L/opt/tongsuo/lib64/ -lssl -lcrypto -Wl,-rpath=/opt/tongsuo/lib64 -o ./tmp/client
gcc server.c  -I/opt/tongsuo/include/ -L/opt/tongsuo/lib64/ -lssl -lcrypto -Wl,-rpath=/opt/tongsuo/lib64 -o ./tmp/server

 #./tmp/client 127.0.0.1:1443
 #./tmp/server 127.0.0.1:1443

