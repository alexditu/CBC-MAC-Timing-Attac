#!/bin/bash

pushd .
cd ../intel_aes_lib
./mk_lnx_lib64.sh
popd

out=bin/cbc_main
mkdir bin
rm $out

LIBCRYPTO=-L../../openssl_local_install/lib
INCLUDE=-I../../openssl_local_install/include
lvl= 
lvl="-O0 -Wall"
yasm=../yasm/yasm

mkdir -p obj/x64

gcc -g $lvl $opt -o $out src/cbc_main.c src/timing.c src/my_getopt.c ${LIBCRYPTO} ${INCLUDE} -Isrc -I../intel_aes_lib/include ../intel_aes_lib/lib/x64/intel_aes64.a -lcrypto

echo created $out
