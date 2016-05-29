LIBCRYPTO=../lib/libcrypto.so
INCLUDE=-I../include
CFLAGS=-g -std=c99 -Wall

build:
	gcc ${INCLUDE} ${CFLAGS} aes_cbc_mac.c ${LIBCRYPTO} -o aes_cbc_mac.out

clean:
	rm *.out
