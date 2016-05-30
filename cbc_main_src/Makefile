LIBCRYPTO=-L../openssl_local_install/lib
#LIBCRYPTO=-L../openssl_local_install/lib/
#LD_LIBRARY_PATH=../openssl_local_install/lib/

INCLUDE=-I../openssl_local_install/include
CFLAGS=-g -std=c99 -Wall

all: clean run

build: aes_cbc_mac.o cbc_main.o
	gcc ${CFLAGS} ${INCLUDE} ${LIBCRYPTO} aes_cbc_mac.o cbc_main.o -o cbc_main -lcrypto

cbc_main.o:
	gcc -c ${CFLAGS} ${INCLUDE} cbc_main.c

aes_cbc_mac.o:
	gcc -c ${CFLAGS} ${INCLUDE} aes_cbc_mac.c 

run: build
	taskset -c 5 ./cbc_main

clean:
	rm -rf cbc_main *.out *.o
