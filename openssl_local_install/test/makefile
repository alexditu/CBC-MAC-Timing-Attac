LIBCRYPTO=../lib/libcrypto.so
INCLUDE=-I../include
CFLAGS=-g -std=c99 -Wall

build:
	gcc ${INCLUDE} ${CFLAGS} test.c ${LIBCRYPTO} -o test.out

clean:
	rm test.out
