#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

#include <openssl/aes.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>


unsigned char * aes_cbc_mac(unsigned char *k, int k_len, unsigned char *m, int m_len);
void print_hex(char *, unsigned char *, int);
unsigned char * concat(unsigned char *s1, int s1_len, unsigned char *s2, int s2_len);