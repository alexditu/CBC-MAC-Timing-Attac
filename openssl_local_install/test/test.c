
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

#include <openssl/aes.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>



void print_hex(char *, char *, int);
/*
	SHA256:
	some parts are implemented in: crypto/sha/sha256.c
	see md32_common.h also: crypto/md32_common.h 
*/
void test_sha256() {
	unsigned char *d;
   	unsigned long n;
	unsigned char *md;

	md = malloc(SHA256_DIGEST_LENGTH * sizeof(char));
	d = (unsigned char *) "ana are mere";
	n = (unsigned long) strlen(d);

	SHA256(d, n, md);
	printf("Digest is:\n");
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		printf("%.2x ", md[i]);
	}
	printf("\n");

	free(md);
}

void test_aes_enc_cbc() {
	/* AES key for Encryption and Decryption */
	// const static unsigned char aes_key[]={0x41,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
	const static unsigned char aes_key[]={0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41};
	// const static unsigned char aes_key[]= "123456789012345";

	/* Input data to encrypt */
	unsigned char aes_input[]={0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41};
	// unsigned char aes_input[]="123456";
	
	/* Init vector */
	unsigned char iv[AES_BLOCK_SIZE];
	memset(iv, 0x00, AES_BLOCK_SIZE);
	
	/* Buffers for Encryption and Decryption */
	unsigned char enc_out[sizeof(aes_input)];
	unsigned char dec_out[sizeof(aes_input)];
	
	/* AES-128 bit CBC Encryption */
	AES_KEY enc_key, dec_key;
	AES_set_encrypt_key(aes_key, sizeof(aes_key)*8, &enc_key);
	AES_cbc_encrypt(aes_input, enc_out, sizeof(aes_input), &enc_key, iv, AES_ENCRYPT);

	print_hex("cbc enc:", enc_out, sizeof(aes_input));

	/* AES-128 bit CBC Decryption */
	memset(iv, 0x00, AES_BLOCK_SIZE); // don't forget to set iv vector again, else you can't decrypt data properly
	AES_set_decrypt_key(aes_key, sizeof(aes_key)*8, &dec_key); // Size of key is in bits
	AES_cbc_encrypt(enc_out, dec_out, sizeof(aes_input), &dec_key, iv, AES_DECRYPT);

	
	print_hex("cbc dec:", dec_out, sizeof(aes_input));
}

void test_aes_ecb_enc() {
/*
void AES_ecb_encrypt(const unsigned char *in, unsigned char *out,
	const AES_KEY *key, const int enc);
*/
	/* AES key for Encryption and Decryption */
	// const static unsigned char aes_key[]={0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
	const static unsigned char aes_key[]={0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41};

	/* Input data to encrypt */
	// unsigned char aes_input[]={0x0,0x1,0x2,0x3,0x4,0x5};
	unsigned char aes_input[]={0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41};

	/* Buffers for Encryption and Decryption */
	unsigned char enc_out[sizeof(aes_input)];
	unsigned char dec_out[sizeof(aes_input)];

	AES_KEY encryptKey, dec_key;

    AES_set_encrypt_key(aes_key, sizeof(aes_key)*8, &encryptKey);
    AES_ecb_encrypt(aes_input, enc_out, &encryptKey, AES_ENCRYPT);

    print_hex("ecb enc:", enc_out, sizeof(aes_input));

    AES_set_decrypt_key(aes_key, sizeof(aes_key)*8, &dec_key); // Size of key is in bits
	AES_ecb_encrypt(enc_out, dec_out, &dec_key, AES_DECRYPT);
	print_hex("ecb dec:", dec_out, sizeof(aes_input));
}

void print_hex(char *msg, char *d, int len) {
	unsigned char *data = (unsigned char *) d;
	printf("%s\n", msg);
	for (int i = 0; i < len; i++) {
		printf("%.2x ", data[i]);
	}
	printf("\n");
}


// void test_evp() {
// 	int key_length, iv_length, data_length;

// 	/* AES key for Encryption and Decryption */
// 	// unsigned char key[]={0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
// 	unsigned char key[]={0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41};

// 	// unsigned char key[]= "1234567890123456";

// 	/* Input data to encrypt */
// 	unsigned char data[]={0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41};
// 	// unsigned char data[]= "1234567890123456";

// 	/* Init vector */
// 	unsigned char iv[AES_BLOCK_SIZE];
// 	memset(iv, 0x00, AES_BLOCK_SIZE);


// 	key_length = sizeof(key);
// 	iv_length = sizeof(iv);
// 	data_length = sizeof(data);

// 	// EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
// 	// EVP_CIPHER_CTX_init(ctx);

// 	const EVP_CIPHER *cipher;
// 	int cipher_key_length, cipher_iv_length;
// 	cipher = EVP_aes_128_ecb();
// 	cipher_key_length = EVP_CIPHER_key_length(cipher);
// 	cipher_iv_length = EVP_CIPHER_iv_length(cipher);

// 	printf("key: %d, iv: %d\n", cipher_key_length, cipher_iv_length);

// 	EVP_CIPHER_CTX ctx;
// 	EVP_CIPHER_CTX_init(&ctx);
// 	EVP_EncryptInit_ex(&ctx, cipher, NULL, (unsigned char *)key, (unsigned char *)iv);


// 	int cipher_length, final_length;
// 	unsigned char *ciphertext;
// 	cipher_length = data_length + EVP_MAX_BLOCK_LENGTH;
// 	ciphertext = (unsigned char *)malloc(cipher_length);

// 	EVP_EncryptUpdate(&ctx, ciphertext, &cipher_length, (unsigned char *)data, data_length);
// 	EVP_EncryptFinal_ex(&ctx, ciphertext + cipher_length, &final_length);

// 	printf("enc len: %d\n", cipher_length);
// 	printf("final_length: %d\n", final_length);
// 	print_hex("enc:", ciphertext, cipher_length + final_length);

// 	free(ciphertext);
// 	EVP_CIPHER_CTX_cleanup(&ctx);

// }


int main(int argc, char **argv) {
	test_sha256();

	test_aes_enc_cbc();

	test_aes_ecb_enc();

	// test_evp();

	return 0;
}	

