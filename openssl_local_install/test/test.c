
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

#include <openssl/aes.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>



void print_hex(char *, char *, int);
unsigned char * concat(unsigned char *s1, int s1_len, unsigned char *s2, int s2_len);


/*
	SHA256:
	some parts are implemented in: crypto/sha/sha256.c
	see md32_common.h also: crypto/md32_common.h 
*/

void sha256(unsigned char *d, unsigned long n, unsigned char **md) {
	*md = malloc(SHA256_DIGEST_LENGTH * sizeof(char));
	SHA256(d, n, *md);
}

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

// aes_enc_cbc(k1, m, 16 * '\x00')
unsigned char * aes_enc_cbc(unsigned char *aes_key, int key_len, unsigned char *aes_input, int input_len) {
	/* Init vector */
	unsigned char iv[AES_BLOCK_SIZE];
	memset(iv, 0x00, AES_BLOCK_SIZE);
	
	/* Buffers for Encryption and Decryption */
	unsigned char *enc_out = malloc(input_len * sizeof(unsigned char));
	unsigned char *dec_out = malloc(input_len * sizeof(unsigned char));
	
	/* AES-128 bit CBC Encryption */
	AES_KEY enc_key, dec_key;
	AES_set_encrypt_key(aes_key, key_len * 8, &enc_key);
	AES_cbc_encrypt(aes_input, enc_out, input_len, &enc_key, iv, AES_ENCRYPT);

	print_hex("cbc enc:", enc_out, input_len);

	/* AES-128 bit CBC Decryption */
	memset(iv, 0x00, AES_BLOCK_SIZE); // don't forget to set iv vector again, else you can't decrypt data properly
	AES_set_decrypt_key(aes_key, key_len * 8, &dec_key); // Size of key is in bits
	AES_cbc_encrypt(enc_out, dec_out, input_len, &dec_key, iv, AES_DECRYPT);

	
	print_hex("cbc dec:", dec_out, input_len);

	free(dec_out);

	return enc_out;
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

unsigned char * aes_ecb_enc(unsigned char *aes_key, int key_len, unsigned char *aes_input, int input_len) {
	/* Buffers for Encryption and Decryption */
	unsigned char *enc_out = malloc(input_len * sizeof(unsigned char));
	unsigned char *dec_out = malloc(input_len * sizeof(unsigned char));

	AES_KEY encryptKey, dec_key;

    AES_set_encrypt_key(aes_key, key_len * 8, &encryptKey);
    AES_ecb_encrypt(aes_input, enc_out, &encryptKey, AES_ENCRYPT);

    print_hex("ecb enc:", enc_out, input_len);

    AES_set_decrypt_key(aes_key, key_len * 8, &dec_key); // Size of key is in bits
	AES_ecb_encrypt(enc_out, dec_out, &dec_key, AES_DECRYPT);
	print_hex("ecb dec:", dec_out, input_len);

	free(dec_out);
	return enc_out;
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

unsigned char * ljust(unsigned char *data, int len) {
	unsigned char * justified = malloc(16 * sizeof(unsigned char));

	// size_t n = sizeof(data);
	printf("len: %d\n", len);
	if (len > 16) {
		perror("Data must be less then or equal to 16 bytes!");
		return NULL;
	}

	int i = 0;
	for (i = 0; i < len; i++) {
		justified[i] = data[i];
	}

	/* fill remaining size with space: 0x20 */
	while (i < 16) {
		justified[i] = 0x20;
		i++;
	}

	return justified;
}

void test_ljust() {
	unsigned char tmp[] = {0x41, 0x42, 0x43, 0x41, 0x42, 0x43};
	print_hex("justified:", ljust(tmp, sizeof(tmp)), 16);
}

unsigned char * aes_cbc_mac(unsigned char *k, int k_len, unsigned char *m, int m_len) {
	unsigned char *ext_key = NULL;
	unsigned char *k1 = NULL;
	unsigned char *k2 = NULL;
	unsigned char *res = NULL;
	unsigned char *res_1 = NULL;
	unsigned char *res_2 = NULL;
	unsigned char *key = ljust(k, k_len);
	unsigned char *msg = ljust(m, m_len);



	// # Derive the keys for raw-CBC and for the final tag
 //    res = SHA256.new(k + "CBC MAC keys").digest()
 //    k1 = res[0:16]
 //    k2 = res[16:32]

	print_hex("k", key, 16);

	//SHA256(d, n, md);
	ext_key = concat(key, 16, "CBC MAC keys", strlen("CBC MAC keys"));
	sha256(ext_key, 16 + strlen("CBC MAC keys"), &res);
	print_hex("sha256:", res, 32);

	k1 = res; // use 16 bytes
	k2 = res + 16;

	// res_1 = aes_enc_cbc(k1, m, 16 * '\x00')
	print_hex("k1:", k1, 16);
	print_hex("msg:", msg, 16);

	res_1 = aes_enc_cbc(k1, 16, msg, 16);
	print_hex("res_1", res_1, 16);


	// # 2 - Perform another AES encryption (simple, without CBC) on the last block from #1 using k2
 //    res_2 = aes_enc(k2, res_1[-16:])
 //    t = res_2

	res_2 = aes_ecb_enc(k2, 16, res_1, 16);
	print_hex("res_2", res_2, 16);

	free(ext_key);
	free(key);
	free(msg);
	free(res);
	free(res_1);
	/* DO this in the calling func! */
	// free(res_2);
	return res_2;
}

unsigned char * concat(unsigned char *s1, int s1_len, unsigned char *s2, int s2_len) {
	unsigned char *s3 = malloc((s1_len + s2_len) * sizeof(char));
	memcpy(s3, s1, s1_len);
	memcpy(s3 + s1_len, s2, s2_len);
	return s3;
}

void test_aes_cbc_mac() {
	unsigned char m[] = "ana are";
	unsigned char k[] = "mere";

	unsigned char *mac = NULL;

	mac = aes_cbc_mac(k, strlen(k), m, strlen(m));
	free(mac);
}


int main(int argc, char **argv) {
	test_aes_cbc_mac();

	// printf("\n\n");
	// test_sha256();

	// test_aes_enc_cbc();

	// test_aes_ecb_enc();

	// // test_evp();
	// test_ljust();


	return 0;
}	

