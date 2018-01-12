#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memcpy */
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#ifdef LINUX
#define MMAP_SEQ MAP_PRIVATE|MAP_POPULATE
#else
#define MMAP_SEQ MAP_PRIVATE
#endif

/* NOTE: since we use counter mode, we don't need padding, as the
 * ciphertext length will be the same as that of the plaintext.
 * Here's the message format we'll use for the ciphertext:
 * +------------+--------------------+-------------------------------+
 * | 16 byte IV | C = AES(plaintext) | HMAC(C) (32 bytes for SHA256) |
 * +------------+--------------------+-------------------------------+
 * */

/* we'll use hmac with sha256, which produces 32 byte output */
#define HM_LEN 32
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
/* need to make sure KDF is orthogonal to other hash functions, like
 * the one used in the KDF, so we use hmac with a key. */

#define IV_LEN 16
#define HM_512_LEN 64

int ske_keyGen(SKE_KEY* K, unsigned char* entropy, size_t entLen)
{
	/* TODO: write this.  If entropy is given, apply a KDF to it to get
	 * the keys (something like HMAC-SHA512 with KDF_KEY will work).
	 * If entropy is null, just get a random key (you can use the PRF). */

	unsigned char key[HM_512_LEN] = {0};
	unsigned int keyLen = HM_512_LEN;

	if (entropy != NULL) {		
		// If the entropy buffer is supplied, the KDF should be applied to it to derive the key.
		HMAC(EVP_sha512(), KDF_KEY, HM_LEN, entropy, entLen, key, &keyLen);
	} else {
		randBytes(key, HM_512_LEN);
	}

	memcpy(K->hmacKey, key, HM_LEN);
	memcpy(K->aesKey, &key[HM_LEN], HM_LEN);

	return keyLen;
}
size_t ske_getOutputLen(size_t inputLen)
{
	return AES_BLOCK_SIZE + inputLen + HM_LEN;
}

size_t ske_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K, unsigned char* IV)
{
	/* TODO: finish writing this.  Look at ctr_example() in aes-example.c
	 * for a hint.  Also, be sure to setup a random IV if none was given.
	 * You can assume outBuf has enough space for the result. */

	if (IV == NULL) {
		IV = malloc(IV_LEN);
		assert(IV != NULL);
		memset(IV, 0, IV_LEN);
		randBytes(IV, IV_LEN);
	}

	// Encrypt using AES
	int aesOutputLen = len; // since we use AES counter mode ciphertext length will equal plaintext length
	unsigned char *aesOutput = malloc(aesOutputLen);
	assert(aesOutput != NULL);
	memset(aesOutput, 0, aesOutputLen);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), 0, K->aesKey, IV)) {
		ERR_print_errors_fp(stderr);
	}

	if (!EVP_EncryptUpdate(ctx, aesOutput, &aesOutputLen, inBuf, len)) {
		ERR_print_errors_fp(stderr);
	}

	EVP_CIPHER_CTX_free(ctx);

	// Make our MAC using HMAC
	unsigned int hmacOutputLen = HM_LEN;
	unsigned char *hmacOutput = malloc(hmacOutputLen);
	assert(hmacOutput != NULL);

	HMAC(EVP_sha256(), K->hmacKey, KLEN_SKE, aesOutput, aesOutputLen, hmacOutput, &hmacOutputLen);

	// xor the IV into the HMAC output so we can validate the provided IV at decryption
	int j;
	for (j = 0; j < IV_LEN; j++) {
		hmacOutput[j] ^= IV[j];
	}

	// Copy the IV, the AES output, and the MAC into the ciphertext buffer in that order.
	unsigned char *ciphertext = malloc(ske_getOutputLen(len)); 
	assert(ciphertext != NULL);

	memcpy(ciphertext, IV, IV_LEN);
	memcpy(&ciphertext[IV_LEN], aesOutput, aesOutputLen);
	memcpy(&ciphertext[IV_LEN + aesOutputLen], hmacOutput, hmacOutputLen);

	free(aesOutput);
	free(hmacOutput);

	memcpy(outBuf, ciphertext, ske_getOutputLen(len));

	return ske_getOutputLen(len);
}
size_t ske_encrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, unsigned char* IV, size_t offset_out)
{
	int inputFd = open(fnin, O_RDWR);
	int outputFd = open(fnout, O_CREAT | O_RDWR, 0600);

	if (inputFd < 0 || outputFd < 0) {
		fprintf(stderr, "Error opening file, errno %d\n", errno);
		return -1;
	}

	size_t inputLen = lseek(inputFd, 0, SEEK_END); // Get the size of the input file
	lseek(inputFd, 0, SEEK_SET);

	size_t outputLen = ske_getOutputLen(inputLen);
	size_t oldOutfileLen = lseek(outputFd, 0, SEEK_END); // Get the current size of the output file
	lseek(outputFd, 0, SEEK_SET);

	if (offset_out == 0) {
		// Don't allow for the old output file contents
		oldOutfileLen = 0;
	}

	// Size the output file with room for our new encoding.
	ftruncate(outputFd, outputLen + oldOutfileLen);

	// Set up our memory mapped regions
	void *input = mmap(NULL, inputLen, PROT_READ | PROT_WRITE, MAP_SHARED, inputFd, 0);

	void *output = mmap(NULL, outputLen + oldOutfileLen, PROT_READ | PROT_WRITE, MAP_SHARED, outputFd, 0);

	if (input == MAP_FAILED || output == MAP_FAILED) {
		fprintf(stderr, "Error mapping file for encryption, errno %d\n", errno);
		return -1;
	}

	// Do the encryption with our mmapped regions
	size_t encryptedLen = ske_encrypt(&((unsigned char *)output)[offset_out], input, inputLen, K, IV);

	// Save memory writes to file
	msync(output, outputLen, MS_SYNC);

	// Tidy up
	munmap(input, inputLen);
	munmap(output, outputLen);
	close(inputFd);
	close(outputFd);

	return encryptedLen;
}
size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K)
{
	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */

	unsigned int cSize = len - IV_LEN - HM_LEN;
	if (cSize <= 0) {
		return -1;
	}

	// Split into IV | C | MAC
	unsigned char IV[IV_LEN] = {0};
	unsigned char *C = malloc(cSize);
	assert(C != NULL);

	unsigned char MAC[HM_LEN] = {0};
	
	memset(C, 0, cSize);
	memcpy(IV, inBuf, IV_LEN);
	memcpy(C, &inBuf[IV_LEN], cSize);
	memcpy(MAC, &inBuf[IV_LEN + cSize], HM_LEN);

	// Check that HMACing C xor'd with the provided IV results in the MAC we got passed
	unsigned int hmacOutputLen = HM_LEN;
	unsigned char *hmacOutput = malloc(hmacOutputLen);
	assert(hmacOutput != NULL);

	HMAC(EVP_sha256(), K->hmacKey, KLEN_SKE, C, cSize, hmacOutput, &hmacOutputLen);

	int j;
	for (j = 0; j < IV_LEN; j++) {
		hmacOutput[j] ^= IV[j];
	}

	if (hmacOutputLen != HM_LEN || memcmp(MAC, hmacOutput, hmacOutputLen) != 0) {
		return -1;
	}

	// Decrypt C with AES
	int decryptedLen = cSize;
	unsigned char *decrypted = malloc(decryptedLen);
	assert(decrypted != NULL);

	memset(decrypted, 0, decryptedLen);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), 0, K->aesKey, IV)) {
		ERR_print_errors_fp(stderr);
	}

	if (!EVP_DecryptUpdate(ctx, decrypted, &decryptedLen, C, cSize)) {
		ERR_print_errors_fp(stderr);
	}

	EVP_CIPHER_CTX_free(ctx);

	memcpy(outBuf, decrypted, decryptedLen);
	free(decrypted);
	return decryptedLen;
}
size_t ske_decrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, size_t offset_in)
{
	int inputFd = open(fnin, O_RDWR);
	int outputFd = open(fnout, O_RDWR | O_CREAT, 0600);

	if (inputFd < 0 || outputFd < 0) {
		fprintf(stderr, "Error opening file, errno %d\n", errno);
		return -1;
	}

	size_t inputLen = lseek(inputFd, 0, SEEK_END) - offset_in; // Get the size of the input file
	lseek(inputFd, 0, SEEK_SET);

	size_t outputLen = inputLen - IV_LEN - HM_LEN;
	ftruncate(outputFd, outputLen);

	void *input = mmap(NULL, inputLen, PROT_READ | PROT_WRITE, MAP_SHARED, inputFd, 0);
	void *output = mmap(NULL, outputLen, PROT_READ | PROT_WRITE, MAP_SHARED, outputFd, 0);

	if (input == MAP_FAILED || output == MAP_FAILED) {
		fprintf(stderr, "Error mapping file, errno %d\n", errno);
		return -1;
	}

	size_t decryptedLen = ske_decrypt(output, &((unsigned char *)input)[offset_in], inputLen, K);

	msync(output, outputLen, MS_SYNC);

	munmap(input, inputLen);
	munmap(output, outputLen);
	close(inputFd);
	close(outputFd);

	return decryptedLen;
}
