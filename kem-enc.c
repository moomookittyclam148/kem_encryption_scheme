/* kem-enc.c
 * simple encryption utility providing CCA2 security.
 * based on the KEM/DEM hybrid model. */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <assert.h>
#include <errno.h>

#include "ske.h"
#include "rsa.h"
#include "prf.h"

static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Encrypt or decrypt data.\n\n"
"   -i,--in     FILE   read input from FILE.\n"
"   -o,--out    FILE   write output to FILE.\n"
"   -k,--key    FILE   the key.\n"
"   -r,--rand   FILE   use FILE to seed RNG (defaults to /dev/urandom).\n"
"   -e,--enc           encrypt (this is the default action).\n"
"   -d,--dec           decrypt.\n"
"   -g,--gen    FILE   generate new key and write to FILE{,.pub}\n"
"   -b,--BITS   NBITS  length of new key (NOTE: this corresponds to the\n"
"                      RSA key; the symmetric key will always be 256 bits).\n"
"                      Defaults to %lu.\n"
"   --help             show this message and exit.\n";

#define FNLEN 255

enum modes {
	ENC,
	DEC,
	GEN
};

/* Let SK denote the symmetric key.  Then to format ciphertext, we
 * simply concatenate:
 * +------------+----------------+
 * | RSA-KEM(X) | SKE ciphertext |
 * +------------+----------------+
 * NOTE: reading such a file is only useful if you have the key,
 * and from the key you can infer the length of the RSA ciphertext.
 * We'll construct our KEM as KEM(X) := RSA(X)|H(X), and define the
 * key to be SK = KDF(X).  Naturally H and KDF need to be "orthogonal",
 * so we will use different hash functions:  H := SHA256, while
 * KDF := HMAC-SHA512, where the key to the hmac is defined in ske.c
 * (see KDF_KEY).
 * */

#define HASHLEN 32 /* for sha256 */

void debugPrint(char *message, unsigned char *buf, int size)
{
	printf("%s\n", message);
	int i;
	for (i = 0; i < size; i++) {
		printf("%3d\t", buf[i]);
		if ((i + 1) % 4 == 0) {
			printf("\n");
		}
	}

	printf("\n\n");
}

int kem_encrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: encapsulate random symmetric key (SK) using RSA and SHA256;
	 * encrypt fnIn with SK; concatenate encapsulation and cihpertext;
	 * write to fnOut. */

	unsigned int symmetricKeyLen = rsa_numBytesN(K);
	unsigned char *symmetricKeyBytes = calloc(symmetricKeyLen, 1);
	assert(symmetricKeyBytes != NULL);
	randBytes(symmetricKeyBytes, symmetricKeyLen - 1);

	unsigned char *rsaOutput = malloc(symmetricKeyLen);
	assert(rsaOutput != NULL);
	rsa_encrypt(rsaOutput, symmetricKeyBytes, symmetricKeyLen, K);

	unsigned int shaOutputLen = HASHLEN;
	unsigned char *shaOutput = calloc(shaOutputLen, 1);
	assert(shaOutput != NULL);

	// SHA256 our plain key
	EVP_MD_CTX *ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(ctx, symmetricKeyBytes, symmetricKeyLen);
	EVP_DigestFinal_ex(ctx, shaOutput, &shaOutputLen);
	EVP_MD_CTX_destroy(ctx);

	// Compute encapsulated symmetric key
	unsigned int encapsulatedKeyLen = symmetricKeyLen + shaOutputLen;
	unsigned char *encapsulatedKey = calloc(encapsulatedKeyLen, 1);
	assert(encapsulatedKey != NULL);

	memcpy(encapsulatedKey, rsaOutput, symmetricKeyLen);
	memcpy(&encapsulatedKey[symmetricKeyLen], shaOutput, shaOutputLen);

	// Write the encapsulated key to the output file
	FILE *outFile = fopen(fnOut, "w");

	fwrite(encapsulatedKey, 1, encapsulatedKeyLen, outFile);
	if (fclose(outFile) != 0) {
		fprintf(stderr, "Unable to close output file stream\n");
		return 1;
	}

	SKE_KEY SK;
	ske_keyGen(&SK, symmetricKeyBytes, symmetricKeyLen);
	
	// Compute the ciphertext and append it to the file after the encapsulated key
	ske_encrypt_file(fnOut, fnIn, &SK, NULL, encapsulatedKeyLen);

	free(symmetricKeyBytes);
	free(rsaOutput);
	free(encapsulatedKey);
	
	return 0;
}

/* NOTE: make sure you check the decapsulation is valid before continuing */
int kem_decrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: write this. */
	/* step 1: recover the symmetric key */
	/* step 2: check decapsulation */
	/* step 3: derive key from ephemKey and decrypt data. */

	// The first n bytes are the RSA, the remaining bytes are the ciphertext
	FILE *inputFile = fopen(fnIn, "r");
	if (inputFile == NULL) {
		fprintf(stderr, "An error occurred opening the input file\n");
		return 1;
	}

	size_t rsaLen = rsa_numBytesN(K);
	unsigned int encapsulatedKeyLen = rsaLen + HASHLEN;

	unsigned char *encapsulatedKey = calloc(encapsulatedKeyLen, 1);
	assert(encapsulatedKey != NULL);

	int amountRead = fread(encapsulatedKey, 1, encapsulatedKeyLen, inputFile);
	fclose(inputFile);

	if (amountRead < 0) {
		fprintf(stderr, "An error occurred reading from the file\n");
		return 1;
	}

	// Split the encapsulatedKey into the RSA and SHA256 parts
	unsigned char *rsa = calloc(rsaLen, 1);
	assert(rsa != NULL);

	unsigned char *sha = calloc(HASHLEN, 1);
	assert(sha != NULL);

	memcpy(rsa, encapsulatedKey, rsaLen);
	memcpy(sha, &encapsulatedKey[rsaLen], HASHLEN);

	unsigned char *symmetricKeyBytes = calloc(rsaLen, 1);
	assert(symmetricKeyBytes != NULL);

	rsa_decrypt(symmetricKeyBytes, rsa, rsaLen, K);

	unsigned int shaOutputLen = HASHLEN;
	unsigned char *shaOutput = calloc(shaOutputLen, 1);
	assert(shaOutput != NULL);

	// SHA256 the key we got out of decrypting RSA and check it matches the value from the KEM
	EVP_MD_CTX *ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(ctx, symmetricKeyBytes, rsaLen);
	EVP_DigestFinal_ex(ctx, shaOutput, &shaOutputLen);
	EVP_MD_CTX_destroy(ctx);

	if (memcmp(sha, shaOutput, HASHLEN) != 0) {
		fprintf(stderr, "Invalid encapsulation\n");
		return 1;
	}

	// Get our SKE key
	SKE_KEY SK;
	ske_keyGen(&SK, symmetricKeyBytes, rsaLen);

	ske_decrypt_file(fnOut, fnIn, &SK, encapsulatedKeyLen);

	free(symmetricKeyBytes);
	free(rsa);
	free(sha);
	free(shaOutput);

	return 0;
}

int main(int argc, char *argv[]) {
	/* define long options */
	static struct option long_opts[] = {
		{"in",      required_argument, 0, 'i'},
		{"out",     required_argument, 0, 'o'},
		{"key",     required_argument, 0, 'k'},
		{"rand",    required_argument, 0, 'r'},
		{"gen",     required_argument, 0, 'g'},
		{"bits",    required_argument, 0, 'b'},
		{"enc",     no_argument,       0, 'e'},
		{"dec",     no_argument,       0, 'd'},
		{"help",    no_argument,       0, 'h'},
		{0,0,0,0}
	};
	/* process options: */
	char c;
	int opt_index = 0;
	char fnRnd[FNLEN+1] = "/dev/urandom";
	fnRnd[FNLEN] = 0;
	char fnIn[FNLEN+1];
	char fnOut[FNLEN+1];
	char fnKey[FNLEN+1];
	memset(fnIn,0,FNLEN+1);
	memset(fnOut,0,FNLEN+1);
	memset(fnKey,0,FNLEN+1);
	int mode = ENC;
	// size_t nBits = 2048;
	size_t nBits = 1024;
	while ((c = getopt_long(argc, argv, "edhi:o:k:r:g:b:", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'h':
				printf(usage,argv[0],nBits);
				return 0;
			case 'i':
				strncpy(fnIn,optarg,FNLEN);
				break;
			case 'o':
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'k':
				strncpy(fnKey,optarg,FNLEN);
				break;
			case 'r':
				strncpy(fnRnd,optarg,FNLEN);
				break;
			case 'e':
				mode = ENC;
				break;
			case 'd':
				mode = DEC;
				break;
			case 'g':
				mode = GEN;
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'b':
				nBits = atol(optarg);
				break;
			case '?':
				printf(usage,argv[0],nBits);
				return 1;
		}
	}

	/* TODO: finish this off.  Be sure to erase sensitive data
	 * like private keys when you're done with them (see the
	 * rsa_shredKey function). */
	RSA_KEY K;

	if (mode == GEN) {
		rsa_keyGen(nBits, &K);

		// // Generate new key and write private key to $FILE, public key to $FILE.pub
		char *publicKeyFn = calloc(FNLEN + 4, 1);
		assert(publicKeyFn != NULL);
		strcat(publicKeyFn, fnOut);
		strcat(publicKeyFn, ".pub");

		FILE *publicKeyFile = fopen(publicKeyFn, "w");
		FILE *privateKeyFile = fopen(fnOut, "w");

		rsa_writePublic(publicKeyFile, &K);
		rsa_writePrivate(privateKeyFile, &K);

		fclose(publicKeyFile);
		fclose(privateKeyFile);
		free(publicKeyFn);
		return 0;
	}

	int keyFd = open(fnKey, O_RDWR | O_CREAT, 0666);
	if ((mode == ENC || mode == DEC) && keyFd < 0) {
		fprintf(stderr, "Error opening key file %d\n", errno);
		return 1;
	}

	FILE *keyFile = fdopen(keyFd, "r+");
	if ((mode == ENC || mode == DEC) && keyFile == NULL) {
		fprintf(stderr, "Error opening key file descriptor\n");
		return 1;
	}

	if (mode == ENC) {
		rsa_readPublic(keyFile, &K);
		kem_encrypt(fnOut, fnIn, &K);
	}

	if (mode == DEC) {
		rsa_readPrivate(keyFile, &K);
		kem_decrypt(fnOut, fnIn, &K);
	}

	fclose(keyFile);

	return 0;
}