/* test code for RSA */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../rsa.h"
#include "../prf.h"

/* turn this on to print more stuff. */
#define VDEBUG 0
/* turn this on for randomized tests. */
#define RANDKEY 0

/* encrypt / decrypt some strings, and make sure
 * this composition is the identity */

#define SZ 2

int main() {
	fprintf(stderr, "simple testing rsa...\n");
	char *pass,*fail;
	if (isatty(fileno(stdout))) {
		pass = "\033[32mpassed\033[0m";
		fail = "\033[31mfailed\033[0m";
	} else {
		pass = "passed";
		fail = "failed";
	}
#if RANDKEY
	setSeed(0,0);
#else
	setSeed((unsigned char*)"random data :D:D:D",18);
#endif
	RSA_KEY K;

	rsa_keyGen(16,&K);


	unsigned char *inputMessage = malloc(SZ);
	unsigned char *ciphertext = malloc(SZ * 16);
	unsigned char *outputMessage = malloc(SZ);

	memset(inputMessage, 0, SZ);
	memset(ciphertext, 0, SZ);
	memset(outputMessage, 0, SZ);

	inputMessage[0] = 62;
	inputMessage[1] = 81;
	
	size_t ciphersize = rsa_encrypt(ciphertext, inputMessage, SZ, &K);

	// TODO: this is why we need to make sure num bytes ciphertext is correct

	rsa_decrypt(outputMessage, ciphertext, ciphersize, &K);

	// rsa_encrypt(ct,pt,mLen,&K);
	// memset(dt,0,mLen);
	// rsa_decrypt(dt,ct,ctLen,&K);

	// for (i = 0; i < 1; i++) {

	// 	pt[mLen-1] = 0; /* avoid reduction mod n. */
	// 	randBytes(pt,mLen-1);
	// 	/* encrypt, decrypt, check. */
	// 	ctLen = rsa_encrypt(ct,pt,mLen,&K);
	// 	memset(dt,0,mLen);
	// 	rsa_decrypt(dt,ct,ctLen,&K);
	// 	for (j = 0; j < mLen; j++) {
	// 		if (dt[j] != pt[j]) break;
	// 	}
	// 	fprintf(stderr, "test[%02lu] %s\n",i,(j==mLen)?pass:fail);
	// }
	// free(pt); free(ct); free(dt);
	return 0;
}
