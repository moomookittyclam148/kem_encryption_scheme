/* test code for RSA */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../rsa.h"
#include "../prf.h"

/* turn this on to print more stuff. */
#define VDEBUG 1
/* turn this on for randomized tests. */
#define RANDKEY 1

/* encrypt / decrypt some strings, and make sure
 * this composition is the identity */

int main() {
	fprintf(stderr, "testing rsa...\n");
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

	rsa_keyGen(1024,&K);
	// rsa_keyGen(256,&K);

	size_t i,j,ctLen,mLen = rsa_numBytesN(&K);

	unsigned char* pt = malloc(mLen);
	unsigned char* ct = malloc(mLen);
	unsigned char* dt = malloc(mLen);
	for (i = 0; i < 32; i++) {
		pt[mLen-1] = 0; /* avoid reduction mod n. */
		randBytes(pt,mLen-1);
		/* encrypt, decrypt, check. */
		ctLen = rsa_encrypt(ct,pt,mLen,&K);
		memset(dt,0,mLen);
		rsa_decrypt(dt,ct,ctLen,&K);
		for (j = 0; j < mLen; j++) {
			if (dt[j] != pt[j]) break;
		}

		#if VDEBUG
		if (j != mLen) {
			int u;

			fprintf(stderr, "\n\n\n\n");
			fprintf(stderr, "pt\n");
			for (u = 0; u < mLen; u++) { fprintf(stderr, "%d\t", pt[u]); if ((u + 1) % 8 == 0) { fprintf(stderr, "\n"); } }

			fprintf(stderr, "\n\n\n\n");
			fprintf(stderr, "ct\n");
			for (u = 0; u < ctLen; u++) { fprintf(stderr, "%d\t", ct[u]); if ((u + 1) % 8 == 0) { fprintf(stderr, "\n"); } }

			fprintf(stderr, "\n\n\n\n");
			fprintf(stderr, "dt\n");
			for (u = 0; u < mLen; u++) { fprintf(stderr, "%d\t", dt[u]); if ((u + 1) % 8 == 0) { fprintf(stderr, "\n"); } }

			fprintf(stderr, "\n\n\n\n");

			fprintf(stderr, "test[%02lu] %s\n",i,(j==mLen)?pass:fail);
			return 1;
		}
		#endif

		fprintf(stderr, "test[%02lu] %s\n",i,(j==mLen)?pass:fail);
	}
	free(pt); free(ct); free(dt);
	return 0;
}
