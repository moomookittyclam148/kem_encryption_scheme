#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rsa.h"
#include "prf.h"

/* NOTE: a random composite surviving 10 Miller-Rabin tests is extremely
 * unlikely.  See Pomerance et al.:
 * http://www.ams.org/mcom/1993-61-203/S0025-5718-1993-1189518-9/
 * */
#define ISPRIME(x) mpz_probab_prime_p(x,10)
#define NEWZ(x) mpz_t x; mpz_init(x)
#define BYTES2Z(x,buf,len) mpz_import(x,len,-1,1,0,0,buf)
#define Z2BYTES(buf,len,x) mpz_export(buf,&len,-1,1,0,0,x)
#define MPZ_PRINT(msg,x) gmp_printf("%s %Zd\n", msg, x)

/* utility function for read/write mpz_t with streams: */
int zToFile(FILE* f, mpz_t x)
{
	mpz_out_raw(f, x);
	return 0;
}
int zFromFile(FILE* f, mpz_t x)
{
	mpz_inp_raw(x, f);
	return 0;
}

int rsa_getPrf(size_t bits, mpz_t result)
{
	size_t bytes = bits / 8;
	unsigned char *buffer = malloc(bytes);

	randBytes(buffer, bytes);

	BYTES2Z(result, buffer, bytes);

	free(buffer);
	return 0;
}

// Collects some random bytes, converts to a number, and finds a prime around there.
int rsa_getPrfPrime(size_t bits, mpz_t prime)
{
	int isPrime;
	rsa_getPrf(bits, prime);

	// Get the next odd number
	if (mpz_even_p(prime)) {
		mpz_add_ui(prime, prime, 1);
	}

	isPrime = ISPRIME(prime);

	while (isPrime == 0) {
		mpz_add_ui(prime, prime, 2);
		isPrime = ISPRIME(prime);
	}

	return 0;
}

int coprime(mpz_t a, mpz_t b)
{
	mpz_t gcd;
	mpz_init(gcd);
	mpz_gcd(gcd, a, b);
	return mpz_cmp_ui(gcd, 1) == 0;
}

int rsa_keyGen(size_t keyBits, RSA_KEY* K)
{
	/* TODO: write this.  Use the prf to get random byte strings of
	 * the right length, and then test for primality (see the ISPRIME
	 * macro above).  Once you've found the primes, set up the other
	 * pieces of the key ({en,de}crypting exponents, and n=pq). */

	rsa_initKey(K);

	// Find random primes p and q
	mpz_t p, q, n;
	mpz_inits(p, q, n, NULL);

	rsa_getPrfPrime(keyBits / 2, p);
	rsa_getPrfPrime(keyBits / 2, q);
	mpz_mul(n, p, q);

	mpz_t e, phi_n, p_sub_1, q_sub_1;
	mpz_inits(e, phi_n, p_sub_1, q_sub_1, NULL);

	// phi(n) = phi(pq) = phi(p)phi(q) since p, q are coprime.
	// Now if x is prime, phi(x) = p - 1.
	// So phi(n) = phi(p)phi(q) = (p - 1)(q - 1).
	mpz_sub_ui(p_sub_1, p, 1);
	mpz_sub_ui(q_sub_1, q, 1);
	mpz_mul(phi_n, p_sub_1, q_sub_1);

	// Select e such that (e, phi(n)) = 1.
	// Start e from 65537 and then add 2 until we find something coprime
	// (from what I gather from fiddling around on the command line openssl seems to always use
	// e as 65537, which I guess makes sense because it doesn't really matter if e is big or small
	// since everyone knows it anyway).
	mpz_set_ui(e, 65537);

	while (!coprime(e, phi_n)) {
		mpz_add_ui(e, e, 2);
	}

	// Find d such that d is the modular multiplicative inverse of e mod phi(n)
	NEWZ(d);
	mpz_invert(d, e, phi_n);

	mpz_set(K->p, p);
	mpz_set(K->q, q);
	mpz_set(K->n, n);
	mpz_set(K->e, e);
	mpz_set(K->d, d);

	return 0;
}

size_t rsa_numBytes(mpz_t n)
{
	size_t bits = mpz_sizeinbase(n, 2);
	return (bits - 1) / 8 + 1;
}

size_t rsa_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K)
{
	NEWZ(message);
	BYTES2Z(message, inBuf, len);

	// c = m^e mod(n)
	NEWZ(ciphertext);
	mpz_powm(ciphertext, message, K->e, K->n);

	size_t writeLen = 0;
	Z2BYTES(outBuf, writeLen, ciphertext);

	return writeLen;
}

size_t rsa_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K)
{
	NEWZ(ciphertext);
	BYTES2Z(ciphertext, inBuf, len);

	// m = c^d mod(n)
	NEWZ(message);
	mpz_powm(message, ciphertext, K->d, K->n);

	size_t writeLen = 0;

	Z2BYTES(outBuf, writeLen, message);
	
	return writeLen;
}

size_t rsa_numBytesN(RSA_KEY* K)
{
	return mpz_size(K->n) * sizeof(mp_limb_t);
}

int rsa_initKey(RSA_KEY* K)
{
	mpz_init(K->d); mpz_set_ui(K->d,0);
	mpz_init(K->e); mpz_set_ui(K->e,0);
	mpz_init(K->p); mpz_set_ui(K->p,0);
	mpz_init(K->q); mpz_set_ui(K->q,0);
	mpz_init(K->n); mpz_set_ui(K->n,0);
	return 0;
}

int rsa_writePublic(FILE* f, RSA_KEY* K)
{
	/* only write n,e */
	zToFile(f,K->n);
	zToFile(f,K->e);
	return 0;
}
int rsa_writePrivate(FILE* f, RSA_KEY* K)
{
	zToFile(f,K->n);
	zToFile(f,K->e);
	zToFile(f,K->p);
	zToFile(f,K->q);
	zToFile(f,K->d);
	return 0;
}
int rsa_readPublic(FILE* f, RSA_KEY* K)
{
	rsa_initKey(K); /* will set all unused members to 0 */
	zFromFile(f,K->n);
	zFromFile(f,K->e);
	return 0;
}
int rsa_readPrivate(FILE* f, RSA_KEY* K)
{
	rsa_initKey(K);
	zFromFile(f,K->n);
	zFromFile(f,K->e);
	zFromFile(f,K->p);
	zFromFile(f,K->q);
	zFromFile(f,K->d);
	
	return 0;
}
int rsa_shredKey(RSA_KEY* K)
{
	/* clear memory for key. */
	mpz_t* L[5] = {&K->d,&K->e,&K->n,&K->p,&K->q};
	size_t i;
	for (i = 0; i < 5; i++) {
		size_t nLimbs = mpz_size(*L[i]);
		if (nLimbs) {
			memset(mpz_limbs_write(*L[i],nLimbs),0,nLimbs*sizeof(mp_limb_t));
			mpz_clear(*L[i]);
		}
	}
	/* NOTE: a quick look at the gmp source reveals that the return of
	 * mpz_limbs_write is only different than the existing limbs when
	 * the number requested is larger than the allocation (which is
	 * of course larger than mpz_size(X)) */
	return 0;
}
