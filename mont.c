/*
 * compute Montgomery square of given bignum using EC_NIST_PRIME_521.
 *
 * compile with:
 *    gcc -m64 -o mont mont.c util.c -lcrypto
 */

#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/objects.h>

#include <openssl/crypto.h>
#include <openssl/ecdsa.h>

#include "util.h"

static void
print_bn_mont_ctx(FILE *fp, BN_MONT_CTX *mont)
{
	fprintf(fp, "BN_MONT_CTX %p\n", mont);

        if (mont == NULL)
		return;

	fprintf(fp, "  ri = %d\n", mont->ri);

	print_bignum(&mont->RR, "RR = ");
	print_bignum(&mont->N, "N = ");
	print_bignum(&mont->Ni, "Ni = ");

	fprintf(fp, "  n0[0] = %lu\n", mont->n0[0]);
	fprintf(fp, "  n0[1] = %lu\n", mont->n0[1]);

	fprintf(fp, "  flags = 0x%x\n", mont->flags);
}

int
main(int argc, char *argv[])
{

	if (argc != 2)
		errx(1, "usage: %s hex", argv[0]);

	BIGNUM *r = BN_new();
	BIGNUM *a = BN_new();

	if (!BN_hex2bn(&a, argv[1])) {
		ERR_print_errors_fp(stderr);
		errx(1, "BN_hex2bn");
	}

	print_bignum_members(a);

	EC_GROUP *group = NULL;
	BN_CTX *ctx = NULL;

	if ((ctx = BN_CTX_new()) == NULL)
		errx(1, "new");

	fprintf(stderr, "a: ");
	BN_print_fp(stderr, a);
	fprintf(stderr, "\n");

	fprintf(stderr, "r before: ");
	BN_print_fp(stderr, r);
	fprintf(stderr, "\n");

	BN_MONT_CTX *mont_ctx = NULL;

	printf("using custom BN_MONT_CTX to resemble secp521r1\n");

	mont_ctx = BN_MONT_CTX_new();
	if (mont_ctx == NULL)
		errx(1, "mont NULL");

	// taken from crypto/ec/ec_curve.c#_EC_NIST_PRIME_521, field p
	unsigned char p_bin[] = {0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

	BIGNUM *p = BN_new();
	BN_bin2bn(p_bin, sizeof (p_bin), p);

	if (!BN_MONT_CTX_set(mont_ctx, p, ctx)) {
		errx(1, "BN_MONT_CTX_set");
	}

	print_bn_mont_ctx(stderr, mont_ctx);

	if (!BN_mod_mul_montgomery(r, a, a, mont_ctx, ctx)) {
	ERR_print_errors_fp(stderr);
	exit(1);
	}

	fprintf(stderr, "r after: ");
	BN_print_fp(stderr, r);
	fprintf(stderr, "\n");

	print_bignum_members(r);

	return (0);
}
