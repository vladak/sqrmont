#include <err.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <pthread.h>

#include "util.h"

unsigned char
hex2dec(char c)
{
	if (isdigit(c))
		return (c - 48);

	return (toupper(c) - 55);
}

unsigned char
hex2byte(unsigned char *in)
{
	return (hex2dec(in[0]) * 16 + hex2dec(in[1]));
}

// TODO: assumptions about length of out
void
hex2char(unsigned char *in, unsigned char *out)
{
	for (int i = 0, j = 0; i < strlen(in); i += 2) {
		char c[2] = { in[i], in[i + 1] };
		out[j++] = hex2byte(c);
	}
}

void
print_hex(unsigned char *in, size_t len)
{
	for (size_t i = 0; i < len; i++)
		printf("%02hhx", in[i]);
	printf("\n");
}

void
print_bignum(BIGNUM *bn, char *ident)
{
	if (bn != NULL) {
		fprintf(stderr, "  %s: ", ident);
		BN_print_fp(stderr, bn);
		fprintf(stderr, "\n");
	}
}

static const char Hex[] = "0123456789ABCDEF";

/* copied from BN_bn2hex */
static char *
get_hex(BIGNUM *a)
{
    int i, j, v, z = 0;
    char *buf;
    char *p;

    if (BN_is_zero(a))
        return OPENSSL_strdup("0");
    buf = OPENSSL_malloc(a->top * BN_BYTES * 3 + 2);
    if (buf == NULL) {
        BNerr(BN_F_BN_BN2HEX, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    p = buf;
    if (a->neg)
        *(p++) = '-';
    for (i = a->top - 1; i >= 0; i--) {  // print single BN_ULONG, starting at highest memory address
        for (j = BN_BITS2 - 8; j >= 0; j -= 8) {  // print a single byte, i.e. two letters
            /* DO NOT strip leading zeros */
            v = ((int)(a->d[i] >> (long)j)) & 0xff;
            // if (z || (v != 0)) {
                *(p++) = Hex[v >> 4];
                *(p++) = Hex[v & 0x0f];
		*(p++) = ' ';
            //    z = 1;
            //}
        }
    }
    *p = '\0';
 err:
    return (buf);
}

static void
print_memory(BIGNUM *a)
{
	unsigned char *p = (unsigned char *)a->d;
	printf("memory: ");
	for (int i = 0; i < a->top * BN_BYTES; i++) {
		printf("%02hhX ", p[i]);
	}
	printf("\n");
}

void
print_bignum_members(BIGNUM *b)
{
	printf("  d: 0x%p\n", b->d);

	print_bignum_bits(b);

	char *hex_str = get_hex(b);
	printf("hex: %s\n", hex_str);
	OPENSSL_free(hex_str);

	print_memory(b);

	printf("  top: %d\n", b->top);
	printf("  dmax: %d\n", b->dmax);
	printf("  neg: %d\n", b->neg);
	printf("\n");
}

void
print_bignum_bits(BIGNUM *a)
{
	printf("bin: ");
	for (int i = a->top * BN_BITS2 - 1; i >= 0; i--) {
		if (BN_is_bit_set(a, i))
			printf("1");
		else
			printf("0");

		if (i % 8 == 0)
			printf(" ");
	}

	printf("\n");

#if 0
	int size = BN_num_bytes(b);
	unsigned char *str = malloc(size);
	BN_bn2bin(b, str);
	printf("bin: %s\n", str);
#endif
}

EC_KEY *
load_key(int nid, char *priv_key_hex, char *pub_key_hex)
{
	EC_KEY *eckey = EC_KEY_new_by_curve_name(nid);
	if (eckey == NULL) {
		ERR_print_errors_fp(stderr);
		errx(1, "EC_KEY_new_by_curve_name");
	}

	BIGNUM *priv_key = NULL;
	if (!BN_hex2bn(&priv_key, priv_key_hex)) {
		ERR_print_errors_fp(stderr);
		errx(1, "BN_hex2bn");
	}

	if (!EC_KEY_set_private_key(eckey, priv_key)) {
		ERR_print_errors_fp(stderr);
		errx(1, "EC_KEY_set_private_key");
	}

	EC_KEY *pub_key = EC_KEY_new_by_curve_name(nid);
	size_t len = strlen(pub_key_hex) / 2;
	unsigned char *pub_key_o = malloc(len);
	if (pub_key_o == NULL)
		err(1, "malloc");
	hex2char(pub_key_hex, pub_key_o);

	print_hex(pub_key_o, len);

	if (o2i_ECPublicKey(&pub_key, (const unsigned char **)&pub_key_o, len) == NULL) {
		ERR_print_errors_fp(stderr);
		errx(1, "o2i_ECPublicKey");
	}

	if (!EC_KEY_set_public_key(eckey, EC_KEY_get0_public_key(pub_key))) {
		ERR_print_errors_fp(stderr);
		errx(1, "EC_KEY_set_public_key");
	}

#if 0
	EC_KEY_set_enc_flags()
	EC_KEY_set_asn1_flag()
	EC_KEY_set_flags()
	EC_KEY_set_conv_form()
#endif

	return eckey;
}

void
print_eckey(EC_KEY *eckey)
{
	fprintf(stderr, "%d: priv_key: ", (int)pthread_self());
	BN_print_fp(stderr, EC_KEY_get0_private_key(eckey));
	fprintf(stderr, "\n");

	unsigned char *out = NULL;
	int len = i2o_ECPublicKey(eckey, &out);
	fprintf(stderr, "%d: pub_key: ",
	    (int)pthread_self());
	for (int i = 0; i < len; i++) {
		fprintf(stderr, "%02hhx", out[i]);
	}
	fprintf(stderr, "\n");
}
