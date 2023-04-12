#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

int main()
{
	// instantiate ctx and BIGNUM variables
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *n = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *M = BN_new();
	BIGNUM *S = BN_new();
	BIGNUM *res = BN_new();

	// Fill the variables with appropriate HEX values
	BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
	BN_hex2bn(&e, "010001");
	BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
	BN_hex2bn(&M, "4c61756e63682061206d697373696c652e");

	// Apply the verification formula
	BN_mod_exp(res, S, e, n, ctx);

	printf("m: %s\n", BN_bn2hex(res));


	// (OPTIONAL) Change the Signature at the last bit
	printf("Change S from 2F to 3F\n");

	BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");

	// Apply the formula
	BN_mod_exp(res, S, e, n, ctx);

	printf("m after changed: %s\n", BN_bn2hex(res));
}
