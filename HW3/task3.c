#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

int main()
{
	// Instantiate BIGNUM variables and ctx for n, d, e, result, and C for cryptic message
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *n = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *res = BN_new();
	BIGNUM *C = BN_new();

	// Fill the variables with appropriate HEX values given in the pdf
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	BN_hex2bn(&e, "010001");
	BN_hex2bn(&C, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");

	// Apply the M = C^d mod n formula to decrypt the message
	BN_mod_exp(res, C, d, n, ctx);

	// Print decrypted message
	printf("decrypted: %s\n", BN_bn2hex(res));

}
