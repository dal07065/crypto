#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

int main()
{
	// Instantiate BIGNUM variables and ctx for context: n, d, e, res for result, M for message
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *n = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *res = BN_new();
	BIGNUM *M = BN_new();

	// Convert HEX values given to BIGNUM values and store into BIGNUM variables
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	BN_hex2bn(&e, "010001");
	BN_hex2bn(&M, "4120746f702073656372657421");

	// Apply the formula C = M^e mod n
	BN_mod_exp(res, M, e, n, ctx);

	printf("encrypted: %s\n", BN_bn2hex(res));

	// Check correct decryption using formula M = C^d mod n
	BN_mod_exp(res, res, d, n, ctx);

	printf("decrypted: %s\n", BN_bn2hex(res));

}
