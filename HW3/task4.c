#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

int main()
{

	// Instantiate BIGNUM variables and ctx for n, d, sig1, sig2, m1, and m2
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *n = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *sig1 = BN_new();
	BIGNUM *sig2 = BN_new();
	BIGNUM *m1 = BN_new();
	BIGNUM *m2 = BN_new();

	// Fill values with appropriate values for n, d, message with $2000 and message with $3000
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	BN_hex2bn(&m1, "49206f776520796f752024323030302e");
	BN_hex2bn(&m2, "49206f776520796f752024333030302e");

	// Apply the sig=m^db mod n formula to both messages and store into sig1 and sig2
	BN_mod_exp(sig1, m1, d, n, ctx);
	BN_mod_exp(sig2, m2, d, n, ctx);

	// Print the signatures
	printf("signature of \'I owe you $2000\' : %s\n", BN_bn2hex(sig1));
	printf("signature of \'I owe you $3000\' : %s\n", BN_bn2hex(sig2));
}
