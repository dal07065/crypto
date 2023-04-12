#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

int main()
{
	// Instantiate BIGNUM variables for ctx for context, p, q, e, res for result, and one for value 1
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *res = BN_new();
	BIGNUM *one = BN_new();

	// Convert the given HEX values to BIGNUM values and store into corresponding variables
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	BN_hex2bn(&e, "0D88C3");
	BN_dec2bn(&one, "1");

	// Subtract 1 from p and 1 from q 
	// n = (p-1)*(q-1)
	BN_sub(p, p, one);
	BN_sub(q, q, one);

	// Multiply (p-1) and (q-1)
	BN_mul(res, p, q, ctx);

	// Apply inverse mod function for e*d = 1 mod n
	BN_mod_inverse(res, e, res, ctx);

	printf("private key: %s\n", BN_bn2hex(res));

}
