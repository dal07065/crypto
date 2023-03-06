#include <openssl/evp.h>
#include <string.h>

int main ()
{

        /* Allow enough space in output buffer for additional block */
        unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
        int inlen, outlen, templen;
        EVP_CIPHER_CTX *ctx;
        /* Bogus key and IV: we'd normally set these from
         * another source.
         */
	unsigned char plaintext [] ="This is a top secret.";
        unsigned char key [17];
	unsigned char iv [] ={0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11};
	unsigned char ciphertext []= {0x76,0x4a,0xa2,0x6b,0x55,0xa4,0xda,0x65,0x4d,0xf6,0xb1,0x9e,0x4b,0xce,0x00,0xf4,0xed,0x05,0xe0,0x93,0x46,0xfb,0x0e,0x76,0x25,0x83,0xcb,0x7d,0xa2,0xac,0x93,0xa2};

	FILE *fptr;

	fptr = fopen("words.txt","r");

	while(fgets(key, 16, fptr))
	{

	key[strcspn(key,"\n")]=0;
	
	for(int i = strlen(key); i < 16; i++)
	{
		strcat(key, "#");
	}

        /* Don't set key or IV right away; we want to check lengths */
        ctx = EVP_CIPHER_CTX_new();
        EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL,1);
        OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
        OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

        /* Now we can set key and IV */
        EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv,1);

        if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, plaintext, strlen(plaintext))) {
         /* Error */
         EVP_CIPHER_CTX_free(ctx);
         return 0;
     	}
	if (!EVP_EncryptFinal_ex(ctx, outbuf+outlen, &templen)) {
         /* Error */
         EVP_CIPHER_CTX_free(ctx);
         return 0;
     	}

	printf("plaintextlength: %zu\t ciphertext length:%d\n", strlen(plaintext), outlen+templen);
	for (int i=0;i<outlen+templen;i++){
	 printf("%x", outbuf[i]);
	}


	printf("\n");
	if (memcmp(ciphertext, outbuf, 32) == 0)
	{
		printf("ciphertext matched!\n");
		printf("key: %s\n", key);
		break;
	}

        EVP_CIPHER_CTX_cleanup(ctx);
	}        
	return 1;
}
