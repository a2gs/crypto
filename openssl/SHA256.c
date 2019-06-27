/*
 * https://wiki.openssl.org/index.php/EVP_Message_Digests
 */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

void digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)
{
	EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_create()) == NULL)
		handleErrors();

	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		handleErrors();

	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		handleErrors();

	if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
		handleErrors();

	if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
		handleErrors();

	EVP_MD_CTX_destroy(mdctx);
}

int main(int argc, char *argv[])
{
	unsigned int d_len = 0, i = 0;
	unsigned char *dgst = NULL;

	if(argc != 2){
		printf("%s <STRING TO HASH>\n", argv[0]);
		return(0);
	}

	digest_message((const unsigned char *)argv[1], strlen(argv[1]), &dgst, &d_len);

	printf("Msg: [%s]\nDigest: [", argv[1]);

	for(i = 0; i < d_len; i++)
		printf("%02X", dgst[i]);

	printf("][%u]\n", d_len);

	OPENSSL_free(dgst);

	return(0);
}
