#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/saf.h>
#include <openssl/e_os2.h>
#include <openssl/ossl_typ.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/lhash.h>
#include <openssl/conf.h>
#include <openssl/txt_db.h>
#include <openssl/engine.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs12.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>
#include <openssl/sm2.h>

#include "internal/cryptlib.h"
#include "internal/evp_int.h"
#include "internal/x509_int.h"

enum BASE64_EVP_PKEY_TYPE
{
	BASE64_TO_PUBLIC_KEY = 0,
	BASE64_TO_PRIVATE_KEY = 1,
};

unsigned int base64_to_evp_pkey_ctx(const unsigned char * base64_data, EVP_PKEY_CTX **ctx, int pkey_type)
{
	EVP_PKEY *pkey = NULL, *ret = NULL;
	unsigned char in_base64[512] = {0}, out_base64[512] = {0};
	const unsigned char *tmp = NULL;
	unsigned int  in_base64_len = 512, out_base64_len = 512, i = 0;

	in_base64_len = strlen(base64_data);
	memcpy(in_base64, base64_data, in_base64_len);

/**************解码base64数据为8 bit数据***********/
	if (SAF_Base64_Decode(in_base64, in_base64_len, out_base64, &out_base64_len) != SAR_Ok)
	{
		fprintf(stderr, "Base64 Decode Fail!\n");
		return 1;
	}
#if 1	
	for (i = 0; i < out_base64_len; i++)
		fprintf(stdout, "%02x ", out_base64[i]);
	fprintf(stdout, "\nlen = %d\n", out_base64_len);
#endif
/**************8 bit数据转换为私钥***********/
	tmp = out_base64;
	if (pkey_type == BASE64_TO_PRIVATE_KEY)
		ret = d2i_AutoPrivateKey(&pkey, &tmp, out_base64_len);
	else if (pkey_type == BASE64_TO_PUBLIC_KEY)
		ret = d2i_PUBKEY(&pkey, &tmp, out_base64_len);
	else
	{
		fprintf(stderr, "Input PKEY Type Error!\n");
		return 1;
	}
	if (!ret)
	{
		fprintf(stderr, "d2i Fail\n");
		return 1;
	}

	*ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (*ctx == NULL)
	{
		fprintf(stderr, "Create EVP PKEY Fail!\n");
		EVP_PKEY_free(pkey);
		return 1;
	}

	EVP_PKEY_free(pkey);

	return 0;
}


int main()
{
	EVP_PKEY_CTX *ctx = NULL, *sign_ctx = NULL, *vrfy_ctx = NULL;
	const EVP_PKEY_ASN1_METHOD *ameth, *new_ameth;
	ENGINE *tmpeng = NULL;
	int pkey_id;
	EVP_PKEY *pkey = NULL, *sign_pkey = NULL, *vrfy_pkey = NULL;
	unsigned char in_base64[512] = {0}, out_base64[512] = {0};
	unsigned int  in_base64_len = 512, out_base64_len = 512;
	
	//unsigned char *tmp_private_base64 = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg03btuLw79nN8c5+XiRuo5s9rFD9u+k6nJ0bIX7P5byihRANCAAR2zebC5JLMAgh7rr41vqUbhdNFuNhlEIPLJQVXvMy9DqH8TfsFMpqCz7YLT1U1MixNSyETKTqKt1tKlCinby5q";
	//unsigned char *tmp_public_base64 = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEds3mwuSSzAIIe66+Nb6lG4XTRbjYZRCDyyUFV7zMvQ6h/E37BTKags+2C09VNTIsTUshEyk6irdbSpQop28uag==";

	unsigned char *tmp_private_base64 = "MHcCAQEEIKrpn03+M6OZV6fiBSBRvJf5ayOm/59zgd7p0yb5zWX1oAoGCCqBHM9VAYItoUQDQgAEmnRHuFVSQ5vdBGy92mxQ7aYjuI8RNP1wKQDaRBu+MEFWU/ObcR+5NtW6gD3LkfN5LfHmpArBchL4PA2pZAr4zw==";
	unsigned char *tmp_public_base64 = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEmnRHuFVSQ5vdBGy92mxQ7aYjuI8RNP1wKQDaRBu+MEFWU/ObcR+5NtW6gD3LkfN5LfHmpArBchL4PA2pZAr4zw==";

	unsigned char *out_sign = NULL, *out_vrfy = NULL, *sign_out = NULL, *vrfy_out = NULL;
	const unsigned char *tmp = NULL;
	int len = 0, i = 0, tmp_len = 0;

printf("------------------sign_pkey---------------\n");

	base64_to_evp_pkey_ctx(tmp_private_base64, &sign_ctx, BASE64_TO_PRIVATE_KEY);

printf("------------------vrfy_pkey---------------\n");

	base64_to_evp_pkey_ctx(tmp_public_base64, &vrfy_ctx, BASE64_TO_PUBLIC_KEY);


	unsigned char data[]="test";
	size_t data_len = 5;
	unsigned char *sign_data = NULL, *new_sign_data = NULL;
	size_t sign_len = 0, new_sign_len = 0;
	int ret_vrfy = 0;

	EVP_PKEY_sign_init(sign_ctx);
	EVP_PKEY_verify_init(vrfy_ctx);

	EVP_PKEY_CTX_set_ec_sign_type(sign_ctx, NID_sm_scheme);
	EVP_PKEY_CTX_set_ec_sign_type(vrfy_ctx, NID_sm_scheme);

printf("--------------------sign-------------------\n");
/**************使用私钥签名***********/
	EVP_PKEY_sign(sign_ctx, NULL, &sign_len, data, data_len);
	sign_data = (unsigned char *)malloc(sign_len);
	EVP_PKEY_sign(sign_ctx, sign_data, &sign_len, data, data_len);
	for (i = 0; i < sign_len; i++)
		printf("%02x ", sign_data[i]);
	printf("\nsign_len=%d\n", (int)sign_len);

printf("--------------------vrfy-------------------\n");
/**************使用公钥验证签名***********/
	ret_vrfy = EVP_PKEY_verify(vrfy_ctx, sign_data, sign_len, data, data_len);
	if (ret_vrfy == 1)
		printf("Signature Verified Successfully\n");
	else
		printf("Signature Verification Failure\n");

	return 0;

}











