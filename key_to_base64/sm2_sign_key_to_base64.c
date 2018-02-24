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
#include <openssl/bio.h>

#include "internal/cryptlib.h"
#include "internal/evp_int.h"
#include "internal/x509_int.h"


enum BASE64_EVP_PKEY_TYPE
{
	BASE64_TO_PUBLIC_KEY = 0,
	BASE64_TO_PRIVATE_KEY = 1,
};

static EVP_PKEY *pgEvpPkey = NULL;

static EVP_PKEY *init_pkey(const unsigned char *asn1_str, const unsigned char *ctx_name, const unsigned char *ctx_type)
{
	int ok_pkey = 0, ok_ctx = 0;
	int pkey_id;
	EVP_PKEY *ret = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	ENGINE *tmpeng = NULL;
	const EVP_PKEY_ASN1_METHOD *ameth;

	ameth = EVP_PKEY_asn1_find_str(&tmpeng, asn1_str, -1);
	if (!ameth)
	{
		fprintf(stderr, "Asn1 Find Str Fail!\n");
		goto end;
	}

	EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL, ameth);

	if (!(ctx = EVP_PKEY_CTX_new_id(pkey_id, NULL))) {
		fprintf(stderr, "Create PKEY_CTX Fail!\n");
		goto end;
	}
	
	ok_pkey = 1;

	if (!EVP_PKEY_keygen_init(ctx)) {
		fprintf(stderr, "PKEY Keygen Init Fail!\n");
		goto end;
	}

	if (!EVP_PKEY_CTX_ctrl_str(ctx, ctx_name, ctx_type)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_PKEY_keygen(ctx, &ret)) {
		fprintf(stderr, "PKEY Keygen Fail!\n");
		goto end;
	}
	
	ok_ctx = 1;
	
	EVP_PKEY_CTX_free(ctx);

	return ret;

end:
	if (ok_pkey) EVP_PKEY_CTX_free(ctx);
	if (ok_ctx) EVP_PKEY_free(ret);
	
	return NULL;
}

unsigned int evp_pkey_to_base64(EVP_PKEY *pkey, int pkey_type, unsigned char *base64_data, unsigned int *base64_date_len)
{
	unsigned char in_base64[512] = {0}, out_base64[512] = {0};
	unsigned char *tmp = NULL;
	unsigned int in_base64_len = 0, out_base64_len = 512, i = 0;
	int ret = 0;
	
	if (pkey == NULL || base64_data ==NULL)
	{
		fprintf(stderr, "Init Data Is NULL, Exit!\n");
		return 0;
	}

	tmp = in_base64;
	if (pkey_type == BASE64_TO_PRIVATE_KEY)
		ret = i2d_PrivateKey(pkey, &tmp);
	else if (pkey_type == BASE64_TO_PUBLIC_KEY)
		ret = i2d_PUBKEY(pkey, &tmp);
	else
	{
		fprintf(stderr, "Input Type Error, Exit!\n");
		return 0;
	}
	if (ret <= 0)
	{
		fprintf(stderr, "Tarnslate PKEY To String Fail, Exit!\n");
		return 0;
	}

	if (SAF_Base64_Encode(in_base64, ret, out_base64, &out_base64_len) != SAR_Ok)
	{
		fprintf(stderr, "Base64 Encode Fail!\n");
		return 0;
	}

	*base64_date_len = out_base64_len;
	memcpy(base64_data, out_base64, out_base64_len);

	return 1;
}

int main(int argc, char **argv)
{
	unsigned char out_base64[512] = {0};
	unsigned int out_base64_len = 512;
	
	pgEvpPkey = init_pkey("EC", "ec_paramgen_curve", "sm2p256v1");
	if (!pgEvpPkey)
	{
		fprintf(stderr, "Init Pkey Fail!\n");
		return 0;
	}

	memset(out_base64, 0, out_base64_len);
printf("\n<--------------PUBLIC-------------->");
	evp_pkey_to_base64(pgEvpPkey, BASE64_TO_PUBLIC_KEY, out_base64, &out_base64_len);
	printf("\nPUBLIC_KEY:\n\t%s\tdatalen:%d\n", out_base64, out_base64_len);
printf("<--------------PUBLIC-------------->\n");

	memset(out_base64, 0, out_base64_len);
printf("\n<--------------PRIVATE-------------->");
	evp_pkey_to_base64(pgEvpPkey, BASE64_TO_PRIVATE_KEY, out_base64, &out_base64_len);
	printf("\nPRIVATE_KEY:\n\t%s\tdatalen:%d\n", out_base64, out_base64_len);
printf("<--------------PRIVATE-------------->\n");

	free(pgEvpPkey);

	return 1;
}











