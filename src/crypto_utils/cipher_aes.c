#include <stdio.h>
#include <openssl/evp.h>
#include "crypto_utils/cipher_aes.h"
#include "itest.h"


int icrypto_cipher_one_go(unsigned char *in, unsigned char *out, int size_in, char cipher, unsigned char *key, unsigned char *iv, 
						int iv_size, unsigned char *aad, int aad_size, int tag_size)
{
    EVP_CIPHER_CTX *cipher_ctx = NULL;
	const EVP_CIPHER *cipher_ossl = NULL;
	int size_out = 0;
	int size_tmp = 0;

	switch (cipher)
	{
		case ICRYPTO_AES_128_ECB:
			cipher_ossl = EVP_aes_128_ecb();
			break;
		case ICRYPTO_AES_128_CBC:
			cipher_ossl = EVP_aes_128_cbc();
			break;
		case ICRYPTO_AES_128_GCM:
			cipher_ossl = EVP_aes_128_gcm();
			break;
		case ICRYPTO_AES_128_CCM:
			cipher_ossl = EVP_aes_128_ccm();
			break;
		case ICRYPTO_AES_192_ECB:
			cipher_ossl = EVP_aes_192_ecb();
			break;
		case ICRYPTO_AES_192_CBC:
			cipher_ossl = EVP_aes_192_cbc();
			break;
		case ICRYPTO_AES_192_GCM:
			cipher_ossl = EVP_aes_192_gcm();
			break;
		case ICRYPTO_AES_192_CCM:
			cipher_ossl = EVP_aes_192_ccm();
			break;
		case ICRYPTO_AES_256_ECB:
			cipher_ossl = EVP_aes_256_ecb();
			break;
		case ICRYPTO_AES_256_CBC:
			cipher_ossl = EVP_aes_256_cbc();
			break;
		case ICRYPTO_AES_256_GCM:
			cipher_ossl = EVP_aes_256_gcm();
			break;
		case ICRYPTO_AES_256_CCM:
			cipher_ossl = EVP_aes_256_ccm();
			break;
		case ICRYPTO_SM4_128_ECB:
		case ICRYPTO_SM4_128_CBC:
		default:
			return size_out;
	}
	do {

		cipher_ctx = EVP_CIPHER_CTX_new();
		ASSERT_TRUE_HIGH_API((cipher_ctx != NULL));
		
		if (cipher == ICRYPTO_AES_128_CCM || cipher == ICRYPTO_AES_192_CCM || cipher == ICRYPTO_AES_256_CCM) {

			ASSERT_EQUAL_HIGH_API(EVP_EncryptInit_ex(cipher_ctx, cipher_ossl, NULL, NULL, NULL),1);
			ASSERT_EQUAL_HIGH_API(EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_CCM_SET_IVLEN, iv_size, NULL), 1);
			/* Set tag length */
			ASSERT_EQUAL_HIGH_API(EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_CCM_SET_TAG, tag_size, NULL), 1);
			ASSERT_EQUAL_HIGH_API(EVP_EncryptInit_ex(cipher_ctx, NULL, NULL, key, iv),1);
			if (NULL != aad) {
					ASSERT_EQUAL_HIGH_API(EVP_EncryptUpdate(cipher_ctx, NULL, &size_tmp, NULL, size_in), 1); 
					ASSERT_EQUAL_HIGH_API(EVP_EncryptUpdate(cipher_ctx, NULL, &aad_size, aad, aad_size), 1);
			}
		}
		else if (cipher == ICRYPTO_AES_128_GCM || cipher == ICRYPTO_AES_192_GCM || cipher == ICRYPTO_AES_256_GCM) {

			ASSERT_EQUAL_HIGH_API(EVP_EncryptInit_ex(cipher_ctx, cipher_ossl, NULL, NULL, NULL),1);
			ASSERT_EQUAL_HIGH_API(EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, NULL), 1);
			/* Set tag length */
			ASSERT_EQUAL_HIGH_API(EVP_EncryptInit_ex(cipher_ctx, NULL, NULL, key, iv),1);
			if (NULL != aad) {
					ASSERT_EQUAL_HIGH_API(EVP_EncryptUpdate(cipher_ctx, NULL, &aad_size, aad, aad_size), 1);
			}
		}
		else {
			ASSERT_EQUAL_HIGH_API(EVP_EncryptInit_ex(cipher_ctx, cipher_ossl, NULL, key, iv),1);
		}
		ASSERT_EQUAL_HIGH_API(EVP_EncryptUpdate(cipher_ctx, out, &size_out, in, size_in), 1);
		ASSERT_EQUAL_HIGH_API(EVP_EncryptFinal_ex(cipher_ctx, out + size_out, &size_tmp), 1);
		size_out += size_tmp;
		if (cipher == ICRYPTO_AES_128_GCM || cipher == ICRYPTO_AES_192_GCM || cipher == ICRYPTO_AES_256_GCM) {
			ASSERT_EQUAL_HIGH_API(EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, tag_size, out + size_out), 1);
			size_out += 16;
		}
		else if (cipher == ICRYPTO_AES_128_CCM || cipher == ICRYPTO_AES_192_CCM || cipher == ICRYPTO_AES_256_CCM) {
			ASSERT_EQUAL_HIGH_API(EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_CCM_GET_TAG, tag_size, out + size_out), 1);
			size_out += 16;
		}

	} while (0);

	if (cipher_ctx != NULL)
		EVP_CIPHER_CTX_free(cipher_ctx);

    return size_out;
}