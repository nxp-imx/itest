#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include "itest.h"
#include "crypto_utils/cipher_aes.h"
#include "crypto_utils/ecc_sign.h"
#include "crypto_utils/dgst.h"

// High level of sentinel api to reduce code size in tests
#define NB_ALGO 8
static hsm_key_type_t key_type_list[NB_ALGO] = {
    HSM_KEY_TYPE_DSA_SM2_FP_256,
    HSM_KEY_TYPE_ECDSA_NIST_P256,
    HSM_KEY_TYPE_ECDSA_NIST_P384,
    HSM_KEY_TYPE_ECDSA_NIST_P521,
    HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256,
    HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384,
    HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_256,
    HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_384,
};

static hsm_signature_scheme_id_t scheme_id_list[NB_ALGO] = {
    HSM_SIGNATURE_SCHEME_DSA_SM2_FP_256_SM3,
    HSM_SIGNATURE_SCHEME_ECDSA_NIST_P256_SHA_256,
    HSM_SIGNATURE_SCHEME_ECDSA_NIST_P384_SHA_384,
    HSM_SIGNATURE_SCHEME_ECDSA_NIST_P521_SHA_512,
    HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_R1_256_SHA_256,
    HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_R1_384_SHA_384,
    HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_T1_256_SHA_256,
    HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_T1_384_SHA_384,
};

static uint16_t size_pubk_list[NB_ALGO] = {
    0x40,
    0x40,
    0x60,
    0x90,
    0x40,
    0x60,
    0x40,
    0x60};

static uint16_t size_privk_list[NB_ALGO] = {
    0x20,
    0x20,
    0x30,
    0x48,
    0x20,
    0x30,
    0x20,
    0x30};

int get_key_param(hsm_key_type_t key_type, hsm_signature_scheme_id_t *scheme_id, uint16_t *size_pubk, uint16_t *size_privk)
{

    uint32_t i;

    for (i = 0; i < NB_ALGO; i++)
    {
        if (key_type_list[i] == key_type)
        {
            if (scheme_id != NULL)
                *scheme_id = scheme_id_list[i];
            if (size_pubk != NULL)
                *size_pubk = size_pubk_list[i];
            if (size_privk != NULL)
                *size_privk = size_privk_list[i];
            break;
        }
    }
    return TRUE_TEST;
}

int isen_generate_key_strict_update(hsm_hdl_t key_store_serv, uint32_t *key_id, hsm_key_type_t key_type,
                                    hsm_key_group_t key_group, uint8_t *out_key, uint16_t out_key_size)
{
    op_generate_key_args_t gen_key_args;

    // PARAM KEY_GEN strict_update
    gen_key_args.key_identifier = key_id;
    gen_key_args.out_size = out_key == NULL ? 0 : out_key_size;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE | HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
    gen_key_args.key_type = key_type;
    gen_key_args.key_group = key_group;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = out_key;
    do
    {
        // GEN KEY + STORE IN NVM
        ASSERT_EQUAL_HIGH_API(hsm_generate_key(key_store_serv, &gen_key_args), HSM_NO_ERROR);
        return TRUE_TEST;
    } while (0);
    return FALSE_TEST;
}

int isen_generate_key(hsm_hdl_t key_store_serv, uint32_t *key_id, hsm_key_type_t key_type,
                      hsm_key_group_t key_group, uint8_t *out_key, uint16_t out_key_size)
{
    op_generate_key_args_t gen_key_args;

    // PARAM KEY_GEN strict_update
    gen_key_args.key_identifier = key_id;
    gen_key_args.out_size = out_key == NULL ? 0 : out_key_size;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = key_type;
    gen_key_args.key_group = key_group;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = out_key;
    do
    {
        // GEN KEY + STORE IN NVM
        ASSERT_EQUAL_HIGH_API(hsm_generate_key(key_store_serv, &gen_key_args), HSM_NO_ERROR);
        return TRUE_TEST;
    } while (0);
    return FALSE_TEST;
}

int isen_kek_generation(hsm_hdl_t sg0_key_mgmt_srv, uint8_t *kek_data, uint32_t key_size, uint32_t *kek_handle)
{

    op_key_exchange_args_t key_exchange_args;

    uint8_t ecdh_secret[32];
    uint8_t kdf_input[63];
    char FixedInfo[] = "NXP HSM USER KEY DERIVATION";

    uint8_t local_key[65];
    int size_privk;
    uint8_t local_pub_key[65];
    uint8_t remote_pub_key[65];
    int local_pub_key_len;

    // =========== NEGOTIATE KEK FOR KEY INJECTION ================= //
    do
    {

        ASSERT_EQUAL_HIGH_API(icrypto_generate_key_pair(NID_X9_62_prime256v1, (unsigned char *)local_pub_key, &local_pub_key_len, (unsigned char *)local_key, &size_privk), 1);
        ASSERT_EQUAL_HIGH_API(local_pub_key_len, 64);

        key_exchange_args.key_identifier = 0;
        key_exchange_args.shared_key_identifier_array_size = sizeof(uint32_t);
        key_exchange_args.shared_key_identifier_array = (uint8_t *)kek_handle;
        key_exchange_args.ke_input_size = 64;
        key_exchange_args.ke_input = local_pub_key;
        key_exchange_args.ke_output_size = 64;
        key_exchange_args.ke_output = remote_pub_key;
        key_exchange_args.kdf_input_size = 0;
        key_exchange_args.kdf_input = 0;
        key_exchange_args.kdf_output_size = 0;
        key_exchange_args.kdf_output = 0;
        key_exchange_args.shared_key_group = 100;
        key_exchange_args.shared_key_info = 0x0A /* Transient KEK */;
        key_exchange_args.shared_key_type = HSM_KEY_TYPE_AES_256;
        key_exchange_args.initiator_public_data_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
        key_exchange_args.key_exchange_scheme = HSM_KE_SCHEME_ECDH_NIST_P256;
        key_exchange_args.kdf_algorithm = HSM_KDF_ONE_STEP_SHA_256;
        key_exchange_args.flags = 6 /* Create + Ephemeral */;
        key_exchange_args.signed_message = NULL;
        key_exchange_args.signed_msg_size = 0;
        ASSERT_EQUAL_HIGH_API(hsm_key_exchange(sg0_key_mgmt_srv, &key_exchange_args), HSM_NO_ERROR);

        ASSERT_EQUAL_HIGH_API(icrypto_ECDH_compute_key((unsigned char *)ecdh_secret, sizeof(ecdh_secret), (unsigned char *)remote_pub_key, 64, NID_X9_62_prime256v1, (unsigned char *)local_key, 32), 1);

        kdf_input[0] = 0;
        kdf_input[1] = 0;
        kdf_input[2] = 0;
        kdf_input[3] = 1;
        memcpy(&kdf_input[4], ecdh_secret, 32);
        memcpy(&kdf_input[36], FixedInfo, 27);

        ASSERT_EQUAL_HIGH_API(icrypto_hash_one_go((unsigned char *)kdf_input, (unsigned char *)kek_data, "sha256", sizeof(kdf_input)), (int)key_size);

        return TRUE_TEST;

    } while (0);

    return FALSE_TEST;
}

int isen_hsm_key_injection_custom(hsm_hdl_t sg0_key_mgmt_srv, uint32_t *key_id, hsm_key_type_t key_type,
                           uint8_t *key_in, uint32_t kek_handle, uint8_t *kek_data, uint32_t key_size,
                           uint16_t key_group, hsm_key_info_t key_info, hsm_op_key_gen_flags_t flags)
{

    op_manage_key_args_t manage_args;

    uint8_t enc_key[512] = {0x00, 0x01, 0x02, 0x03,
                            0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B};


    // =========== INJECT KEYS ================= //
    do
    {

        ASSERT_EQUAL_HIGH_API(icrypto_cipher_one_go(key_in, enc_key + 12, key_size, ICRYPTO_AES_256_GCM, kek_data, enc_key, 12, NULL, 0U, 16), (int)(key_size + 16));

        manage_args.key_identifier = key_id;
        manage_args.kek_identifier = kek_handle;
        manage_args.input_size = 12 + key_size + 16;
        manage_args.key_type = key_type;
        manage_args.key_group = key_group;
        manage_args.flags = flags; /* Create */
        manage_args.key_info = key_info;
        manage_args.input_data = enc_key;
        ASSERT_EQUAL_HIGH_API(hsm_manage_key(sg0_key_mgmt_srv, &manage_args), HSM_NO_ERROR);

        return TRUE_TEST;

    } while (0);

    return FALSE_TEST;
}

int isen_hsm_key_injection(hsm_hdl_t sg0_key_mgmt_srv, uint32_t *key_id, hsm_key_type_t key_type, uint8_t *key_in, uint32_t kek_handle, uint8_t *kek_data, uint32_t key_size)
{
    return isen_hsm_key_injection_custom(sg0_key_mgmt_srv, key_id, key_type, key_in, kek_handle, kek_data, key_size, 1U, 0U, HSM_OP_KEY_GENERATION_FLAGS_CREATE);
}

/*========= OTP ROOT KEK ==========*/

int isen_hsm_key_injection_custom_otp_kek(hsm_hdl_t sg0_key_mgmt_srv, uint32_t *key_id, hsm_key_type_t key_type,
                           uint8_t *key_in, uint8_t *kek_data, uint32_t key_size,
                           uint16_t key_group, hsm_key_info_t key_info, hsm_op_key_gen_flags_t flags)
{

    op_manage_key_args_t manage_args;

    uint8_t enc_key[512] = {0x00, 0x01, 0x02, 0x03,
                            0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B};


    // =========== INJECT KEYS ================= //
    do
    {

        ASSERT_EQUAL_HIGH_API(icrypto_cipher_one_go(key_in, enc_key + 12, key_size, ICRYPTO_AES_256_GCM, kek_data, enc_key, 12, NULL, 0U, 16), (int)(key_size + 16));
/*        ITEST_LOG("Enc key ->");
        for (int i = 0; i < (12 + key_size + 16); i++) {
            ITEST_LOG("0x%x, ", enc_key[i]);
        }
        ITEST_LOG("\n");
*/
        manage_args.key_identifier = key_id;
        manage_args.kek_identifier = 0U;
        manage_args.input_size = 12 + key_size + 16;
        manage_args.key_type = key_type;
        manage_args.key_group = key_group;
        manage_args.flags = flags; /* Create */
        manage_args.key_info = key_info;
        manage_args.input_data = enc_key;
        ASSERT_EQUAL_HIGH_API(hsm_manage_key(sg0_key_mgmt_srv, &manage_args), HSM_NO_ERROR);

        return TRUE_TEST;

    } while (0);

    return FALSE_TEST;
}

#if 1
int isen_hsm_key_injection_otp_kek(hsm_hdl_t sg0_key_mgmt_srv, uint32_t *key_id, hsm_key_type_t key_type, uint8_t *key_in, uint32_t key_size)
{
    uint8_t key_enc_key[32] = { 0x6a, 0xb5, 0x3e, 0x0e, 0x4d, 0xa4, 0x9f, 0x95, 0xd5, 0xb5, 0xee, 0x7f, 
                                0x83, 0x00, 0x26, 0xa2, 0x70, 0xd7, 0xd9, 0x4e, 0xaf, 0xbc, 0x1f, 0x55, 
                                0xf1, 0x59, 0x71, 0x30, 0x2a, 0x41, 0x18, 0x55
    };
    return isen_hsm_key_injection_custom_otp_kek(sg0_key_mgmt_srv, key_id, key_type, key_in, key_enc_key, key_size, 1U, 0U, HSM_OP_KEY_GENERATION_FLAGS_CREATE | HSM_OP_MANAGE_KEY_FLAGS_OTP_ROOT_KEK);
}

int isen_hsm_key_injection_v2x_otp_kek(hsm_hdl_t sg0_key_mgmt_srv, uint32_t *key_id, hsm_key_type_t key_type, uint8_t *key_in, uint32_t key_size)
{
    uint8_t key_enc_key[32] = { 0x44, 0x9a, 0x32, 0xa7, 0x62, 0x09, 0xd4, 0x6d, 0x6c, 0x83, 0xf6, 0xa5,
                                0x48, 0x62, 0x7e, 0xe7, 0x73, 0x33, 0x93, 0x61, 0x72, 0xdd, 0x66, 0xf8,
                                0x48, 0xc7, 0xa0, 0xa6, 0x7d, 0xb5, 0x99, 0x58
    };
    return isen_hsm_key_injection_custom_otp_kek(sg0_key_mgmt_srv, key_id, key_type, key_in, key_enc_key, key_size, 1U, 0U, HSM_OP_KEY_GENERATION_FLAGS_CREATE| HSM_OP_MANAGE_KEY_FLAGS_OTP_ROOT_KEK);
}
#else

int isen_hsm_key_injection_otp_kek(hsm_hdl_t sg0_key_mgmt_srv, uint32_t *key_id, hsm_key_type_t key_type, uint8_t *key_in, uint32_t key_size)
{
    uint8_t key_enc_key[32] = { 0x80, 0x89, 0xca, 0x0d, 0xd5, 0xf6, 0x8b, 0xfa, 0x05, 0xd7, 0x8c, 0xc0, 0xf0, 0xd5, 0x82, 0x2e, 0xdd, 0x71, 0x06, 0xfe, 0x5a, 0x52, 0xfd, 0xbf, 0x3d, 0xae, 0x96, 0xb4, 0x78, 0x6a, 0x74, 0x09
    };
    return isen_hsm_key_injection_custom_otp_kek(sg0_key_mgmt_srv, key_id, key_type, key_in, key_enc_key, key_size, 1U, 0U, HSM_OP_KEY_GENERATION_FLAGS_CREATE | HSM_OP_MANAGE_KEY_FLAGS_OTP_ROOT_KEK);
}

int isen_hsm_key_injection_v2x_otp_kek(hsm_hdl_t sg0_key_mgmt_srv, uint32_t *key_id, hsm_key_type_t key_type, uint8_t *key_in, uint32_t key_size)
{
    uint8_t key_enc_key[32] = { 0x14, 0xff, 0x1f, 0xff, 0xd7, 0xfe, 0x97, 0x7c, 0x68, 0xa2, 0x15, 0x98, 0x92, 0x76, 0x31, 0x0e, 0x21, 0xdc, 0xf9, 0x13, 0x78, 0x49, 0x0e, 0x46, 0xc1, 0xa4, 0x64, 0xbb, 0x66, 0xc9, 0xff, 0xa7
    };
    return isen_hsm_key_injection_custom_otp_kek(sg0_key_mgmt_srv, key_id, key_type, key_in, key_enc_key, key_size, 1U, 0U, HSM_OP_KEY_GENERATION_FLAGS_CREATE| HSM_OP_MANAGE_KEY_FLAGS_OTP_ROOT_KEK);
}
#endif