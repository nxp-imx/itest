#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include "itest.h"

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
    0x60
};

static uint16_t size_privk_list[NB_ALGO] = {
    0x20,
    0x20,
    0x30,
    0x48,
    0x20,
    0x30,
    0x20,
    0x30
};

int get_key_param(hsm_key_type_t key_type,hsm_signature_scheme_id_t *scheme_id, uint16_t *size_pubk, uint16_t *size_privk) {

    uint32_t i;

    for(i = 0; i < NB_ALGO; i++) {
        if (key_type_list[i] == key_type) {
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
                                    hsm_key_group_t key_group, uint8_t *out_key, uint16_t out_key_size) {
    op_generate_key_args_t gen_key_args;

    // PARAM KEY_GEN strict_update
    gen_key_args.key_identifier = key_id;
    gen_key_args.out_size = out_key == NULL ? 0 : out_key_size;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE | HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
    gen_key_args.key_type = key_type;
    gen_key_args.key_group = key_group;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = out_key;
    do {
        // GEN KEY + STORE IN NVM
        ASSERT_EQUAL_HIGH_API(hsm_generate_key(key_store_serv, &gen_key_args), HSM_NO_ERROR);
        return TRUE_TEST;
    } while (0);
    return FALSE_TEST;
}

int isen_generate_key(hsm_hdl_t key_store_serv, uint32_t *key_id, hsm_key_type_t key_type,
                                    hsm_key_group_t key_group, uint8_t *out_key, uint16_t out_key_size) {
    op_generate_key_args_t gen_key_args;

    // PARAM KEY_GEN strict_update
    gen_key_args.key_identifier = key_id;
    gen_key_args.out_size = out_key == NULL ? 0 : out_key_size;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = key_type;
    gen_key_args.key_group = key_group;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = out_key;
    do {
        // GEN KEY + STORE IN NVM
        ASSERT_EQUAL_HIGH_API(hsm_generate_key(key_store_serv, &gen_key_args), HSM_NO_ERROR);
        return TRUE_TEST;
    } while (0);
    return FALSE_TEST;
}

int isen_kek_generation(hsm_hdl_t sg0_key_mgmt_srv, uint8_t *kek_data, uint32_t key_size, uint32_t *kek_handle){

    op_key_exchange_args_t key_exchange_args;

    EC_KEY *local_key = NULL;
    uint8_t *local_pub_key = NULL;
    uint8_t remote_pub_key[65];
    BN_CTX *bn_ctx = NULL;
    size_t local_pub_key_len;
    EC_POINT *remote_point = NULL;
    const EC_GROUP *curve_group = NULL;

    uint8_t ecdh_secret[32];
    uint8_t kdf_input[63];
    char FixedInfo[] = "NXP HSM USER KEY DERIVATION";
    EVP_MD_CTX *kdf_context = NULL;

    // =========== NEGOTIATE KEK FOR KEY INJECTION ================= //
    do {
        bn_ctx = BN_CTX_new();
        ASSERT_TRUE_HIGH_API((bn_ctx != NULL));

        local_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        ASSERT_TRUE_HIGH_API((local_key != NULL));

        curve_group = EC_KEY_get0_group(local_key);
        ASSERT_TRUE_HIGH_API((curve_group != NULL));

        ASSERT_EQUAL_HIGH_API(EC_KEY_generate_key(local_key),1);

        local_pub_key_len = EC_KEY_key2buf(local_key, POINT_CONVERSION_UNCOMPRESSED,
                        &local_pub_key, bn_ctx);
        ASSERT_EQUAL_HIGH_API(local_pub_key_len,65);

        key_exchange_args.key_identifier = 0;
        key_exchange_args.shared_key_identifier_array_size = sizeof(uint32_t);
        key_exchange_args.shared_key_identifier_array = (uint8_t *)kek_handle;
        key_exchange_args.ke_input_size = 64;
        key_exchange_args.ke_input = &local_pub_key[1];
        key_exchange_args.ke_output_size = 64;
        key_exchange_args.ke_output = &remote_pub_key[1];
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

        remote_pub_key[0] = 0x04;

        remote_point = EC_POINT_new(curve_group);
        ASSERT_TRUE_HIGH_API((remote_point != NULL));

        ASSERT_EQUAL_HIGH_API(EC_POINT_oct2point(curve_group, remote_point, remote_pub_key, 65, bn_ctx), 1);

        ASSERT_EQUAL_HIGH_API(ECDH_compute_key(ecdh_secret, sizeof(ecdh_secret), remote_point, local_key, NULL), 32);

        kdf_input[0] = 0;
        kdf_input[1] = 0;
        kdf_input[2] = 0;
        kdf_input[3] = 1;
        memcpy(&kdf_input[4], ecdh_secret, 32);
        memcpy(&kdf_input[36], FixedInfo, 27);

        kdf_context = EVP_MD_CTX_new();
        ASSERT_TRUE_HIGH_API((kdf_context != NULL));

        ASSERT_EQUAL_HIGH_API(EVP_DigestInit_ex(kdf_context, EVP_sha256(), NULL), 1);
        ASSERT_EQUAL_HIGH_API(EVP_DigestUpdate(kdf_context, kdf_input, sizeof(kdf_input)), 1);
        ASSERT_EQUAL_HIGH_API(EVP_DigestFinal_ex(kdf_context, kek_data, &key_size),1);

        EVP_MD_CTX_free(kdf_context);
        EC_POINT_free(remote_point);
        OPENSSL_free(local_pub_key);
        BN_CTX_free(bn_ctx);
        EC_KEY_free(local_key);
        return TRUE_TEST;
    } while (0);
    /*catch failure ASSERT HIGH API*/
    if (kdf_context != NULL)
        EVP_MD_CTX_free(kdf_context);
    if (remote_point != NULL)
        EC_POINT_free(remote_point);
    if (local_pub_key != NULL)
    OPENSSL_free(local_pub_key);
    if (bn_ctx != NULL)
        BN_CTX_free(bn_ctx);
    if (local_key != NULL)
        EC_KEY_free(local_key);
    return FALSE_TEST;
}

int isen_hsm_key_injection(hsm_hdl_t sg0_key_mgmt_srv, uint32_t *key_id, hsm_key_type_t key_type, uint8_t *key_in, uint32_t kek_handle, uint8_t *kek_data, uint32_t key_size){

    op_manage_key_args_t manage_args;

    uint8_t enc_key[512] = {0x00, 0x01, 0x02, 0x03,
                                0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0A, 0x0B };
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    int enc_len;

    // =========== INJECT KEYS ================= //
    do {
        cipher_ctx = EVP_CIPHER_CTX_new();
        ASSERT_TRUE_HIGH_API((cipher_ctx != NULL));

        ASSERT_EQUAL_HIGH_API(EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, kek_data, enc_key),1);
        enc_len = 16;
        ASSERT_EQUAL_HIGH_API(EVP_EncryptUpdate(cipher_ctx, &enc_key[12], &enc_len, key_in, key_size), 1);
        ASSERT_EQUAL_HIGH_API(EVP_EncryptFinal_ex(cipher_ctx, &enc_key[key_size+12], &enc_len), 1);
        ASSERT_EQUAL_HIGH_API(EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, 16, &enc_key[key_size+12]), 1);

        manage_args.key_identifier = key_id;
        manage_args.kek_identifier = kek_handle;
        manage_args.input_size = 12 + key_size + 16;
        manage_args.key_type = key_type;
        manage_args.key_group = 1;
        manage_args.flags = 2; /* Create */;
        manage_args.key_info = 0U;
        manage_args.input_data = enc_key;
        ASSERT_EQUAL_HIGH_API(hsm_manage_key(sg0_key_mgmt_srv, &manage_args), HSM_NO_ERROR);
        
        EVP_CIPHER_CTX_free(cipher_ctx);
        return TRUE_TEST;

    } while (0);
    /*catch failure ASSERT HIGH API*/
    if (cipher_ctx != NULL)
        EVP_CIPHER_CTX_free(cipher_ctx);

    return FALSE_TEST;
}
