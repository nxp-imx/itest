#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include "itest.h"

// auth encrypt test iv full generated + iv not fully generated

int seco_auth_enc_test(void){

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    op_key_exchange_args_t key_exchange_args;
    open_svc_cipher_args_t cipher_srv_args;
    op_auth_enc_args_t auth_enc_args;
    op_manage_key_args_t manage_args;

    hsm_hdl_t sg0_sess;
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    hsm_hdl_t sg0_cipher_hdl;
    uint32_t key_id_aes_128 = 0;
    uint32_t key_id_aes_192 = 0;
    uint32_t key_id_aes_256 = 0;
    uint8_t buff_encr[1024];
    uint8_t buff_decr[1024];
    uint8_t msg[1024];
    uint8_t ref_encr[1024];

    uint32_t msg_size = 378;
    uint8_t aad[16] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
    uint8_t *iv = &buff_encr[msg_size + 16U];

    uint32_t kek_handle;
    uint8_t kek_data[32];
    uint8_t aes_128_key_data[16];
    uint8_t aes_192_key_data[24];
    uint8_t aes_256_key_data[32];

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
    uint32_t key_size = sizeof(kek_data);

    uint8_t enc_key[12 + 48] = {0x00, 0x01, 0x02, 0x03,
                                0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0A, 0x0B };
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    int enc_len;


    clear_seco_nvm();

    // START NVM
    ASSERT_NOT_EQUAL(start_nvm_seco(), NVM_STATUS_STOPPED);

    // INPUT BUFF AS RANDOM
    ASSERT_EQUAL(randomize(msg, msg_size), msg_size);
    ASSERT_EQUAL(randomize(iv, 16), 16);
    ASSERT_EQUAL(randomize(kek_data, sizeof(kek_data)), sizeof(kek_data));
    ASSERT_EQUAL(randomize(aes_128_key_data, sizeof(aes_128_key_data)), sizeof(aes_128_key_data));
    ASSERT_EQUAL(randomize(aes_192_key_data, sizeof(aes_192_key_data)), sizeof(aes_192_key_data));
    ASSERT_EQUAL(randomize(aes_256_key_data, sizeof(aes_256_key_data)), sizeof(aes_256_key_data));

    // SECO SESSION
    args.session_priority = 0;
    args.operating_mode = 0;
    ASSERT_EQUAL(hsm_open_session(&args, &sg0_sess), HSM_NO_ERROR);

    // KEY STORE SG0
    key_store_srv_args.key_store_identifier = (uint32_t) 0x12121212;
    key_store_srv_args.authentication_nonce = (uint32_t) 0x12345678;
    key_store_srv_args.max_updates_number = 12;
    key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
    key_store_srv_args.signed_message = NULL;
    key_store_srv_args.signed_msg_size = 0;
    ASSERT_EQUAL(hsm_open_key_store_service(sg0_sess, &key_store_srv_args, &sg0_key_store_serv), HSM_NO_ERROR);

    //OPEN CIPHER SG0
    cipher_srv_args.flags = 0U;
    ASSERT_EQUAL(hsm_open_cipher_service(sg0_key_store_serv, &cipher_srv_args, &sg0_cipher_hdl), HSM_NO_ERROR);

    // KEY MGMNT SG0
    key_mgmt_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_key_management_service(sg0_key_store_serv, &key_mgmt_srv_args, &sg0_key_mgmt_srv), HSM_NO_ERROR);

    // =========== NEGOTIATE KEK FOR KEY INJECTION ================= //
    bn_ctx = BN_CTX_new();
    ASSERT_TRUE((bn_ctx != NULL));

    local_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    ASSERT_TRUE((local_key != NULL));

    curve_group = EC_KEY_get0_group(local_key);
    ASSERT_TRUE((curve_group != NULL));

    ASSERT_EQUAL(EC_KEY_generate_key(local_key),1);

    local_pub_key_len = EC_KEY_key2buf(local_key, POINT_CONVERSION_UNCOMPRESSED,
                       &local_pub_key, bn_ctx);
    ASSERT_EQUAL(local_pub_key_len,65);

    key_exchange_args.key_identifier = 0;
    key_exchange_args.shared_key_identifier_array_size = sizeof(uint32_t);
    key_exchange_args.shared_key_identifier_array = (uint8_t *)&kek_handle;
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
    ASSERT_EQUAL(hsm_key_exchange(sg0_key_mgmt_srv, &key_exchange_args), HSM_NO_ERROR);

    remote_pub_key[0] = 0x04;

    remote_point = EC_POINT_new(curve_group);
    ASSERT_TRUE((remote_point != NULL));

    ASSERT_EQUAL(EC_POINT_oct2point(curve_group, remote_point, remote_pub_key, 65, bn_ctx), 1);

    ASSERT_EQUAL(ECDH_compute_key(ecdh_secret, sizeof(ecdh_secret), remote_point, local_key, NULL), 32);

    kdf_input[0] = 0;
    kdf_input[1] = 0;
    kdf_input[2] = 0;
    kdf_input[3] = 1;
    memcpy(&kdf_input[4], ecdh_secret, 32);
    memcpy(&kdf_input[36], FixedInfo, 27);

    kdf_context = EVP_MD_CTX_new();
    ASSERT_TRUE((kdf_context != NULL));

    ASSERT_EQUAL(EVP_DigestInit_ex(kdf_context, EVP_sha256(), NULL), 1);
    ASSERT_EQUAL(EVP_DigestUpdate(kdf_context, kdf_input, sizeof(kdf_input)), 1);
    ASSERT_EQUAL(EVP_DigestFinal_ex(kdf_context, kek_data, &key_size),1);

    // =========== INJECT KEYS FOR AES GCM TEST ================= //

    cipher_ctx = EVP_CIPHER_CTX_new();
    ASSERT_TRUE((cipher_ctx != NULL));

    ASSERT_EQUAL(EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, kek_data, enc_key),1);
    enc_len = 16;
    ASSERT_EQUAL(EVP_EncryptUpdate(cipher_ctx, &enc_key[12], &enc_len, aes_128_key_data, 16), 1);
    ASSERT_EQUAL(EVP_EncryptFinal_ex(cipher_ctx, &enc_key[28], &enc_len), 1);
    ASSERT_EQUAL(EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, 16, &enc_key[28]), 1);

    manage_args.key_identifier = &key_id_aes_128;
    manage_args.kek_identifier = kek_handle;
    manage_args.input_size = 12 + 16 + 16;
    manage_args.key_type = HSM_KEY_TYPE_AES_128;
    manage_args.key_group = 1;
    manage_args.flags = 2; /* Create */;
    manage_args.key_info = 0U;
    manage_args.input_data = enc_key;
    ASSERT_EQUAL(hsm_manage_key(sg0_key_mgmt_srv, &manage_args), HSM_NO_ERROR);

    ASSERT_EQUAL(EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, kek_data, enc_key),1);
    enc_len = 24;
    ASSERT_EQUAL(EVP_EncryptUpdate(cipher_ctx, &enc_key[12], &enc_len, aes_192_key_data, 24), 1);
    ASSERT_EQUAL(EVP_EncryptFinal_ex(cipher_ctx, &enc_key[36], &enc_len), 1);
    ASSERT_EQUAL(EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, 16, &enc_key[36]), 1);

    manage_args.key_identifier = &key_id_aes_192;
    manage_args.kek_identifier = kek_handle;
    manage_args.input_size = 12 + 24 + 16;
    manage_args.key_type = HSM_KEY_TYPE_AES_192;
    manage_args.key_group = 1;
    manage_args.flags = 2; /* Create */;
    manage_args.key_info = 0U;
    manage_args.input_data = enc_key;
    ASSERT_EQUAL(hsm_manage_key(sg0_key_mgmt_srv, &manage_args), HSM_NO_ERROR);

    ASSERT_EQUAL(EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, kek_data, enc_key),1);
    enc_len = 32;
    ASSERT_EQUAL(EVP_EncryptUpdate(cipher_ctx, &enc_key[12], &enc_len, aes_256_key_data, 32), 1);
    ASSERT_EQUAL(EVP_EncryptFinal_ex(cipher_ctx, &enc_key[44], &enc_len), 1);
    ASSERT_EQUAL(EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, 16, &enc_key[44]), 1);

    manage_args.key_identifier = &key_id_aes_256;
    manage_args.kek_identifier = kek_handle;
    manage_args.input_size = 12 + 32 + 16;
    manage_args.key_type = HSM_KEY_TYPE_AES_256;
    manage_args.key_group = 1;
    manage_args.flags = 2; /* Create */;
    manage_args.key_info = 0U;
    manage_args.input_data = enc_key;
    ASSERT_EQUAL(hsm_manage_key(sg0_key_mgmt_srv, &manage_args), HSM_NO_ERROR);

    EVP_MD_CTX_free(kdf_context);
    EC_POINT_free(remote_point);
    OPENSSL_free(local_pub_key);
    BN_CTX_free(bn_ctx);
    EC_KEY_free(local_key);

    // ======================== FULL IV GENERATED ========================
    // AUTH ENC KEY AES128 -> ENCRYPT
    auth_enc_args.key_identifier = key_id_aes_128;
    auth_enc_args.iv = iv;
    auth_enc_args.iv_size = 0U;
    auth_enc_args.aad = aad;
    auth_enc_args.aad_size = 16U;
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV;
    auth_enc_args.input = msg;
    auth_enc_args.output = buff_encr;
    auth_enc_args.input_size = msg_size;
    auth_enc_args.output_size = msg_size + 16U + 12U;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);

    // CALCULATE REFERENCE ENCRYPTED DATA WITH GENERATED IV
    ASSERT_EQUAL(EVP_EncryptInit_ex(cipher_ctx, EVP_aes_128_gcm(), NULL, aes_128_key_data, iv),1);
    enc_len = auth_enc_args.aad_size;
    ASSERT_EQUAL(EVP_EncryptUpdate(cipher_ctx, NULL, &enc_len, aad, enc_len), 1);
    enc_len = auth_enc_args.input_size;
    ASSERT_EQUAL(EVP_EncryptUpdate(cipher_ctx, ref_encr, &enc_len, msg, enc_len), 1);
    ASSERT_EQUAL(EVP_EncryptFinal_ex(cipher_ctx, &ref_encr[auth_enc_args.input_size], &enc_len), 1);
    ASSERT_EQUAL(EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, 16, &ref_encr[auth_enc_args.input_size]), 1);

    // VERIFY ENCRYPTED DATA + TAG
    ASSERT_EQUAL(memcmp(buff_encr, ref_encr, msg_size + 16U), 0);

    // AUTH ENC KEY AES128 -> DECRYPT
    auth_enc_args.key_identifier = key_id_aes_128;
    auth_enc_args.iv = iv;
    auth_enc_args.iv_size = 12U;
    auth_enc_args.aad = aad;
    auth_enc_args.aad_size = 0;
    auth_enc_args.aad_size = 16U;
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT;
    auth_enc_args.input = buff_encr;
    auth_enc_args.output = buff_decr;
    auth_enc_args.input_size = msg_size + 16U;
    auth_enc_args.output_size = msg_size;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);
    // CHECK DECRYPTED OUTPUT
    ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);

    // AUTH ENC KEY AES192 -> ENCRYPT
    auth_enc_args.key_identifier = key_id_aes_192;
    auth_enc_args.iv = iv;
    auth_enc_args.iv_size = 0U;
    auth_enc_args.aad = aad;
    auth_enc_args.aad_size = 16U;
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV;
    auth_enc_args.input = msg;
    auth_enc_args.output = buff_encr;
    auth_enc_args.input_size = msg_size;
    auth_enc_args.output_size = msg_size + 16U + 12U;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);

    // CALCULATE REFERENCE ENCRYPTED DATA WITH GENERATED IV
    ASSERT_EQUAL(EVP_EncryptInit_ex(cipher_ctx, EVP_aes_192_gcm(), NULL, aes_192_key_data, iv),1);
    enc_len = auth_enc_args.aad_size;
    ASSERT_EQUAL(EVP_EncryptUpdate(cipher_ctx, NULL, &enc_len, aad, enc_len), 1);
    enc_len = auth_enc_args.input_size;
    ASSERT_EQUAL(EVP_EncryptUpdate(cipher_ctx, ref_encr, &enc_len, msg, enc_len), 1);
    ASSERT_EQUAL(EVP_EncryptFinal_ex(cipher_ctx, &ref_encr[auth_enc_args.input_size], &enc_len), 1);
    ASSERT_EQUAL(EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, 16, &ref_encr[auth_enc_args.input_size]), 1);

    // VERIFY ENCRYPTED DATA + TAG
    ASSERT_EQUAL(memcmp(buff_encr, ref_encr, msg_size + 16U), 0);

    // AUTH ENC KEY AES192 -> DECRYPT
    auth_enc_args.key_identifier = key_id_aes_192;
    auth_enc_args.iv = iv;
    auth_enc_args.iv_size = 12U;
    auth_enc_args.aad = aad;
    auth_enc_args.aad_size = 16U;
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT;
    auth_enc_args.input = buff_encr;
    auth_enc_args.output = buff_decr;
    auth_enc_args.input_size = msg_size + 16U;
    auth_enc_args.output_size = msg_size;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);
    // CHECK DECRYPTED OUTPUT
    ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);


    // AUTH ENC KEY AES256 -> ENCRYPT
    auth_enc_args.key_identifier = key_id_aes_256;
    auth_enc_args.iv = iv;
    auth_enc_args.iv_size = 0U;
    auth_enc_args.aad = aad;
    auth_enc_args.aad_size = 16U;
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV;
    auth_enc_args.input = msg;
    auth_enc_args.output = buff_encr;
    auth_enc_args.input_size = msg_size;
    auth_enc_args.output_size = msg_size + 16U + 12U;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);

    // CALCULATE REFERENCE ENCRYPTED DATA WITH GENERATED IV
    ASSERT_EQUAL(EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, aes_256_key_data, iv),1);
    enc_len = auth_enc_args.aad_size;
    ASSERT_EQUAL(EVP_EncryptUpdate(cipher_ctx, NULL, &enc_len, aad, enc_len), 1);
    enc_len = auth_enc_args.input_size;
    ASSERT_EQUAL(EVP_EncryptUpdate(cipher_ctx, ref_encr, &enc_len, msg, enc_len), 1);
    ASSERT_EQUAL(EVP_EncryptFinal_ex(cipher_ctx, &ref_encr[auth_enc_args.input_size], &enc_len), 1);
    ASSERT_EQUAL(EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, 16, &ref_encr[auth_enc_args.input_size]), 1);

    // VERIFY ENCRYPTED DATA + TAG
    ASSERT_EQUAL(memcmp(buff_encr, ref_encr, msg_size + 16U), 0);

    // AUTH ENC KEY AES256 -> DECRYPT
    auth_enc_args.key_identifier = key_id_aes_256;
    auth_enc_args.iv = iv;
    auth_enc_args.iv_size = 12U;
    auth_enc_args.aad = aad;
    auth_enc_args.aad_size = 16U;
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT;
    auth_enc_args.input = buff_encr;
    auth_enc_args.output = buff_decr;
    auth_enc_args.input_size = msg_size + 16U;
    auth_enc_args.output_size = msg_size;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);
    // CHECK DECRYPTED OUTPUT
    ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);

    // ======================== NOT FULL IV GENERATED ========================
    // INPUT BUFF AS RANDOM
    ASSERT_EQUAL(randomize(msg, msg_size), msg_size);
    ASSERT_EQUAL(randomize(iv, 16), 16);

    // AUTH ENC KEY AES128 -> ENCRYPT
    auth_enc_args.key_identifier = key_id_aes_128;
    auth_enc_args.iv = iv;
    auth_enc_args.iv_size = 4U;
    auth_enc_args.aad = aad;
    auth_enc_args.aad_size = 16U;
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV;
    auth_enc_args.input = msg;
    auth_enc_args.output = buff_encr;
    auth_enc_args.input_size = msg_size;
    auth_enc_args.output_size = msg_size + 16U + 12U;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);
    // BAD PARAM TEST
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_INVALID_PARAM);

    // CALCULATE REFERENCE ENCRYPTED DATA WITH GENERATED IV
    ASSERT_EQUAL(EVP_EncryptInit_ex(cipher_ctx, EVP_aes_128_gcm(), NULL, aes_128_key_data, iv),1);
    enc_len = auth_enc_args.aad_size;
    ASSERT_EQUAL(EVP_EncryptUpdate(cipher_ctx, NULL, &enc_len, aad, enc_len), 1);
    enc_len = auth_enc_args.input_size;
    ASSERT_EQUAL(EVP_EncryptUpdate(cipher_ctx, ref_encr, &enc_len, msg, enc_len), 1);
    ASSERT_EQUAL(EVP_EncryptFinal_ex(cipher_ctx, &ref_encr[auth_enc_args.input_size], &enc_len), 1);
    ASSERT_EQUAL(EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, 16, &ref_encr[auth_enc_args.input_size]), 1);

    // VERIFY ENCRYPTED DATA + TAG
    ASSERT_EQUAL(memcmp(buff_encr, ref_encr, msg_size + 16U), 0);

    // AUTH ENC KEY AES128 -> DECRYPT
    auth_enc_args.key_identifier = key_id_aes_128;
    auth_enc_args.iv = iv;
    auth_enc_args.iv_size = 12U;
    auth_enc_args.aad = aad;
    auth_enc_args.aad_size = 16U;
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT;
    auth_enc_args.input = buff_encr;
    auth_enc_args.output = buff_decr;
    auth_enc_args.input_size = msg_size + 16U;
    auth_enc_args.output_size = msg_size;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);
    // CHECK DECRYPTED OUTPUT
    ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);

    // AUTH ENC KEY AES192 -> ENCRYPT
    auth_enc_args.key_identifier = key_id_aes_192;
    auth_enc_args.iv = iv;
    auth_enc_args.iv_size = 4U;
    auth_enc_args.aad = aad;
    auth_enc_args.aad_size = 16U;
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV;
    auth_enc_args.input = msg;
    auth_enc_args.output = buff_encr;
    auth_enc_args.input_size = msg_size;
    auth_enc_args.output_size = msg_size + 16U + 12U;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);

    // CALCULATE REFERENCE ENCRYPTED DATA WITH GENERATED IV
    ASSERT_EQUAL(EVP_EncryptInit_ex(cipher_ctx, EVP_aes_192_gcm(), NULL, aes_192_key_data, iv),1);
    enc_len = auth_enc_args.aad_size;
    ASSERT_EQUAL(EVP_EncryptUpdate(cipher_ctx, NULL, &enc_len, aad, enc_len), 1);
    enc_len = auth_enc_args.input_size;
    ASSERT_EQUAL(EVP_EncryptUpdate(cipher_ctx, ref_encr, &enc_len, msg, enc_len), 1);
    ASSERT_EQUAL(EVP_EncryptFinal_ex(cipher_ctx, &ref_encr[auth_enc_args.input_size], &enc_len), 1);
    ASSERT_EQUAL(EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, 16, &ref_encr[auth_enc_args.input_size]), 1);

    // VERIFY ENCRYPTED DATA + TAG
    ASSERT_EQUAL(memcmp(buff_encr, ref_encr, msg_size + 16U), 0);

    // AUTH ENC KEY AES192 -> DECRYPT
    auth_enc_args.key_identifier = key_id_aes_192;
    auth_enc_args.iv = iv;
    auth_enc_args.iv_size = 12U;
    auth_enc_args.aad = aad;
    auth_enc_args.aad_size = 16U;
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT;
    auth_enc_args.input = buff_encr;
    auth_enc_args.output = buff_decr;
    auth_enc_args.input_size = msg_size + 16U;
    auth_enc_args.output_size = msg_size;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);
    // CHECK DECRYPTED OUTPUT
    ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);


    // AUTH ENC KEY AES256 -> ENCRYPT
    auth_enc_args.key_identifier = key_id_aes_256;
    auth_enc_args.iv = iv;
    auth_enc_args.iv_size = 4U;
    auth_enc_args.aad = aad;
    auth_enc_args.aad_size = 16U;
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV;
    auth_enc_args.input = msg;
    auth_enc_args.output = buff_encr;
    auth_enc_args.input_size = msg_size;
    auth_enc_args.output_size = msg_size + 16U + 12U;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);

    // CALCULATE REFERENCE ENCRYPTED DATA WITH GENERATED IV
    ASSERT_EQUAL(EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, aes_256_key_data, iv),1);
    enc_len = auth_enc_args.aad_size;
    ASSERT_EQUAL(EVP_EncryptUpdate(cipher_ctx, NULL, &enc_len, aad, enc_len), 1);
    enc_len = auth_enc_args.input_size;
    ASSERT_EQUAL(EVP_EncryptUpdate(cipher_ctx, ref_encr, &enc_len, msg, enc_len), 1);
    ASSERT_EQUAL(EVP_EncryptFinal_ex(cipher_ctx, &ref_encr[auth_enc_args.input_size], &enc_len), 1);
    ASSERT_EQUAL(EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, 16, &ref_encr[auth_enc_args.input_size]), 1);

    // VERIFY ENCRYPTED DATA + TAG
    ASSERT_EQUAL(memcmp(buff_encr, ref_encr, msg_size + 16U), 0);

    // AUTH ENC KEY AES256 -> DECRYPT
    auth_enc_args.key_identifier = key_id_aes_256;
    auth_enc_args.iv = iv;
    auth_enc_args.iv_size = 12U;
    auth_enc_args.aad = aad;
    auth_enc_args.aad_size = 16U;
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT;
    auth_enc_args.input = buff_encr;
    auth_enc_args.output = buff_decr;
    auth_enc_args.input_size = msg_size + 16U;
    auth_enc_args.output_size = msg_size;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);
    // CHECK DECRYPTED OUTPUT
    ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);

    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_seco(), NVM_STATUS_STOPPED);

    EVP_CIPHER_CTX_free(cipher_ctx);

    return TRUE_TEST;
}
