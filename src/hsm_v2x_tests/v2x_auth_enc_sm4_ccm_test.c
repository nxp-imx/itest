#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include "itest.h"
#include "test_vectors/tv_cipher_sm4_ccm.h"

// auth encrypt/decrypt sm4 ccm test iv full generated + iv not fully generated

int v2x_auth_enc_sm4_ccm_test(void){

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    open_svc_cipher_args_t cipher_srv_args;
    op_auth_enc_args_t auth_enc_args;

    hsm_hdl_t sg0_sess;
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    hsm_hdl_t sg0_cipher_hdl;
    uint32_t key_id_aes_128 = 0U;
    uint8_t buff_encr[1024];
    uint8_t buff_decr[1024];
    uint8_t *msg;
    uint16_t i = 0;
    //uint8_t *ref_encr = NULL;
    //uint8_t iv_tmp[16] = {0x0, 0x4, 0x6, 0xff};

    uint32_t msg_size = 0U;
    uint8_t aad[16] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
    uint8_t *iv;

    uint32_t kek_handle;
    uint8_t kek_data[32];
    uint8_t *aes_128_key_data;

    uint32_t key_size = sizeof(kek_data);

    clear_v2x_nvm();

    // START NVM
    ASSERT_NOT_EQUAL(start_nvm_v2x(), NVM_STATUS_STOPPED);

    // INPUT BUFF AS RANDOM
    ASSERT_EQUAL(randomize(kek_data, sizeof(kek_data)), sizeof(kek_data));

    // SG0
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_HIGH;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK;
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
    ASSERT_EQUAL(isen_kek_generation(sg0_key_mgmt_srv, kek_data, key_size, &kek_handle), TRUE_TEST);

    for (i = 0; i < test_data_size_sm4_ccm; i++) {

        msg = test_data_sm4_ccm[i].message;
        msg_size = test_data_sm4_ccm[i].message_length;
        aes_128_key_data = test_data_sm4_ccm[i].sm4_key;
        iv = test_data_sm4_ccm[i].nonce;

        // =========== INJECT KEYS FOR AES GCM TEST ================= //
        ASSERT_EQUAL(isen_hsm_key_injection(sg0_key_mgmt_srv, &key_id_aes_128, HSM_KEY_TYPE_SM4_128, aes_128_key_data, kek_handle, kek_data, 16), TRUE_TEST);

        // ======================== TEST_VECTOR DECRYPT ======================

        // AUTH ENC KEY AES128 -> DECRYPT
        auth_enc_args.key_identifier = key_id_aes_128;
        auth_enc_args.iv = iv;
        auth_enc_args.iv_size = 12U;
        auth_enc_args.aad = aad;
        auth_enc_args.aad_size = 0U;
        auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_SM4_CCM;
        auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT;
        auth_enc_args.input = test_data_sm4_ccm[i].encrypted_data;
        auth_enc_args.output = buff_decr;
        auth_enc_args.input_size = test_data_sm4_ccm[i].encrypted_length;
        auth_enc_args.output_size = msg_size;
        ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);
        // CHECK DECRYPTED OUTPUT
        ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);

        // ======================== FULL IV GENERATED ========================

        iv = &buff_encr[msg_size + 16U];

        // AUTH ENC KEY AES128 -> ENCRYPT
        auth_enc_args.key_identifier = key_id_aes_128;
        auth_enc_args.iv = iv;
        auth_enc_args.iv_size = 0U;
        auth_enc_args.aad = aad;
        auth_enc_args.aad_size = 0U;
        auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_SM4_CCM;
        auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV;
        auth_enc_args.input = msg;
        auth_enc_args.output = buff_encr;
        auth_enc_args.input_size = msg_size;
        auth_enc_args.output_size = msg_size + 16U + 12U;
        ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);

        // AUTH ENC KEY AES128 -> DECRYPT
        auth_enc_args.key_identifier = key_id_aes_128;
        auth_enc_args.iv = iv;
        auth_enc_args.iv_size = 12U;
        auth_enc_args.aad = aad;
        auth_enc_args.aad_size = 0U;
        auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_SM4_CCM;
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
        ASSERT_EQUAL(randomize(iv, 16), 16);

        // AUTH ENC KEY AES128 -> ENCRYPT
        auth_enc_args.key_identifier = key_id_aes_128;
        auth_enc_args.iv = iv;
        auth_enc_args.iv_size = 4U;
        auth_enc_args.aad = aad;
        auth_enc_args.aad_size = 16U;
        auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_SM4_CCM;
        auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV;
        auth_enc_args.input = msg;
        auth_enc_args.output = buff_encr;
        auth_enc_args.input_size = msg_size;
        auth_enc_args.output_size = msg_size + 16U + 12U;
        ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);
        // BAD PARAM TEST
        auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT;
        ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_INVALID_PARAM);

        // AUTH ENC KEY AES128 -> DECRYPT
        auth_enc_args.key_identifier = key_id_aes_128;
        auth_enc_args.iv = iv;
        auth_enc_args.iv_size = 12U;
        auth_enc_args.aad = aad;
        auth_enc_args.aad_size = 16U;
        auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_SM4_CCM;
        auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT;
        auth_enc_args.input = buff_encr;
        auth_enc_args.output = buff_decr;
        auth_enc_args.input_size = msg_size + 16U;
        auth_enc_args.output_size = msg_size;
        ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);
        // CHECK DECRYPTED OUTPUT
        ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);

        // SET BAD TAG
        buff_encr[msg_size] = 0x00;
        buff_encr[msg_size + 1] = 0xFF;
        // AUTH ENC KEY AES128 -> DECRYPT with bad tag
        auth_enc_args.key_identifier = key_id_aes_128;
        auth_enc_args.iv = iv;
        auth_enc_args.iv_size = 12U;
        auth_enc_args.aad = aad;
        auth_enc_args.aad_size = 16U;
        auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_SM4_CCM;
        auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT;
        auth_enc_args.input = buff_encr;
        auth_enc_args.output = buff_decr;
        auth_enc_args.input_size = msg_size + 16U;
        auth_enc_args.output_size = msg_size;
        ASSERT_NOT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);
    }

    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_v2x(), NVM_STATUS_STOPPED);

    return TRUE_TEST;
}
