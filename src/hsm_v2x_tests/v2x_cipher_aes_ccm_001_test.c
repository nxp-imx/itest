#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
#include "crypto_utils/cipher_aes.h"
// requirement: enc/decr with all aes ccm 128/192/256 double check with openssl

int v2x_cipher_aes_ccm_001(void){

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    open_svc_cipher_args_t cipher_srv_args;
    op_cipher_one_go_args_t cipher_args;

    uint32_t kek_handle;
    uint8_t kek_data[32];
    uint32_t key_size = sizeof(kek_data);
    uint8_t aes_128_key_data[16];
    uint8_t aes_192_key_data[24];
    uint8_t aes_256_key_data[32];
    
    hsm_hdl_t sg0_sess;
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    hsm_hdl_t sg0_cipher_hdl;
    uint32_t key_id_aes_128 = 0;
    uint32_t key_id_aes_192 = 0;
    uint32_t key_id_aes_256 = 0;
    uint8_t buff_encr[1024];
    uint8_t buff_decr[1024];
    uint8_t expected_enc[1024];
    uint8_t msg[1024];
    uint8_t iv[16];
    uint32_t msg_size;

    clear_v2x_nvm();

    // INPUT BUFF AS RANDOM
    ASSERT_EQUAL(randomize(msg, 128), 128);
    ASSERT_EQUAL(randomize(iv, 16), 16);
    ASSERT_EQUAL(randomize(kek_data, sizeof(kek_data)), sizeof(kek_data));
    ASSERT_EQUAL(randomize(aes_128_key_data, sizeof(aes_128_key_data)), sizeof(aes_128_key_data));
    ASSERT_EQUAL(randomize(aes_192_key_data, sizeof(aes_192_key_data)), sizeof(aes_192_key_data));
    ASSERT_EQUAL(randomize(aes_256_key_data, sizeof(aes_256_key_data)), sizeof(aes_256_key_data));

    // START NVM
    ASSERT_NOT_EQUAL(start_nvm_v2x(), NVM_STATUS_STOPPED);

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

    // KEY MGMNT SG0
    key_mgmt_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_key_management_service(sg0_key_store_serv, &key_mgmt_srv_args, &sg0_key_mgmt_srv), HSM_NO_ERROR);

    //OPEN CIPHER SG0
    cipher_srv_args.flags = 0U;
    ASSERT_EQUAL(hsm_open_cipher_service(sg0_key_store_serv, &cipher_srv_args, &sg0_cipher_hdl), HSM_NO_ERROR);

    // =========== NEGOTIATE KEK FOR KEY INJECTION ================= //
    ASSERT_EQUAL(isen_kek_generation(sg0_key_mgmt_srv, kek_data, key_size, &kek_handle), TRUE_TEST);

    // =========== INJECT KEYS FOR AES GCM TEST ================= //
    ASSERT_EQUAL(isen_hsm_key_injection(sg0_key_mgmt_srv, &key_id_aes_128, HSM_KEY_TYPE_AES_128, aes_128_key_data, kek_handle, kek_data, 16), TRUE_TEST);

    // =========== INJECT KEYS FOR AES GCM TEST ================= //
    ASSERT_EQUAL(isen_hsm_key_injection(sg0_key_mgmt_srv, &key_id_aes_192, HSM_KEY_TYPE_AES_192, aes_192_key_data, kek_handle, kek_data, 24), TRUE_TEST);

    // =========== INJECT KEYS FOR AES GCM TEST ================= //
    ASSERT_EQUAL(isen_hsm_key_injection(sg0_key_mgmt_srv, &key_id_aes_256, HSM_KEY_TYPE_AES_256, aes_256_key_data, kek_handle, kek_data, 32), TRUE_TEST);

    for (msg_size = 16; msg_size <= 128; msg_size+= 1) {

        // CIPHER ONE GO AES_128 CCM -> ENCRYPT
        cipher_args.key_identifier = key_id_aes_128;
        cipher_args.iv = iv;
        cipher_args.iv_size = 12;
        cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CCM;
        cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
        cipher_args.input = msg;
        cipher_args.output = buff_encr;
        cipher_args.input_size = msg_size;
        cipher_args.output_size = msg_size + 16;
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
        ASSERT_EQUAL(icrypto_cipher_one_go(msg, expected_enc, msg_size, ICRYPTO_AES_128_CCM, aes_128_key_data, iv, NULL, 0), (int)(msg_size + 16));
        ASSERT_EQUAL(memcmp(buff_encr, expected_enc, msg_size + 16), 0);

        // CIPHER ONE GO AES_128 CCM -> DECRYPT
        cipher_args.key_identifier = key_id_aes_128;
        cipher_args.iv = iv;
        cipher_args.iv_size = 12;
        cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CCM;
        cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
        cipher_args.input = buff_encr;
        cipher_args.output = buff_decr;
        cipher_args.input_size = msg_size + 16;
        cipher_args.output_size = msg_size;
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
        // CHECK DECRYPTED OUTPUT
        ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);

        /*========================================================*/

        // CIPHER ONE GO AES_192 CCM -> ENCRYPT
        cipher_args.key_identifier = key_id_aes_192;
        cipher_args.iv = iv;
        cipher_args.iv_size = 12;
        cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CCM;
        cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
        cipher_args.input = msg;
        cipher_args.output = buff_encr;
        cipher_args.input_size = msg_size;
        cipher_args.output_size = msg_size + 16;
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
        ASSERT_EQUAL(icrypto_cipher_one_go(msg, expected_enc, msg_size, ICRYPTO_AES_192_CCM, aes_192_key_data, iv, NULL, 0), (int)(msg_size + 16));
        ASSERT_EQUAL(memcmp(buff_encr, expected_enc, msg_size + 16), 0);

        // CIPHER ONE GO AES_192 CCM -> DECRYPT
        cipher_args.key_identifier = key_id_aes_192;
        cipher_args.iv = iv;
        cipher_args.iv_size = 12;
        cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CCM;
        cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
        cipher_args.input = buff_encr;
        cipher_args.output = buff_decr;
        cipher_args.input_size = msg_size + 16;
        cipher_args.output_size = msg_size;
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
        // CHECK DECRYPTED OUTPUT
        ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);

        /*========================================================*/

        // CIPHER ONE GO AES_256 CCM -> ENCRYPT
        cipher_args.key_identifier = key_id_aes_256;
        cipher_args.iv = iv;
        cipher_args.iv_size = 12;
        cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CCM;
        cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
        cipher_args.input = msg;
        cipher_args.output = buff_encr;
        cipher_args.input_size = msg_size;
        cipher_args.output_size = msg_size + 16;
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
        ASSERT_EQUAL(icrypto_cipher_one_go(msg, expected_enc, msg_size, ICRYPTO_AES_256_CCM, aes_256_key_data, iv, NULL, 0), (int)(msg_size + 16));
        ASSERT_EQUAL(memcmp(buff_encr, expected_enc, msg_size + 16), 0);

        // CIPHER ONE GO AES_256 CCM -> DECRYPT
        cipher_args.key_identifier = key_id_aes_256;
        cipher_args.iv = iv;
        cipher_args.iv_size = 12;
        cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CCM;
        cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
        cipher_args.input = buff_encr;
        cipher_args.output = buff_decr;
        cipher_args.input_size = msg_size + 16;
        cipher_args.output_size = msg_size;
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
        // CHECK DECRYPTED OUTPUT
        ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);

    }

    ASSERT_EQUAL(hsm_close_cipher_service(sg0_cipher_hdl), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_v2x(), NVM_STATUS_STOPPED);

    return TRUE_TEST;
}
