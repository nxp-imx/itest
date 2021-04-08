#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
// requirement: aes gcm iv should contain counter part and fixed part, or be random, depending on setting


int seco_aes_gcm_iv_001(void){
    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    open_svc_cipher_args_t cipher_srv_args;
    op_auth_enc_args_t auth_enc_args;

    op_generate_key_args_t gen_key_args;

    hsm_hdl_t sg0_sess;
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    hsm_hdl_t sg0_cipher_hdl;

    uint32_t key_id;
    uint32_t idx;
    uint32_t num_matching_bytes;
    uint64_t counter_val1;
    uint64_t counter_val2;

    uint8_t plaintext[128];
    uint8_t ciphertext[128 + +16 + 12];
    uint8_t aad[16];
    uint8_t fixed_iv[4];
    uint8_t iv1[12];
    uint8_t iv2[12];

    // INPUT BUFF AS RANDOM
    ASSERT_EQUAL(randomize(plaintext, sizeof(plaintext)), sizeof(plaintext));
    ASSERT_EQUAL(randomize(aad, sizeof(aad)), sizeof(aad));
    ASSERT_EQUAL(randomize(fixed_iv, sizeof(fixed_iv)), sizeof(fixed_iv));
    // STORED IVs EQUAL
    memset(iv1, 0U, sizeof(iv1));
    memset(iv2, 0U, sizeof(iv2));

    clear_seco_nvm();

    // START NVM
    ASSERT_NOT_EQUAL(start_nvm_seco(), NVM_STATUS_STOPPED);

    // SECO SESSION
    args.session_priority = 0;
    args.operating_mode = 0;
    ASSERT_EQUAL(hsm_open_session(&args, &sg0_sess), HSM_NO_ERROR);

    // KEY STORE SECO
    key_store_srv_args.key_store_identifier = (uint32_t) 0x12121212;
    key_store_srv_args.authentication_nonce = (uint32_t) 0x12345678;
    key_store_srv_args.max_updates_number = 12;
    key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
    key_store_srv_args.signed_message = NULL;
    key_store_srv_args.signed_msg_size = 0;
    ASSERT_EQUAL(hsm_open_key_store_service(sg0_sess, &key_store_srv_args, &sg0_key_store_serv), HSM_NO_ERROR);

    // KEY MGMNT SECO
    key_mgmt_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_key_management_service(sg0_key_store_serv, &key_mgmt_srv_args, &sg0_key_mgmt_srv), HSM_NO_ERROR);

    // PARAM AES KEY_GEN transient
    gen_key_args.key_identifier = &key_id;
    gen_key_args.out_size = 0;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_AES_128;
    gen_key_args.key_group = 1;
    gen_key_args.key_info = HSM_KEY_INFO_TRANSIENT;
    gen_key_args.out_key = NULL;
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

    //OPEN CIPHER SG0
    cipher_srv_args.flags = 0U;
    ASSERT_EQUAL(hsm_open_cipher_service(sg0_key_store_serv, &cipher_srv_args, &sg0_cipher_hdl), HSM_NO_ERROR);

    // TEST FORMAT OF IV FOR FULL GENERATION MODE

    // AUTH ENC KEY AES128 -> ENCRYPT
    auth_enc_args.key_identifier = key_id;
    auth_enc_args.iv = NULL;
    auth_enc_args.iv_size = 0U;
    auth_enc_args.aad = aad;
    auth_enc_args.aad_size = sizeof(aad);
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV;
    auth_enc_args.input = plaintext;
    auth_enc_args.output = ciphertext;
    auth_enc_args.input_size = sizeof(plaintext);
    auth_enc_args.output_size = sizeof(ciphertext);
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);

    // EXTRACT GENERATED IV
    memcpy(iv1,&ciphertext[sizeof(ciphertext)-sizeof(iv1)], sizeof(iv1));

    // AUTH ENC KEY AES128 -> ENCRYPT (exact same input - IV should be different)
    auth_enc_args.key_identifier = key_id;
    auth_enc_args.iv = NULL;
    auth_enc_args.iv_size = 0U;
    auth_enc_args.aad = aad;
    auth_enc_args.aad_size = sizeof(aad);
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV;
    auth_enc_args.input = plaintext;
    auth_enc_args.output = ciphertext;
    auth_enc_args.input_size = sizeof(plaintext);
    auth_enc_args.output_size = sizeof(ciphertext);
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);

    // EXTRACT GENERATED IV
    memcpy(iv2,&ciphertext[sizeof(ciphertext)-sizeof(iv2)], sizeof(iv2));

    // WEAK RANDOMNESS TEST - NO MORE THAN 3 BYTES IDENTICAL
    num_matching_bytes = 0;
    for (idx = 0; idx < sizeof(iv1); idx++) {
        if (iv1[idx] == iv2[idx]) {
            num_matching_bytes++;
        }
    }
    ASSERT_TRUE((num_matching_bytes < 4));

    // TEST FORMAT OF IV FOR COUNTER MODE

    // AUTH ENC KEY AES128 -> ENCRYPT
    auth_enc_args.key_identifier = key_id;
    auth_enc_args.iv = fixed_iv;
    auth_enc_args.iv_size = sizeof(fixed_iv);
    auth_enc_args.aad = aad;
    auth_enc_args.aad_size = sizeof(aad);
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV;
    auth_enc_args.input = plaintext;
    auth_enc_args.output = ciphertext;
    auth_enc_args.input_size = sizeof(plaintext);
    auth_enc_args.output_size = sizeof(ciphertext);
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);

    // EXTRACT GENERATED IV
    memcpy(iv1,&ciphertext[sizeof(ciphertext)-sizeof(iv1)], sizeof(iv1));
    // VERIFY FIXED PART
    ASSERT_EQUAL(memcmp(iv1, fixed_iv, sizeof(fixed_iv)), 0);
    // EXTRACT COUNTER
    counter_val1 = *(uint64_t *)(&(iv1[4]));

    // AUTH ENC KEY AES128 -> ENCRYPT (exact same input - counter should increment)
    auth_enc_args.key_identifier = key_id;
    auth_enc_args.iv = fixed_iv;
    auth_enc_args.iv_size = sizeof(fixed_iv);
    auth_enc_args.aad = aad;
    auth_enc_args.aad_size = sizeof(aad);
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV;
    auth_enc_args.input = plaintext;
    auth_enc_args.output = ciphertext;
    auth_enc_args.input_size = sizeof(plaintext);
    auth_enc_args.output_size = sizeof(ciphertext);
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);

    // EXTRACT GENERATED IV
    memcpy(iv2,&ciphertext[sizeof(ciphertext)-sizeof(iv2)], sizeof(iv2));
    // VERIFY FIXED PART
    ASSERT_EQUAL(memcmp(iv2, fixed_iv, sizeof(fixed_iv)), 0);
    // EXTRACT COUNTER
    counter_val2 = *(uint64_t *)(&(iv2[4]));

    // VERIFY COUNTER WAS INCREMENTED
    ASSERT_EQUAL(counter_val2, counter_val1 + 1);

    // CLOSE SRV KEY_MGMT AND KEY_STORE
    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);

    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_seco(), NVM_STATUS_STOPPED);

    return TRUE_TEST;
}
