#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include "itest.h"
#include "test_vectors/tv_cipher_sm4_ccm.h"

// auth encrypt/decrypt sm4 ccm test iv full generated + iv not fully generated

int v2x_generic_crypto_sm4_ccm_test(void){

    open_session_args_t args;
    hsm_hdl_t key_generic_crypto_hdl;
    hsm_hdl_t sg0_sess;
    open_svc_key_generic_crypto_args_t args_generic_crypto;
    op_key_generic_crypto_args_t args_op_gc;
    //uint32_t key_id_aes_128 = 0U;
    uint8_t buff_encr[1024];
    uint8_t buff_decr[1024];
    //uint8_t *msg;
    uint16_t i = 0;
    //uint8_t *ref_encr = NULL;
    //uint8_t iv_tmp[16] = {0x0, 0x4, 0x6, 0xff};

    //uint32_t msg_size = 0U;
    //uint8_t aad[16] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};

    clear_v2x_nvm();

    // START NVM
    ASSERT_NOT_EQUAL(start_nvm_v2x(), NVM_STATUS_STOPPED);

    // SG0
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_HIGH;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sg0_sess), HSM_NO_ERROR);

    ASSERT_EQUAL(hsm_open_key_generic_crypto_service(sg0_sess, &args_generic_crypto, &key_generic_crypto_hdl), HSM_NO_ERROR);

    for (i = 0; i < test_data_size_sm4_ccm; i++) {

        args_op_gc.input = test_data_sm4_ccm[i].message;
        args_op_gc.output = buff_encr;
        args_op_gc.input_size = test_data_sm4_ccm[i].message_length;
        args_op_gc.output_size = test_data_sm4_ccm[i].message_length + 16U;
        args_op_gc.iv = test_data_sm4_ccm[i].nonce;
        args_op_gc.iv_size = 12U;
        args_op_gc.key = test_data_sm4_ccm[i].sm4_key;
        args_op_gc.key_size = 16U;
        args_op_gc.tag_size = 16U;
        args_op_gc.aad = NULL;
        args_op_gc.aad_size = 0u;
        args_op_gc.crypto_algo = HSM_KEY_GENERIC_ALGO_SM4_CCM;
        args_op_gc.flags = HSM_KEY_GENERIC_FLAGS_ENCRYPT;

        ASSERT_EQUAL(hsm_key_generic_crypto(key_generic_crypto_hdl, &args_op_gc), HSM_NO_ERROR);
        // CHECK DECRYPTED OUTPUT
        ASSERT_EQUAL(memcmp(test_data_sm4_ccm[i].encrypted_data, buff_encr, test_data_sm4_ccm[i].message_length + 16U), 0);


        args_op_gc.input = test_data_sm4_ccm[i].encrypted_data;
        args_op_gc.output = buff_decr;
        args_op_gc.input_size = test_data_sm4_ccm[i].message_length + 16U;
        args_op_gc.output_size = test_data_sm4_ccm[i].message_length;
        args_op_gc.iv = test_data_sm4_ccm[i].nonce;
        args_op_gc.iv_size = 12U;
        args_op_gc.key = test_data_sm4_ccm[i].sm4_key;
        args_op_gc.key_size = 16U;
        args_op_gc.tag_size = 16U;
        args_op_gc.aad = NULL;
        args_op_gc.aad_size = 0u;
        args_op_gc.crypto_algo = HSM_KEY_GENERIC_ALGO_SM4_CCM;
        args_op_gc.flags = HSM_KEY_GENERIC_FLAGS_DECRYPT;

        ASSERT_EQUAL(hsm_key_generic_crypto(key_generic_crypto_hdl, &args_op_gc), HSM_NO_ERROR);
        // CHECK DECRYPTED OUTPUT
        ASSERT_EQUAL(memcmp(test_data_sm4_ccm[i].message, buff_decr, test_data_sm4_ccm[i].message_length), 0);

        buff_encr[test_data_sm4_ccm[i].message_length] = 0x00;
        buff_encr[test_data_sm4_ccm[i].message_length] = 0xFF;
        args_op_gc.input = buff_encr;
        args_op_gc.output = buff_decr;
        args_op_gc.input_size = test_data_sm4_ccm[i].message_length + 16U;
        args_op_gc.output_size = test_data_sm4_ccm[i].message_length;
        args_op_gc.iv = test_data_sm4_ccm[i].nonce;
        args_op_gc.iv_size = 12U;
        args_op_gc.key = test_data_sm4_ccm[i].sm4_key;
        args_op_gc.key_size = 16U;
        args_op_gc.tag_size = 16U;
        args_op_gc.aad = NULL;
        args_op_gc.aad_size = 0u;
        args_op_gc.crypto_algo = HSM_KEY_GENERIC_ALGO_SM4_CCM;
        args_op_gc.flags = HSM_KEY_GENERIC_FLAGS_DECRYPT;

        ASSERT_NOT_EQUAL(hsm_key_generic_crypto(key_generic_crypto_hdl, &args_op_gc), HSM_NO_ERROR);
    }

    ASSERT_EQUAL(hsm_close_key_generic_crypto_service(key_generic_crypto_hdl), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_v2x(), NVM_STATUS_STOPPED);

    return TRUE_TEST;
}
