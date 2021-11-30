#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
// requirement: aes gcm iv should contain counter part and fixed part, or be random, depending on setting


int seco_cmac_mmcau_001(void){
    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    open_svc_mac_args_t mac_srv_args;
    hsm_hdl_t sg0_mac_hdl;
    op_mac_one_go_args_t mac_one_go;
    hsm_mac_verification_status_t mac_status;

    op_generate_key_args_t gen_key_args;

    hsm_hdl_t sg0_sess;
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;

    uint32_t key_id;
    uint8_t aes128_test_message[256], work_area[256];

    clear_seco_nvm();

    // INPUT BUFF AS RANDOM
    ASSERT_EQUAL(randomize(aes128_test_message, 128), 128);

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
    key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE | HSM_SVC_KEY_STORE_FLAGS_CMAC_MMCAU_ENGINE;
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

    mac_srv_args.flags = 0u;
    ASSERT_EQUAL(hsm_open_mac_service(sg0_key_store_serv, &mac_srv_args, &sg0_mac_hdl), HSM_NO_ERROR);

    gen_key_args.key_identifier = &key_id;
    gen_key_args.out_size = 0U;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_AES_128;
    gen_key_args.key_group = 12;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = NULL;
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

    mac_one_go.key_identifier = key_id;
    mac_one_go.algorithm = HSM_OP_MAC_ONE_GO_ALGO_AES_CMAC;
    mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION | HSM_OP_MAC_ONE_GO_FLAGS_MAC_USE_ENGINE_MMCAU;
    mac_one_go.payload = aes128_test_message;
    mac_one_go.mac = work_area;
    mac_one_go.payload_size = 128u;
    mac_one_go.mac_size = 16u;
    ASSERT_EQUAL(hsm_mac_one_go(sg0_mac_hdl, &mac_one_go, &mac_status), HSM_NO_ERROR);

    mac_one_go.key_identifier = key_id;
    mac_one_go.algorithm = HSM_OP_MAC_ONE_GO_ALGO_AES_CMAC;
    mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION | HSM_OP_MAC_ONE_GO_FLAGS_MAC_USE_ENGINE_MMCAU;
    mac_one_go.payload = aes128_test_message;
    mac_one_go.mac = work_area;
    mac_one_go.payload_size = 128u;
    mac_one_go.mac_size = 8u;
    ASSERT_EQUAL(hsm_mac_one_go(sg0_mac_hdl, &mac_one_go, &mac_status), HSM_NO_ERROR);

    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);

    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_seco(), NVM_STATUS_STOPPED);

    return TRUE_TEST;
}
