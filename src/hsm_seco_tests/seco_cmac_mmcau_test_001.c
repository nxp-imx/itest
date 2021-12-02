#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
// requirement: seco should support fast cmac, hsm service can't use the CAU if a she service is open


int seco_cmac_mmcau_001(void){
    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    open_svc_mac_args_t mac_srv_args;
    hsm_hdl_t sg0_mac_hdl, sg0_mac_hdl2;
    op_mac_one_go_args_t mac_one_go;
    hsm_mac_verification_status_t mac_status;

    op_generate_key_args_t gen_key_args;

    hsm_hdl_t sg0_sess;
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    hsm_hdl_t sg0_key_store_serv2, sg0_key_mgmt_srv2;

    uint32_t key_id;
    uint8_t aes128_test_message[256], work_area[256];

    uint32_t key_storage_identifier = 0xC0A1A;
    uint32_t password = 0xEFFACECA;
    uint16_t max_updates_number = 10;
    uint32_t signed_message_length = 0;
    uint8_t *signed_message = NULL;
    struct she_hdl_s *she_hdl = NULL;

    clear_seco_nvm();
    clear_she_seco_nvm();

    // INPUT BUFF AS RANDOM
    ASSERT_EQUAL(randomize(aes128_test_message, 128), 128);

    // SECO SESSION
    args.session_priority = 0;
    args.operating_mode = 0;
    ASSERT_EQUAL(hsm_open_session(&args, &sg0_sess), HSM_NO_ERROR);

    // START NVM SHE
    ASSERT_NOT_EQUAL(start_nvm_she_seco(), NVM_STATUS_STOPPED);
    // OPEN SHE SRVs
    ASSERT_EQUAL(she_storage_create( key_storage_identifier, password, max_updates_number, signed_message, signed_message_length ), SHE_STORAGE_CREATE_WARNING);
    ASSERT_NOT_EQUAL(she_hdl = she_open_session(key_storage_identifier, password, NULL, NULL), NULL);

    // KEY STORE SECO FAIL CAU USED BY SHE
    key_store_srv_args.key_store_identifier = (uint32_t) 0x12121212;
    key_store_srv_args.authentication_nonce = (uint32_t) 0x12345678;
    key_store_srv_args.max_updates_number = 12;
    key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE | HSM_SVC_KEY_STORE_FLAGS_FAST_CMAC;
    key_store_srv_args.signed_message = NULL;
    key_store_srv_args.signed_msg_size = 0;
    ASSERT_NOT_EQUAL(hsm_open_key_store_service(sg0_sess, &key_store_srv_args, &sg0_key_store_serv), HSM_NO_ERROR);

    // CLOSE SHE SRV
    ASSERT_NOT_EQUAL(stop_nvm_she_seco(), NVM_STATUS_STOPPED);
    she_close_session(she_hdl);

    // START NVM
    ASSERT_NOT_EQUAL(start_nvm_seco(), NVM_STATUS_STOPPED);

    ASSERT_EQUAL(hsm_open_key_store_service(sg0_sess, &key_store_srv_args, &sg0_key_store_serv), HSM_NO_ERROR);

    // KEY MGMNT SECO
    key_mgmt_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_key_management_service(sg0_key_store_serv, &key_mgmt_srv_args, &sg0_key_mgmt_srv), HSM_NO_ERROR);

    // KEY STORE 2 SECO
    key_store_srv_args.key_store_identifier = (uint32_t) 0xbad4c0c0;
    key_store_srv_args.authentication_nonce = (uint32_t) 0x12345678;
    key_store_srv_args.max_updates_number = 12;
    key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE | HSM_SVC_KEY_STORE_FLAGS_FAST_CMAC;
    key_store_srv_args.signed_message = NULL;
    key_store_srv_args.signed_msg_size = 0;
    ASSERT_EQUAL(hsm_open_key_store_service(sg0_sess, &key_store_srv_args, &sg0_key_store_serv2), HSM_NO_ERROR);

    // KEY MGMNT 2 SECO
    key_mgmt_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_key_management_service(sg0_key_store_serv2, &key_mgmt_srv_args, &sg0_key_mgmt_srv2), HSM_NO_ERROR);

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
    mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION | HSM_OP_MAC_ONE_GO_FLAGS_FAST_CMAC;
    mac_one_go.payload = aes128_test_message;
    mac_one_go.mac = work_area;
    mac_one_go.payload_size = 128u;
    mac_one_go.mac_size = 16u;
    ASSERT_EQUAL(hsm_mac_one_go(sg0_mac_hdl, &mac_one_go, &mac_status), HSM_NO_ERROR);

    mac_one_go.key_identifier = key_id;
    mac_one_go.algorithm = HSM_OP_MAC_ONE_GO_ALGO_AES_CMAC;
    mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION | HSM_OP_MAC_ONE_GO_FLAGS_FAST_CMAC;
    mac_one_go.payload = aes128_test_message;
    mac_one_go.mac = work_area;
    mac_one_go.payload_size = 128u;
    mac_one_go.mac_size = 8u;
    ASSERT_EQUAL(hsm_mac_one_go(sg0_mac_hdl, &mac_one_go, &mac_status), HSM_NO_ERROR);

    // PARAM AES KEY_GEN ON KEY STORE 2
    gen_key_args.key_identifier = &key_id;
    gen_key_args.out_size = 0;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_AES_128;
    gen_key_args.key_group = 1;
    gen_key_args.key_info = HSM_KEY_INFO_TRANSIENT;
    gen_key_args.out_key = NULL;
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv2, &gen_key_args), HSM_NO_ERROR);

    mac_srv_args.flags = 0u;
    ASSERT_EQUAL(hsm_open_mac_service(sg0_key_store_serv2, &mac_srv_args, &sg0_mac_hdl2), HSM_NO_ERROR);

    gen_key_args.key_identifier = &key_id;
    gen_key_args.out_size = 0U;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_AES_128;
    gen_key_args.key_group = 12;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = NULL;
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv2, &gen_key_args), HSM_NO_ERROR);

    mac_one_go.key_identifier = key_id;
    mac_one_go.algorithm = HSM_OP_MAC_ONE_GO_ALGO_AES_CMAC;
    mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION | HSM_OP_MAC_ONE_GO_FLAGS_FAST_CMAC;
    mac_one_go.payload = aes128_test_message;
    mac_one_go.mac = work_area;
    mac_one_go.payload_size = 128u;
    mac_one_go.mac_size = 16u;
    ASSERT_EQUAL(hsm_mac_one_go(sg0_mac_hdl2, &mac_one_go, &mac_status), HSM_NO_ERROR);

    mac_one_go.key_identifier = key_id;
    mac_one_go.algorithm = HSM_OP_MAC_ONE_GO_ALGO_AES_CMAC;
    mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION | HSM_OP_MAC_ONE_GO_FLAGS_FAST_CMAC;
    mac_one_go.payload = aes128_test_message;
    mac_one_go.mac = work_area;
    mac_one_go.payload_size = 128u;
    mac_one_go.mac_size = 8u;
    ASSERT_EQUAL(hsm_mac_one_go(sg0_mac_hdl2, &mac_one_go, &mac_status), HSM_NO_ERROR);

    ASSERT_EQUAL(hsm_close_mac_service(sg0_mac_hdl2), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv2), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv2), HSM_NO_ERROR);

    ASSERT_EQUAL(hsm_close_mac_service(sg0_mac_hdl), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);

    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_seco(), NVM_STATUS_STOPPED);

    return TRUE_TEST;
}
