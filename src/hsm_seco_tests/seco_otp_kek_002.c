#include <stdio.h>
#include <stdlib.h>
#include <openssl/obj_mac.h>
#include "crypto_utils/ecc_sign.h"
#include "itest.h"

// v2x key injection with otp kek using all curves supported (DXL B0 key injection)

#define NB_ALGO 4
static hsm_key_type_t key_type_[NB_ALGO] = {
    HSM_KEY_TYPE_ECDSA_NIST_P256,
    HSM_KEY_TYPE_ECDSA_NIST_P384,
    HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256,
    HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384,
};

static hsm_key_type_t algos_sign[NB_ALGO] = {
    HSM_SIGNATURE_SCHEME_ECDSA_NIST_P256_SHA_256,
    HSM_SIGNATURE_SCHEME_ECDSA_NIST_P384_SHA_384,
    HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_R1_256_SHA_256,
    HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_R1_384_SHA_384,

};

static int curves_openssl[NB_ALGO] = {
    NID_X9_62_prime256v1,
    NID_secp384r1,
    NID_brainpoolP256r1,
    NID_brainpoolP384r1,
};

static char *algos_dgst_ecc[NB_ALGO] = {
    "sha256",
    "sha384",
    "sha256",
    "sha384",
};

static uint16_t size_pub_key[NB_ALGO] = {
    0x40,
    0x60,
    0x40,
    0x60,
};

int seco_otp_kek_002_test(void){

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    open_svc_sign_gen_args_t sig_gen_srv_args;
    op_generate_sign_args_t sg0_sig_gen_args; 
    
    hsm_hdl_t sg0_sess, sg0_sig_gen_serv;
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    uint32_t key_id_0 = 0;
    uint8_t pub_key_0[1024];
    uint8_t privk_0[1024];
    int size_pubk_0 = 0;
    int size_privk_0 = 0;
    uint8_t msg_0[300];
    uint8_t sign_out_0[1024];
    uint32_t i;

    // REMOVE NVM
    clear_v2x_nvm();

    // INPUT BUFF AS RANDOM
    ASSERT_EQUAL(randomize(msg_0, 300), 300);

    // START NVM
    ASSERT_NOT_EQUAL(start_nvm_v2x(), NVM_STATUS_STOPPED);
    
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


    // KEY MGMNT SG0
    key_mgmt_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_key_management_service(sg0_key_store_serv, &key_mgmt_srv_args, &sg0_key_mgmt_srv), HSM_NO_ERROR);

    // SIGN GEN OPEN SRV SG0
    sig_gen_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_signature_generation_service(sg0_key_store_serv, &sig_gen_srv_args, &sg0_sig_gen_serv), HSM_NO_ERROR);



    for(i = 0; i < NB_ALGO; i++){
        ASSERT_EQUAL(icrypto_generate_key_pair(curves_openssl[i], (unsigned char *) pub_key_0, &size_pubk_0, (unsigned char *)privk_0, &size_privk_0), 1);

        // =========== INJECT KEYS FOR AES GCM TEST =========== //
        ASSERT_EQUAL(isen_hsm_key_injection_otp_kek(sg0_key_mgmt_srv, &key_id_0, key_type_[i], privk_0, size_privk_0), TRUE_TEST);


	    // GEN THE SIGN OF THE INJECTED KEY
        sg0_sig_gen_args.key_identifier = key_id_0;
        sg0_sig_gen_args.message = msg_0;
        sg0_sig_gen_args.signature = sign_out_0;
        sg0_sig_gen_args.message_size = 300;
        sg0_sig_gen_args.signature_size = size_pub_key[i]+1;
        sg0_sig_gen_args.scheme_id = algos_sign[i];
        sg0_sig_gen_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE; 
        ASSERT_EQUAL(hsm_generate_signature(sg0_sig_gen_serv, &sg0_sig_gen_args), HSM_NO_ERROR);


        ASSERT_EQUAL(icrypto_verify_signature(curves_openssl[i], (unsigned char *) pub_key_0, size_pubk_0, NULL,\
                                            0, (unsigned char *) msg_0, sizeof(msg_0), algos_dgst_ecc[i], (unsigned char *) sign_out_0, size_pub_key[i]), 1);
 
    }
    
    // CLOSE SRV/SESSION
    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_v2x(), NVM_STATUS_STOPPED);
    
    return TRUE_TEST;
}
