#include <stdio.h>
#include <stdlib.h>
#include "test_api.h"
// requirement: rng srv can be open on all Mu

int v2x_rng_srv_001(void){

    open_session_args_t args;
    open_svc_rng_args_t rng_srv_args;
    op_get_random_args_t rng_get_random_args;

    hsm_hdl_t sg0_sess, sv0_sess;
    hsm_hdl_t sg1_sess, sv1_sess;
    hsm_hdl_t sv0_rng_serv, sv1_rng_serv, sg0_rng_serv, sg1_rng_serv;
    uint8_t rng_out_buff[4096];
    
    // SG0
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_HIGH;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sg0_sess), HSM_NO_ERROR);

    // SV0
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_HIGH;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK | HSM_OPEN_SESSION_NO_KEY_STORE_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sv0_sess), HSM_NO_ERROR);

    // SG1
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_LOW;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sg1_sess), HSM_NO_ERROR);

    // SV1
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_LOW;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK | HSM_OPEN_SESSION_NO_KEY_STORE_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sv1_sess), HSM_NO_ERROR);

    // OPEN RNG SERV
    rng_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_rng_service(sv0_sess, &rng_srv_args, &sv0_rng_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_open_rng_service(sv1_sess, &rng_srv_args, &sv1_rng_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_open_rng_service(sg0_sess, &rng_srv_args, &sg0_rng_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_open_rng_service(sg1_sess, &rng_srv_args, &sg1_rng_serv), HSM_NO_ERROR);

    // GET RANDOM Mu SV/SG
    rng_get_random_args.output = rng_out_buff;
    rng_get_random_args.random_size = 3;
    ASSERT_EQUAL(hsm_get_random(sv0_rng_serv, &rng_get_random_args), HSM_NO_ERROR);
    rng_get_random_args.random_size = 176;
    ASSERT_EQUAL(hsm_get_random(sv1_rng_serv, &rng_get_random_args), HSM_NO_ERROR);
    rng_get_random_args.random_size = 2050;
    ASSERT_EQUAL(hsm_get_random(sg0_rng_serv, &rng_get_random_args), HSM_NO_ERROR);
    rng_get_random_args.random_size = 4096;
    ASSERT_EQUAL(hsm_get_random(sg1_rng_serv, &rng_get_random_args), HSM_NO_ERROR);

    // CLOSE SRV/SESSION
    ASSERT_EQUAL(hsm_close_rng_service(sv0_rng_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_rng_service(sv1_rng_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_rng_service(sg0_rng_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_rng_service(sg1_rng_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg1_sess), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sv0_sess), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sv1_sess), HSM_NO_ERROR);

    return TRUE_TEST;
}
