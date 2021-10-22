#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
// requirement: rng srv can be open on all Mu

int seco_rng_srv_001(void){

    open_session_args_t args;
    open_svc_rng_args_t rng_srv_args;
    op_get_random_args_t rng_get_random_args;

    hsm_hdl_t sg0_sess;
    hsm_hdl_t sg0_rng_serv;
    uint8_t rng_out_buff[4096];
    
    // SECO OPEN SESSION
    args.session_priority = 0;
    args.operating_mode = 0;
    ASSERT_EQUAL(hsm_open_session(&args, &sg0_sess), HSM_NO_ERROR);

    // OPEN RNG SERV
    rng_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_rng_service(sg0_sess, &rng_srv_args, &sg0_rng_serv), HSM_NO_ERROR);

    // GET RANDOM Mu SV/SG
    rng_get_random_args.output = rng_out_buff;
    rng_get_random_args.random_size = 2050;
    ASSERT_EQUAL(hsm_get_random(sg0_rng_serv, &rng_get_random_args), HSM_NO_ERROR);

    // CLOSE SRV/SESSION
    ASSERT_EQUAL(hsm_close_rng_service(sg0_rng_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);

    return TRUE_TEST;
}
