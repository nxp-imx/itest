#include <stdio.h>
#include <stdlib.h>
#include <omp.h>
#include "itest.h"
// requirement: test the rex and scheduler on v2xp 

int v2x_rex_stress_v2xp_001(void){

    open_session_args_t args;
    open_svc_rng_args_t rng_srv_args;
    op_get_random_args_t rng_get_random_args1, rng_get_random_args2, rng_get_random_args3, rng_get_random_args4;

    hsm_hdl_t sg0_sess, sv0_sess;
    hsm_hdl_t sg1_sess, sv1_sess;
    hsm_hdl_t sv0_rng_serv, sv1_rng_serv, sg0_rng_serv, sg1_rng_serv;
    uint8_t rng_out_buff1[4096], rng_out_buff2[4096], rng_out_buff3[4096], rng_out_buff4[4096];
    uint32_t iter = 0x4000;
    
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
#pragma omp parallel sections
    {
#pragma omp section
	{
	    uint32_t j;
	    for (j = 0; j < iter; j++) {
		// GET RANDOM Mu SV/SG
		rng_get_random_args1.output = rng_out_buff1;
		rng_get_random_args1.random_size = 2048;
		ASSERT_EQUAL(hsm_get_random(sv0_rng_serv, &rng_get_random_args1), HSM_NO_ERROR);
	    }
	}
#pragma omp section
	{
	    uint32_t j;
	    for (j = 0; j < iter; j++) {
		rng_get_random_args2.output = rng_out_buff2;
		rng_get_random_args2.random_size = 1024;
		ASSERT_EQUAL(hsm_get_random(sv1_rng_serv, &rng_get_random_args2), HSM_NO_ERROR);
	    }
	}
#pragma omp section
	{
	    uint32_t j;
	    for (j = 0; j < iter; j++) {
		rng_get_random_args3.output = rng_out_buff3;
		rng_get_random_args3.random_size = 2050;
		ASSERT_EQUAL(hsm_get_random(sg0_rng_serv, &rng_get_random_args3), HSM_NO_ERROR);
	    }
	}
#pragma omp section
	{
	    uint32_t j;
	    for (j = 0; j < iter; j++) {
		rng_get_random_args4.output = rng_out_buff4;
		rng_get_random_args4.random_size = 4096;
		ASSERT_EQUAL(hsm_get_random(sg1_rng_serv, &rng_get_random_args4), HSM_NO_ERROR);
	    }
	}
    }

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
