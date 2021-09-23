#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
#include "test_vectors/tv_verify_nistp256.h"

/* Number of iterations */
#define NUM_OPERATIONS  (5000u)

int v2x_perf_pub_key_decompression_nistp256(void){

    open_session_args_t args;
    
    op_pub_key_dec_args_t pub_key_dec_args;
    hsm_hdl_t sg0_sess;
    hsm_key_type_t key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
    uint16_t size_pub_key;
    uint16_t size_pub_key_c;
    uint8_t pub_key_comp[0x90];
    uint8_t pub_key_decomp[0x90];
    uint32_t idx, idx_test = 0U, iter = NUM_OPERATIONS;

    timer_perf_t t_perf;
    test_data_verify_t *tv = test_data_nistp256;
    uint32_t tv_size = test_data_size_nistp256;

    get_key_param(HSM_KEY_TYPE_ECDSA_NIST_P256, NULL, &size_pub_key, NULL);
    size_pub_key_c = size_pub_key/2 + 1;

    // SG0
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_HIGH;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sg0_sess), HSM_NO_ERROR);

    memset(&t_perf, 0, sizeof(t_perf));

    for (idx = 0; idx < iter; idx++) {   

        memcpy(pub_key_comp, tv[idx_test].public_key, size_pub_key_c);
        if ((tv[idx_test].public_key[size_pub_key - 1] & 1) == 1U)
            pub_key_comp[size_pub_key_c - 1] = 0x1;
        else
            pub_key_comp[size_pub_key_c - 1] = 0x0;
        
        // PUB KEY DECOMPRESS
        pub_key_dec_args.key = pub_key_comp;
        pub_key_dec_args.out_key = pub_key_decomp;
        pub_key_dec_args.key_size = size_pub_key_c;
        pub_key_dec_args.out_key_size = size_pub_key;
        pub_key_dec_args.key_type = key_type;
        /* Start the timer */
        start_timer(&t_perf);
        ASSERT_EQUAL(hsm_pub_key_decompression(sg0_sess, &pub_key_dec_args), HSM_NO_ERROR);
        /* Stop the timer */
        stop_timer(&t_perf);
        // CHECK IF THE RECOVERED PUB KEY IS EQUAL TO THE ONE GENERATED
        ASSERT_EQUAL(memcmp(tv[idx_test].public_key, pub_key_decomp, size_pub_key), 0);
        /* Restart if end of test vector is achieved */
        if (idx_test == (tv_size-1))
            idx_test = 0;
        else
            idx_test++;
    }
    /* Finalize time to get stats */
    finalize_timer(&t_perf, iter);
    ITEST_CHECK_KPI_OPS(t_perf.op_sec, 1);
    
    // CLOSE SRV/SESSION
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);

    return TRUE_TEST;
}
