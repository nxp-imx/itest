// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
#include "crypto_utils/dgst.h"

// requirement: hash tests all algos from 1 byte to 300 bytes

// HSM_HASH_ALGO_SHA_224
// HSM_HASH_ALGO_SHA_256
// HSM_HASH_ALGO_SHA_384
// HSM_HASH_ALGO_SHA_512

/* Number of iterations */
#define NUM_OPERATIONS 3000

#define NB_ALGO 4
#define MAX_DGST_SIZE 0x40
#define MAX_MSG_SIZE 16384
#define NUM_MSG_SIZE 6

static hsm_hash_algo_t algos[NB_ALGO] = {
	HSM_HASH_ALGO_SHA_224,
	HSM_HASH_ALGO_SHA_256,
	HSM_HASH_ALGO_SHA_384,
	HSM_HASH_ALGO_SHA_512,
};

static char *algos_str[NB_ALGO] = {
	"sha224",
	"sha256",
	"sha384",
	"sha512",
	};

static uint16_t dgst_size[NB_ALGO] = {
	0x1C,
	0x20,
	0x30,
	0x40,
};

int ele_hash(void)
{
	open_session_args_t open_session_args = {0};
	hsm_hdl_t hsm_session_hdl;
	timer_perf_t t_perf;
	op_hash_one_go_args_t hash_args;
	uint8_t dgst_in_buff[MAX_MSG_SIZE];
	uint8_t dgst_out_buff[MAX_DGST_SIZE];
	uint8_t dgst_expected[MAX_DGST_SIZE];
	uint32_t block_size[] = {16, 64, 256, 1024, 8192, 16384};
	uint32_t size_input;
	uint32_t i, j, k, iter = NUM_OPERATIONS;

	open_session_args.session_priority = 0;
	open_session_args.operating_mode = 0;

	ASSERT_EQUAL(hsm_open_session(&open_session_args,
				      &hsm_session_hdl),
		     HSM_NO_ERROR);

	for (i = 0; i < NB_ALGO; i++) {
		for (k = 0; k < NUM_MSG_SIZE; k++) {
			size_input = block_size[k];
			ITEST_LOG("Generating hash for %s for %d byte input message: ",
				  algos_str[i], size_input);
			// GEN HASH Mu SV0
			hash_args.input = dgst_in_buff;
			hash_args.output = dgst_out_buff;
			hash_args.input_size = size_input;
			hash_args.output_size = dgst_size[i];
			hash_args.algo = algos[i];
			hash_args.svc_flags = HSM_HASH_FLAG_ONE_SHOT;

			// INPUT BUFF AS RANDOM
			ASSERT_EQUAL(randomize(dgst_in_buff, size_input),
				     size_input);

			for (j = 0; j < iter; j++) {
				 /* Start the timer */
				start_timer(&t_perf);
				ASSERT_EQUAL(hsm_hash_one_go(hsm_session_hdl,
							     &hash_args),
					     HSM_NO_ERROR);
				/* Stop the timer */
				stop_timer(&t_perf);

				// GEN EXPECTED DIGEST (OPENSSL)
				ASSERT_EQUAL(icrypto_hash_one_go((unsigned char *)dgst_in_buff,
								 (unsigned char *) dgst_expected,
								 algos_str[i], size_input),
					     dgst_size[i]);
				// CHECK HASH OUTPUT
				ASSERT_EQUAL(memcmp(dgst_out_buff,
						    dgst_expected,
						    dgst_size[i]),
					     0);
			}
				/* Finalize time to get stats */
				finalize_timer(&t_perf, iter);
				ITEST_CHECK_KPI_OPS(t_perf.op_sec, 10);
		}
	}

	ASSERT_EQUAL(hsm_close_session(hsm_session_hdl), HSM_NO_ERROR);

	return TRUE_TEST;
}
