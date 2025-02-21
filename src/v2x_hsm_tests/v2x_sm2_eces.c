// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

/* Number of iterations */
#define NUM_OPERATIONS 300
#define NUM_MSG_SIZE 3
#define MAX_MSG_SIZE 16384
#define ECES_EXTRA_CIPHER_BYTES 97
#define MAX_CIPHER_SIZE 16484 /* MAX_MSG_SIZE + ECES_EXTRA_CIPHER_BYTES + 3 */
#define SIZE_PUB_KEY 0x40

int v2x_sm2_eces(void)
{
	open_session_args_t open_session_args = {0};
	open_svc_key_management_args_t key_mgmt_args = {0};
	op_sm2_eces_enc_args_t sm2_eces_enc_args = {0};
	open_svc_sm2_eces_args_t open_sm2_eces_args = {0};
	op_sm2_eces_dec_args_t sm2_eces_dec_args = {0};
	op_generate_key_args_t key_gen_args = {0};

	hsm_err_t err = 0;
	hsm_hdl_t key_mgmt_hdl = 0, sm2_eces_hdl = 0;
	uint32_t key_id = 0;
	uint8_t plaintext[MAX_MSG_SIZE] = {0};
	uint8_t ciphertext[MAX_CIPHER_SIZE] = {0};
	uint8_t test_msg[MAX_MSG_SIZE] = {0};
	uint32_t block_size[] = {16, 64, 256};
	uint32_t i = 0, j = 0, iter = NUM_OPERATIONS;
	uint8_t pub_key[SIZE_PUB_KEY] = {0};
	timer_perf_t t_perf = {0};

	/* input buffer as random */
	ASSERT_EQUAL(randomize(plaintext, MAX_MSG_SIZE), MAX_MSG_SIZE);

	/* open session for V2X HSM SG MU */
	open_session_args.mu_type = V2X_SG0;
	ASSERT_EQUAL(hsm_open_session(&open_session_args, &hsm_session_hdl),
		     HSM_NO_ERROR);

	/* open key store service */
	ASSERT_EQUAL(hsm_open_key_store(hsm_session_hdl, &key_store_hdl),
		     HSM_NO_ERROR);

	/* open key management service */
	ASSERT_EQUAL(hsm_open_key_management_service(key_store_hdl,
						     &key_mgmt_args,
						     &key_mgmt_hdl),
		     HSM_NO_ERROR);

	/* open sm2 eces service */
	ASSERT_EQUAL(hsm_open_sm2_eces_service(key_store_hdl,
					       &open_sm2_eces_args,
					       &sm2_eces_hdl),
		     HSM_NO_ERROR);

	/* generate sm2 eces key */
	key_gen_args.key_identifier = &key_id;
	key_gen_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
	key_gen_args.out_size = SIZE_PUB_KEY;
	key_gen_args.key_group = 1;
	key_gen_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
	key_gen_args.key_info = 0;
	key_gen_args.out_key = pub_key;
	ASSERT_EQUAL(hsm_generate_key(key_mgmt_hdl, &key_gen_args),
		     HSM_NO_ERROR);

	for (i = 0; i < NUM_MSG_SIZE; i++) {
		/* sm2 eces encryption */
		sm2_eces_enc_args.input = plaintext;
		sm2_eces_enc_args.output = ciphertext;
		sm2_eces_enc_args.pub_key = pub_key;
		sm2_eces_enc_args.input_size = block_size[i];
		/* align output size with 32 bits i.e align(plaintext_size + 97) */
		sm2_eces_enc_args.output_size = (block_size[i] + ECES_EXTRA_CIPHER_BYTES)
						+ ((sizeof(u_int32_t) -
						(block_size[i] + ECES_EXTRA_CIPHER_BYTES) %
						sizeof(u_int32_t)) %
						sizeof(u_int32_t));
		sm2_eces_enc_args.pub_key_size = SIZE_PUB_KEY;
		sm2_eces_enc_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
		sm2_eces_enc_args.flags = 0;

		ITEST_LOG("SM2-256-ECES encryption for 1s on %d byte blocks: ",
			  block_size[i]);
		memset(&t_perf, 0, sizeof(t_perf));
		t_perf.session_hdl = hsm_session_hdl;
		for (j = 0; j < iter; j++) {
			/* Start the timer */
			start_timer(&t_perf);
			err = hsm_sm2_eces_encryption(hsm_session_hdl,
						      &sm2_eces_enc_args);
			if (err)
				goto out;
			/* Stop the timer */
			stop_timer(&t_perf);
		}
		/* Finalize time to get stats */
		finalize_timer(&t_perf, iter);
		print_perf(&t_perf, iter);

		/* sm2 eces decryption */
		sm2_eces_dec_args.input = ciphertext;
		sm2_eces_dec_args.output = test_msg;
		sm2_eces_dec_args.key_identifier = key_id;
		sm2_eces_dec_args.input_size = block_size[i] + ECES_EXTRA_CIPHER_BYTES;
		sm2_eces_dec_args.output_size = block_size[i];
		sm2_eces_dec_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
		sm2_eces_dec_args.flags = 0;
		ITEST_LOG("SM2-256-ECES decryption for 1s on %d byte blocks: ",
			  block_size[i]);
		memset(&t_perf, 0, sizeof(t_perf));
		t_perf.session_hdl = hsm_session_hdl;
		for (j = 0; j < iter; j++) {
			/* Start the timer */
			start_timer(&t_perf);
			err = hsm_sm2_eces_decryption(sm2_eces_hdl,
						      &sm2_eces_dec_args);
			if (err)
				goto out;
			ASSERT_EQUAL(memcmp(test_msg, plaintext, block_size[i]),
				     0);
			/* Stop the timer */
			stop_timer(&t_perf);
		}
		/* Finalize time to get stats */
		finalize_timer(&t_perf, iter);
		print_perf(&t_perf, iter);
	}

out:
	ASSERT_EQUAL(hsm_close_sm2_eces_service(sm2_eces_hdl), HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_key_management_service(key_mgmt_hdl), HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_key_store_service(key_store_hdl), HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_session(hsm_session_hdl), HSM_NO_ERROR);

	if (err)
		ASSERT_FALSE(err);

	return TRUE_TEST;
}
