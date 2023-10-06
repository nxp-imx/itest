// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

/* Number of iterations */
#define NUM_OPERATIONS	500

#define NB_ALGO	3
#define MAX_PUB_KEY_SIZE (0x60)
#define MAX_MSG_SIZE (0x30)

static hsm_signature_scheme_id_t scheme_id[NB_ALGO] = {
	HSM_SIGNATURE_SCHEME_ECDSA_SHA224,
	HSM_SIGNATURE_SCHEME_ECDSA_SHA256,
	HSM_SIGNATURE_SCHEME_ECDSA_SHA384,
};

static uint16_t size_pub_key[NB_ALGO] = {
	0x38,
	0x40,
	0x60,
};

static uint32_t msg_size[NB_ALGO] = {
	0x1C,
	0x20,
	0x30,
};

static hsm_bit_key_sz_t bit_key_sz[NB_ALGO] = {
	HSM_KEY_SIZE_ECC_BP_R1_224,
	HSM_KEY_SIZE_ECC_BP_R1_256,
	HSM_KEY_SIZE_ECC_BP_R1_384,
};

static hsm_permitted_algo_t permitted_algo[NB_ALGO] = {
	PERMITTED_ALGO_ECDSA_SHA224,
	PERMITTED_ALGO_ECDSA_SHA256,
	PERMITTED_ALGO_ECDSA_SHA384,
};

int ecdsa_brainpool_sign_verify(void)
{
	open_session_args_t open_session_args = {0};
	open_svc_key_store_args_t key_store_args = {0};
	open_svc_key_management_args_t key_mgmt_args;
	op_generate_sign_args_t sig_gen_args = {0};
	op_verify_sign_args_t sig_ver_args = {0};
	op_generate_key_args_t key_gen_args = {0};
	open_svc_sign_gen_args_t open_sig_gen_args = {0};
	open_svc_sign_ver_args_t open_sig_ver_args = {0};

	hsm_err_t err;
	hsm_hdl_t hsm_session_hdl;
	hsm_hdl_t key_store_hdl, key_mgmt_hdl, sig_gen_hdl = 0, sig_ver_hdl = 0;
	uint8_t pub_key[NB_ALGO][MAX_PUB_KEY_SIZE] = {0};
	uint8_t sign_out_0[MAX_PUB_KEY_SIZE];
	uint32_t key_id[NB_ALGO] = {0};
	hsm_verification_status_t verify_status;
	timer_perf_t t_perf;
	uint32_t i, j, iter = NUM_OPERATIONS, num_algo = NB_ALGO;
	uint8_t msg_0[MAX_MSG_SIZE];
	op_pub_key_recovery_args_t args = {0};

	open_session_args.session_priority = 0;
	open_session_args.operating_mode = 0;
	ASSERT_EQUAL(hsm_open_session(&open_session_args,
				      &hsm_session_hdl),
		     HSM_NO_ERROR);

	key_store_args.key_store_identifier = 0xABCD;
	key_store_args.authentication_nonce = 0x1234;
	key_store_args.flags = 1;
	err = hsm_open_key_store_service(hsm_session_hdl,
					 &key_store_args,
					 &key_store_hdl);

	if (err == HSM_KEY_STORE_CONFLICT) {
		key_store_args.flags = 0;
		ASSERT_EQUAL(hsm_open_key_store_service(hsm_session_hdl,
							&key_store_args,
							&key_store_hdl),
			     HSM_NO_ERROR);
	} else {
		ASSERT_EQUAL(err, HSM_NO_ERROR);
	}

	// INPUT BUFF AS RANDOM
	ASSERT_EQUAL(randomize(msg_0, MAX_MSG_SIZE), MAX_MSG_SIZE);

	memset(&key_mgmt_args, 0, sizeof(key_mgmt_args));
	memset(&sign_out_0, 0, sizeof(sign_out_0));

	ASSERT_EQUAL(hsm_open_key_management_service(key_store_hdl,
						     &key_mgmt_args,
						     &key_mgmt_hdl),
		     HSM_NO_ERROR);

	memset(&open_sig_gen_args, 0, sizeof(open_sig_gen_args));
	ASSERT_EQUAL(hsm_open_signature_generation_service(key_store_hdl,
							   &open_sig_gen_args,
							   &sig_gen_hdl),
		     HSM_NO_ERROR);

	memset(&open_sig_ver_args, 0, sizeof(open_sig_ver_args));
	ASSERT_EQUAL(hsm_open_signature_verification_service(hsm_session_hdl,
							     &open_sig_ver_args,
							     &sig_ver_hdl),
		     HSM_NO_ERROR);

	for (j = 0; j < num_algo; j++) {
		key_gen_args.key_identifier = &key_id[j];
		key_gen_args.out_size = size_pub_key[j];
		key_gen_args.key_group = 3;
		key_gen_args.key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
		key_gen_args.key_usage = HSM_KEY_USAGE_SIGN_HASH |
					 HSM_KEY_USAGE_VERIFY_HASH;
		key_gen_args.permitted_algo = permitted_algo[j];
		key_gen_args.bit_key_sz = bit_key_sz[j];
		key_gen_args.key_lifecycle = 0;
		key_gen_args.key_type = HSM_KEY_TYPE_ECC_BP_R1;
		key_gen_args.out_key = pub_key[j];

		ASSERT_EQUAL(hsm_generate_key(key_mgmt_hdl, &key_gen_args),
			     HSM_NO_ERROR);

		ITEST_LOG("ECDSA_SHA_%d signing on %d byte size blocks: ",
			 bit_key_sz[j], msg_size[j]);
		sig_gen_args.key_identifier = key_id[j];
		sig_gen_args.message = msg_0;
		sig_gen_args.signature = sign_out_0;
		sig_gen_args.signature_size = size_pub_key[j];
		sig_gen_args.message_size = msg_size[j];
		sig_gen_args.scheme_id = scheme_id[j];
		sig_gen_args.salt_len = 0;
		sig_gen_args.exp_signature_size = size_pub_key[j];
		sig_gen_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST;
		memset(&t_perf, 0, sizeof(t_perf));

		for (i = 0U; i < iter; i++) {
			/* Start the timer */
			start_timer(&t_perf);
			ASSERT_EQUAL(hsm_generate_signature(sig_gen_hdl,
							    &sig_gen_args),
				     HSM_NO_ERROR);
			/* Stop the timer */
			stop_timer(&t_perf);
		}

		/* Finalize time to get stats */
		finalize_timer(&t_perf, iter);
		ITEST_CHECK_KPI_OPS(t_perf.op_sec, 10);

		args.key_identifier = key_id[j];
		args.out_key_size = size_pub_key[j];
		args.out_key = pub_key[j];

		ASSERT_EQUAL(hsm_pub_key_recovery(key_store_hdl, &args),
			     HSM_NO_ERROR);
		ITEST_LOG("ECDSA_SHA_%d verification on %d byte size blocks: ",
			 bit_key_sz[j], msg_size[j]);
		sig_ver_args.key = pub_key[j];
		sig_ver_args.message = msg_0;
		sig_ver_args.signature = sign_out_0;
		sig_ver_args.key_size = size_pub_key[j];
		sig_ver_args.signature_size = size_pub_key[j];
		sig_ver_args.message_size = msg_size[j];
		sig_ver_args.verification_status = HSM_VERIFICATION_STATUS_SUCCESS;
		sig_ver_args.scheme_id = scheme_id[j];
		sig_ver_args.salt_len = 0;
		sig_ver_args.key_sz = bit_key_sz[j];
		sig_ver_args.pkey_type = HSM_PUBKEY_TYPE_ECC_BP_R1;
		sig_ver_args.flags = HSM_OP_VERIFY_SIGN_FLAGS_INPUT_DIGEST;
		memset(&t_perf, 0, sizeof(t_perf));

		for (i = 0U; i < iter; i++) {
			/* Start the timer */
			start_timer(&t_perf);
			ASSERT_EQUAL(hsm_verify_signature(sig_ver_hdl,
							  &sig_ver_args,
							  &verify_status),
				     HSM_NO_ERROR);

			ASSERT_EQUAL(verify_status,
				     HSM_VERIFICATION_STATUS_SUCCESS);
			/* Stop the timer */
			stop_timer(&t_perf);
		}

		/* Finalize time to get stats */
		finalize_timer(&t_perf, iter);
		ITEST_CHECK_KPI_OPS(t_perf.op_sec, 10);
	}
	ASSERT_EQUAL(hsm_close_signature_generation_service(sig_gen_hdl),
		     HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_signature_verification_service(sig_ver_hdl),
		     HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_key_management_service(key_mgmt_hdl),
		     HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_key_store_service(key_store_hdl), HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_session(hsm_session_hdl), HSM_NO_ERROR);

	return TRUE_TEST;
}
