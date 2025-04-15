// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

/* Number of iterations */
#define NUM_OPERATIONS  (200u)
#define MAX_MSG_SIZE 16384
#define NUM_MSG_SIZE 6
#define PUB_KEY_SIZE (0x40)

int v2x_sm2_sign_verify(void)
{
	open_session_args_t open_session_args = {0};
	open_svc_key_store_args_t key_store_srv_args = {0};
	open_svc_key_management_args_t key_mgmt_srv_args = {0};
	open_svc_sign_gen_args_t sig_gen_srv_args = {0};
	open_svc_sign_ver_args_t sig_ver_srv_args = {0};
	op_generate_key_args_t gen_key_args = {0};
	op_generate_sign_args_t sig_gen_args = {0};
	op_verify_sign_args_t sig_ver_args = {0};
	hsm_hdl_t sg0_sig_gen_serv = 0, sv0_sig_ver_serv = 0;
	hsm_hdl_t sg0_key_mgmt_srv = 0;
	uint32_t key_id = 0, num_msg_size = NUM_MSG_SIZE;
	uint8_t msg_input[MAX_MSG_SIZE] = {0};
	uint8_t sign_out[PUB_KEY_SIZE + 1] = {0};
	uint8_t pub_key[PUB_KEY_SIZE] = {0};
	uint32_t iter = NUM_OPERATIONS, i = 0, j = 0;
	uint32_t msg_size[] = {16, 64, 256, 1024, 8192, 16384};
	timer_perf_t t_perf = {0};
	hsm_err_t err = 0;
	hsm_verification_status_t verify_status = 0;

	// INPUT BUFF AS RANDOM
	ASSERT_EQUAL(randomize(msg_input, MAX_MSG_SIZE), MAX_MSG_SIZE);

	/* Open session for V2X HSM SG MU */
	open_session_args.mu_type = V2X_SG0;
	ASSERT_EQUAL(hsm_open_session(&open_session_args, &hsm_session_hdl),
		     HSM_NO_ERROR);

	/* Open session for V2X HSM SV MU */
	open_session_args.mu_type = V2X_SV0;
	ASSERT_EQUAL(hsm_open_session(&open_session_args, &hsm_session_hdl2),
		     HSM_NO_ERROR);

	/* set number of nessage sizes based on soc */
	if (soc != IMX8DXL_DL3)
		num_msg_size = NUM_MSG_SIZE - 2;

	key_store_srv_args.key_store_identifier = 1234;
	key_store_srv_args.authentication_nonce = 1234;
	key_store_srv_args.max_updates_number = 12;
	key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
	key_store_srv_args.signed_message = NULL;
	key_store_srv_args.signed_msg_size = 0;
	err = hsm_open_key_store_service(hsm_session_hdl, &key_store_srv_args,
					 &key_store_hdl);
	if (err == HSM_KEY_STORE_CONFLICT) {
		/* key store may already exist. */
		key_store_srv_args.flags = 0;
		err = hsm_open_key_store_service(hsm_session_hdl,
						 &key_store_srv_args,
						 &key_store_hdl);
	} else
		ASSERT_EQUAL(err, HSM_NO_ERROR);

	// KEY MGMNT SG0
	ASSERT_EQUAL(hsm_open_key_management_service(key_store_hdl,
						     &key_mgmt_srv_args,
						     &sg0_key_mgmt_srv),
		     HSM_NO_ERROR);

	// SIGN GEN OPEN SRV
	ASSERT_EQUAL(hsm_open_signature_generation_service(key_store_hdl,
							   &sig_gen_srv_args,
							   &sg0_sig_gen_serv),
		     HSM_NO_ERROR);

	// SIGN VERIFY OPEN SRV
	ASSERT_EQUAL(hsm_open_signature_verification_service(hsm_session_hdl2,
							     &sig_ver_srv_args,
							     &sv0_sig_ver_serv),
		     HSM_NO_ERROR);

	gen_key_args.key_identifier = &key_id;
	gen_key_args.out_size = PUB_KEY_SIZE;
	gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
	gen_key_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
	gen_key_args.key_group = 12;
	gen_key_args.key_info = 0U;
	gen_key_args.out_key = pub_key;
	ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args),
		     HSM_NO_ERROR);

	for (i = 0; i < num_msg_size; i++) {
		sig_gen_args.key_identifier = key_id;
		sig_gen_args.message = msg_input;
		sig_gen_args.signature = sign_out;
		sig_gen_args.message_size = msg_size[i];
		sig_gen_args.signature_size = PUB_KEY_SIZE + 1; /* Add 1 byte for Ry */
		sig_gen_args.scheme_id = HSM_SIGNATURE_SCHEME_DSA_SM2_FP_256_SM3;
		sig_gen_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE;

		memset(&t_perf, 0, sizeof(t_perf));
		t_perf.session_hdl = hsm_session_hdl;

		ITEST_LOG("SM2 signature generation for 1s on %d byte size blocks: ",
			  msg_size[i]);
		for (j = 0; j < iter; j++) {
			/* Start the timer */
			start_timer(&t_perf);
			err = hsm_generate_signature(sg0_sig_gen_serv,
						     &sig_gen_args);
			if (err)
				goto out;
			/* Stop the timer */
			stop_timer(&t_perf);
		}
		/* Finalize time to get stats */
		finalize_timer(&t_perf, iter);
		print_perf(&t_perf, iter);

		sig_ver_args.key = pub_key;
		sig_ver_args.message = msg_input;
		sig_ver_args.signature = sign_out;
		sig_ver_args.key_size = PUB_KEY_SIZE;
		sig_ver_args.signature_size = PUB_KEY_SIZE + 1; /* Add 1 byte for Ry */
		sig_ver_args.message_size = msg_size[i];
		sig_ver_args.scheme_id = HSM_SIGNATURE_SCHEME_DSA_SM2_FP_256_SM3;
		sig_ver_args.flags = HSM_OP_VERIFY_SIGN_FLAGS_INPUT_MESSAGE;

		memset(&t_perf, 0, sizeof(t_perf));
		t_perf.session_hdl = hsm_session_hdl2;

		ITEST_LOG("SM2 signature verification for 1s on %d byte size blocks: ",
			  msg_size[i]);

		for (j = 0; j < iter; j++) {
			/* Start the timer */
			start_timer(&t_perf);
			err = hsm_verify_signature(sv0_sig_ver_serv,
						   &sig_ver_args,
						   &verify_status);
			if (err)
				goto out;
			ASSERT_EQUAL(verify_status,
				     HSM_VERIFICATION_STATUS_SUCCESS);
			/* Stop the timer */
			stop_timer(&t_perf);
		}
		/* Finalize time to get stats */
		finalize_timer(&t_perf, iter);
		print_perf(&t_perf, iter);
	}

out:
	ASSERT_EQUAL(hsm_close_signature_verification_service(sv0_sig_ver_serv),
		     HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_signature_generation_service(sg0_sig_gen_serv),
		     HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_key_store_service(key_store_hdl),
		     HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_session(hsm_session_hdl),
		     HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_session(hsm_session_hdl2),
		     HSM_NO_ERROR);

	if (err)
		ASSERT_FALSE(err);

	return TRUE_TEST;
}
