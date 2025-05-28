// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

/* Number of iterations */
#define NUM_OPERATIONS  (1000u)

#define NB_ALGO 3
#define MAX_MSG_SIZE 16384
#define NUM_MSG_SIZE 6
#define MAX_PUB_KEY_SIZE (0x84)
#define KEY_GROUP 12

static hsm_signature_scheme_id_t scheme_id[NB_ALGO] = {
	HSM_SIGNATURE_SCHEME_ECDSA_NIST_P256_SHA_256,
	HSM_SIGNATURE_SCHEME_ECDSA_NIST_P384_SHA_384,
	HSM_SIGNATURE_SCHEME_ECDSA_NIST_P521_SHA_512,
};

static uint16_t size_pub_key[NB_ALGO] = {
	0x40,
	0x60,
	0x84,
};

static char *algo[NB_ALGO] = {
	"ECDSA_NIST_SHA_256",
	"ECDSA_NIST_SHA_384",
	"ECDSA_NIST_SHA_512",
};

static hsm_key_type_t key_type[NB_ALGO] = {
	HSM_KEY_TYPE_ECDSA_NIST_P256,
	HSM_KEY_TYPE_ECDSA_NIST_P384,
	HSM_KEY_TYPE_ECDSA_NIST_P521,
};

int v2x_ecdsa_nist_sign_verify(void)
{
	open_session_args_t open_session_args = {0};
	open_svc_key_management_args_t key_mgmt_args = {0};
	open_svc_sign_gen_args_t open_sig_gen_args = {0};
	open_svc_sign_ver_args_t open_sig_ver_args = {0};
	op_generate_sign_args_t sig_gen_args = {0};
	op_verify_sign_args_t sig_ver_args = {0};
	hsm_hdl_t sig_gen_hdl = 0, sig_ver_hdl = 0;
	hsm_hdl_t key_mgmt_hdl = 0;
	uint32_t key_id[NB_ALGO] = {0};
	uint8_t msg_input[MAX_MSG_SIZE] = {0};
	uint8_t sign_out[MAX_PUB_KEY_SIZE + 1] = {0};
	uint8_t pub_key[NB_ALGO][MAX_PUB_KEY_SIZE] = {0};
	uint32_t iter = NUM_OPERATIONS, i = 0, j = 0, k = 0;
	uint32_t msg_size[] = {16, 64, 256, 1024, 8192, 16384};
	timer_perf_t t_perf = {0};
	hsm_err_t err = 0;
	hsm_verification_status_t verify_status = 0;

	/* input buffer as random */
	ASSERT_EQUAL(randomize(msg_input, MAX_MSG_SIZE), MAX_MSG_SIZE);

	/* open session for V2X HSM SG MU */
	open_session_args.mu_type = V2X_SG0;
	err = hsm_open_session(&open_session_args, &hsm_session_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_session failed err:0x%x\n", err);
		goto out;
	}

	/* open session for V2X HSM SV MU */
	open_session_args.mu_type = V2X_SV0;
	err = hsm_open_session(&open_session_args, &hsm_session_hdl2);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_session failed err:0x%x\n", err);
		goto out;
	}

	/* open key store service */
	err = hsm_open_key_store(hsm_session_hdl, &key_store_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_key_store failed err:0x%x\n", err);
		goto out;
	}
	/* open key management service */
	err = hsm_open_key_management_service(key_store_hdl,
					      &key_mgmt_args,
					      &key_mgmt_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_key_management_service failed err:0x%x\n", err);
		goto out;
	}

	/* open signature generation service */
	err = hsm_open_signature_generation_service(key_store_hdl,
						    &open_sig_gen_args,
						    &sig_gen_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_signature_generation_service failed err:0x%x\n", err);
		goto out;
	}

	/* open signature verification service */
	err = hsm_open_signature_verification_service(hsm_session_hdl2,
						      &open_sig_ver_args,
						      &sig_ver_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_signature_verification_service failed err:0x%x\n", err);
		goto out;
	}

	for (j = 0; j < NB_ALGO; j++) {
		err = hsm_generate_key_request(key_mgmt_hdl, &key_id[j],
					       size_pub_key[j], KEY_GROUP,
					       key_type[j],
					       HSM_OP_KEY_GENERATION_FLAGS_CREATE,
					       HSM_KEY_INFO_TRANSIENT,
					       pub_key[j]);
		if (err) {
			printf("hsm_generate_key failed err:0x%x\n", err);
			goto out;
		}

		for (i = 0; i < NUM_MSG_SIZE; i++) {
			sig_gen_args.key_identifier = key_id[j];
			sig_gen_args.message = msg_input;
			sig_gen_args.signature = sign_out;
			sig_gen_args.message_size = msg_size[i];
			sig_gen_args.signature_size = size_pub_key[j] + 1; /* Add 1 byte for Ry */
			sig_gen_args.scheme_id = scheme_id[j];
			sig_gen_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE;

			memset(&t_perf, 0, sizeof(t_perf));
			t_perf.session_hdl = hsm_session_hdl;

			ITEST_LOG("%s signature generation for 1s on %d byte size blocks: ",
				  algo[j], msg_size[i]);
			for (k = 0; k < iter; k++) {
				/* Start the timer */
				start_timer(&t_perf);
				err = hsm_generate_signature(sig_gen_hdl,
							     &sig_gen_args);
				if (err) {
					printf("hsm_generate_signature failed err:0x%x\n", err);
					goto out;
				}
				/* Stop the timer */
				stop_timer(&t_perf);
			}
			/* Finalize time to get stats */
			finalize_timer(&t_perf, iter);
			print_perf(&t_perf, iter);

			sig_ver_args.key = pub_key[j];
			sig_ver_args.message = msg_input;
			sig_ver_args.signature = sign_out;
			sig_ver_args.key_size = size_pub_key[j];
			sig_ver_args.signature_size = size_pub_key[j] + 1; /* Add 1 byte for Ry */
			sig_ver_args.message_size = msg_size[i];
			sig_ver_args.scheme_id = scheme_id[j];
			sig_ver_args.flags = HSM_OP_VERIFY_SIGN_FLAGS_INPUT_MESSAGE;

			memset(&t_perf, 0, sizeof(t_perf));
			t_perf.session_hdl = hsm_session_hdl2;

			ITEST_LOG("%s signature verification for 1s on %d byte size blocks: ",
				  algo[j], msg_size[i]);
			for (k = 0; k < iter; k++) {
				/* Start the timer */
				start_timer(&t_perf);
				err = hsm_verify_signature(sig_ver_hdl,
							   &sig_ver_args,
							   &verify_status);
				if (err) {
					printf("hsm_verify_signature failed err:0x%x\n", err);
					goto out;
				}
				/* Stop the timer */
				stop_timer(&t_perf);
				if (verify_status != HSM_VERIFICATION_STATUS_SUCCESS) {
					printf("Signature Verification failed\n");
					err = -1;
					goto out;
				}
			}
			/* Finalize time to get stats */
			finalize_timer(&t_perf, iter);
			print_perf(&t_perf, iter);
		}
	}

out:
	if (sig_ver_hdl)
		hsm_close_signature_verification_service(sig_ver_hdl);
	if (sig_gen_hdl)
		hsm_close_signature_generation_service(sig_gen_hdl);
	if (key_store_hdl)
		hsm_close_key_store_service(key_store_hdl);
	hsm_close_session(hsm_session_hdl);
	hsm_close_session(hsm_session_hdl2);

	if (err)
		return FALSE_TEST;

	return TRUE_TEST;
}
