// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "itest.h"

/* Number of iterations */
#define NUM_OPERATIONS  (2000u)
#define MAC_SIZE        16

hsm_err_t cipher_test(hsm_hdl_t cipher_hdl, uint32_t key_identifier,
		      uint8_t *input, uint8_t *output, uint32_t block_size,
		      uint8_t *iv, uint16_t iv_size,
		      hsm_op_cipher_one_go_algo_t algo,
		      hsm_op_cipher_one_go_flags_t flags, uint32_t session_hdl)
{
	op_cipher_one_go_args_t cipher_args = {0};
	uint32_t j, iter = NUM_OPERATIONS;
	timer_perf_t t_perf = {0};
	hsm_err_t err = 0;

	cipher_args.key_identifier = key_identifier;
	cipher_args.iv = iv;
	cipher_args.iv_size = iv_size;
	cipher_args.cipher_algo = algo;
	cipher_args.flags = flags;
	cipher_args.input = input;
	cipher_args.output = output;
	cipher_args.input_size = block_size;
	cipher_args.output_size = block_size;

	memset(&t_perf, 0, sizeof(t_perf));
	t_perf.session_hdl = session_hdl;

	for (j = 0; j < iter; j++) {
		/* Start the timer */
		start_timer(&t_perf);
		err = hsm_cipher_one_go(cipher_hdl, &cipher_args);
		if (err)
			return err;
		/* Stop the timer */
		stop_timer(&t_perf);
	}
	/* Finalize time to get stats */
	finalize_timer(&t_perf, iter);
	print_perf(&t_perf, iter);

	return err;
}

hsm_err_t cmac_test(hsm_hdl_t mac_hdl, uint32_t key_identifier,
		    hsm_op_mac_one_go_algo_t algo, uint8_t *payload,
		    uint32_t payload_size, uint8_t *mac,
		    hsm_op_mac_one_go_flags_t flags, uint32_t session_hdl)
{
	op_mac_one_go_args_t mac_one_go = {0};
	hsm_mac_verification_status_t mac_status = 0;
	timer_perf_t t_perf = {0};
	uint32_t i = 0, iter = NUM_OPERATIONS;
	hsm_err_t err = 0;

	mac_one_go.key_identifier = key_identifier;
	mac_one_go.algorithm = algo;
	mac_one_go.flags = flags;
	mac_one_go.payload = payload;
	mac_one_go.mac = mac;
	mac_one_go.payload_size = payload_size;
	mac_one_go.mac_size = MAC_SIZE;

	memset(&t_perf, 0, sizeof(t_perf));
	t_perf.session_hdl = session_hdl;

	for (i = 0U; i < iter; i++) {
		/* Start the timer */
		start_timer(&t_perf);
		err = hsm_mac_one_go(mac_hdl, &mac_one_go, &mac_status);
		if (err)
			return err;
		/* Stop the timer */
		stop_timer(&t_perf);
		if (flags == HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION)
			ASSERT_EQUAL(mac_status,
				     HSM_MAC_VERIFICATION_STATUS_SUCCESS);
	}
	/* Finalize time to get stats */
	finalize_timer(&t_perf, iter);
	print_perf(&t_perf, iter);
	return err;
}

hsm_err_t auth_test(hsm_hdl_t cipher_hdl, uint32_t key_identifier,
		    uint8_t *input, uint32_t input_size, uint8_t *output,
		    uint32_t output_size, uint8_t *iv, uint16_t iv_size,
		    uint8_t *aad, uint16_t aad_size,
		    hsm_op_auth_enc_algo_t algo, hsm_op_auth_enc_flags_t flags,
		    uint32_t session_hdl)
{
	op_auth_enc_args_t auth_enc_args = {0};
	uint32_t j = 0, iter = NUM_OPERATIONS;
	timer_perf_t t_perf = {0};
	hsm_err_t err = 0;

	auth_enc_args.key_identifier = key_identifier;
	auth_enc_args.iv_size = iv_size;
	auth_enc_args.iv = iv;
	auth_enc_args.ae_algo = algo;
	auth_enc_args.flags = flags;
	auth_enc_args.aad_size = aad_size;
	auth_enc_args.aad = aad;
	auth_enc_args.input_size = input_size;
	auth_enc_args.input = input;
	auth_enc_args.output_size = output_size;
	auth_enc_args.output = output;

	memset(&t_perf, 0, sizeof(t_perf));
	t_perf.session_hdl = session_hdl;

	for (j = 0; j < iter; j++) {
		/* Start the timer */
		start_timer(&t_perf);
		err = hsm_auth_enc(cipher_hdl, &auth_enc_args);
		if (err)
			return err;
		/* Stop the timer */
		stop_timer(&t_perf);
	}
	/* Finalize time to get stats */
	finalize_timer(&t_perf, iter);
	print_perf(&t_perf, iter);

	return err;
}
