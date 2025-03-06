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

hsm_err_t hsm_generate_key_perf(hsm_hdl_t key_mgmt_hdl, uint32_t key_id,
				uint16_t out_size, hsm_key_group_t key_group,
				hsm_key_type_t key_type, uint8_t *out_key,
#ifdef PSA_COMPLIANT
				hsm_key_lifetime_t key_lifetime,
				hsm_key_usage_t key_usage,
				hsm_permitted_algo_t permitted_algo,
				hsm_bit_key_sz_t bit_key_sz,
				hsm_key_lifecycle_t key_lifecycle,
#else
				hsm_key_info_t key_info,
#endif
				timer_perf_t *t_perf)
{
	op_generate_key_args_t key_gen_args = {0};
	hsm_err_t err = 0;

	key_gen_args.key_identifier = &key_id;
	key_gen_args.out_size = out_size;
	key_gen_args.key_group = key_group;
	key_gen_args.out_key = out_key;
	key_gen_args.key_type = key_type;
#ifdef PSA_COMPLIANT
	key_gen_args.bit_key_sz = bit_key_sz;
	key_gen_args.key_lifecycle = key_lifecycle;
	key_gen_args.key_lifetime = key_lifetime;
	key_gen_args.key_usage = key_usage;
	key_gen_args.permitted_algo = permitted_algo;
#else
	key_gen_args.key_info = key_info;
#endif
	/* Start the timer */
	start_timer(t_perf);
	err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
	if (err)
		return err;

	/* Stop the timer */
	stop_timer(t_perf);

	return err;
}

hsm_err_t hsm_open_key_store(hsm_hdl_t hsm_session_hdl, hsm_hdl_t *key_store_hdl)
{
	hsm_err_t err = 0;
	open_svc_key_store_args_t key_store_args = {0};

	key_store_args.key_store_identifier = 0xABCD;
	key_store_args.authentication_nonce = 0x1234;
	key_store_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
	err = hsm_open_key_store_service(hsm_session_hdl,
					 &key_store_args,
					 key_store_hdl);

	if (err == HSM_KEY_STORE_CONFLICT) {
		key_store_args.flags = 0;
		ASSERT_EQUAL(hsm_open_key_store_service(hsm_session_hdl,
							&key_store_args,
							key_store_hdl),
			     HSM_NO_ERROR);
	} else {
		ASSERT_EQUAL(err, HSM_NO_ERROR);
	}

	return err;
}

hsm_err_t hsm_generate_key_request(hsm_hdl_t key_mgmt_hdl, uint32_t *key_id,
				   uint16_t out_size, hsm_key_group_t key_group,
				   hsm_key_type_t key_type, hsm_op_key_gen_flags_t flags,
#ifdef PSA_COMPLIANT
				   hsm_key_lifetime_t key_lifetime,
				   hsm_key_usage_t key_usage,
				   hsm_permitted_algo_t permitted_algo,
				   hsm_bit_key_sz_t bit_key_sz,
				   hsm_key_lifecycle_t key_lifecycle,
#else
				   hsm_key_info_t key_info,
#endif
				   uint8_t *out_key)
{
	op_generate_key_args_t key_gen_args = {0};
	hsm_err_t err = 0;

	key_gen_args.key_identifier = key_id;
	key_gen_args.out_size = out_size;
	key_gen_args.key_group = key_group;
	key_gen_args.out_key = out_key;
	key_gen_args.key_type = key_type;
	key_gen_args.flags = flags;
#ifdef PSA_COMPLIANT
	key_gen_args.bit_key_sz = bit_key_sz;
	key_gen_args.key_lifecycle = key_lifecycle;
	key_gen_args.key_lifetime = key_lifetime;
	key_gen_args.key_usage = key_usage;
	key_gen_args.permitted_algo = permitted_algo;
#else
	key_gen_args.key_info = key_info;
#endif
	err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);

	return err;
}
