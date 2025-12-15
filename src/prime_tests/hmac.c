// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
#include "prime/prime_functions.h"

/* Number of iterations */
#define NUM_OPERATIONS 100000

#define MAX_PAYLOAD_SIZE 16384
#define NUM_PAYLOAD_SIZE 10
#define BURST_SZ	252
#define NUM_KEY_SIZE	3
#define MAX_KEY_SZ	0x80

static uint8_t sha_algo[NUM_KEY_SIZE] = {
	CRYPTO_AUTH_SHA_256,
	CRYPTO_AUTH_SHA_384,
	CRYPTO_AUTH_SHA_521,
};

static uint16_t key_sz[NUM_KEY_SIZE] = {
	0x40,
	0x80,
	0x80,
};

static uint32_t digest_sz[NUM_KEY_SIZE] = {
	0x20,
	0x30,
	0x40,
};

int hmac(void)
{
	prime_err_t err = 0;
	crypto_op_args_t *op_ptr[BURST_SZ] = {0};
	hmac_key_t key_args = {0};
	crypto_op_args_t op  = {0};
	uint8_t test_msg[MAX_PAYLOAD_SIZE] = {0};
	uint32_t payload_size[] = {32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384};
	timer_perf_t t_perf = {0};
	uint32_t i = 0, j = 0, k = 0, t = 0, iter = NUM_OPERATIONS;
	uint8_t hmac_key[MAX_KEY_SZ] = {0};
	open_service_args_t op_serv_args = {0};
	uint32_t unused_ops = iter, enq_ops = 0;

	/* open prime service */
	op_serv_args.serv_type = SERVICE_TYPE_ALL;
	serv_hdl = prime_open_service(&op_serv_args, &serv_hdl);

	ASSERT_EQUAL(randomize(test_msg, sizeof(test_msg)), sizeof(test_msg));
	ASSERT_EQUAL(randomize(hmac_key, sizeof(hmac_key)), sizeof(hmac_key));

	for (t = 0; t < NUM_KEY_SIZE; t++) {
		/* load hmac key */
		key_args.keylen = key_sz[t];
		key_args.key = hmac_key;
		key_args.keyslot = 0;
		key_args.sha_algo = sha_algo[t];
		err = prime_auth_init(&key_args);
		if (err) {
			printf("prime_auth_init failed err: 0x%x\n", err);
			goto out;
		}

		for (i = 0; i < NUM_PAYLOAD_SIZE; i++) {
			/* allocate input buffer from reserved memory */
			op.src.len = payload_size[i];
			prime_malloc(serv_hdl,
					 &op.src.virt_addr,
					 &op.src.phys_addr,
					 op.src.len);

			/* allocate digest buffer from reserved memory */
			op.op_auth_args.digest.len = digest_sz[t];
			prime_malloc(serv_hdl,
					 &op.op_auth_args.digest.virt_addr,
					 &op.op_auth_args.digest.phys_addr,
					 op.op_auth_args.digest.len);

			/* prepare op */
			op.op_type = CRYPTO_OP_TYPE_HMAC;
			op.op_auth_args.sha_algo = key_args.sha_algo;
			op.op_auth_args.keyslot = key_args.keyslot;
			op.op_auth_args.dir = CRYPTO_AUTH_OP_HMAC_GEN;

			/* copy the test vector input data */
			prime_mcopy(op.src.virt_addr, test_msg, op.src.len);

			/* cache clean */
			data_cache_clean(op.src.virt_addr, op.src.len, 1);

			/* fill op pointer array */
			for (k = 0; k < BURST_SZ; k++)
				op_ptr[k] = &op;

			/* clear the time structure */
			memset(&t_perf, 0, sizeof(t_perf));
			unused_ops = iter;

			ITEST_LOG("HMAC_SHA%d generation on %d byte blocks\n",
				   digest_sz[t] * 8, payload_size[i]);
			for (j = 0; j < iter; j = j + enq_ops) {
				/* calculate number of ops to be enqueued */
				enq_ops = (unused_ops > BURST_SZ) ? BURST_SZ : unused_ops;

				/* Start the timer */
				start_timer(&t_perf);

				/* invoke fast crypto engine */
				prime_process_ops(serv_hdl, op_ptr, enq_ops);

				/* Stop the timer */
				stop_timer(&t_perf);

				/* update remaining ops */
				unused_ops = unused_ops - enq_ops;
			}

			if (unused_ops > 0)
				ITEST_LOG("PRIME: %u operations not processed\n", unused_ops);

			/* Finalize time to get stats */
			finalize_timer(&t_perf, iter);
			print_perf_prime(&t_perf, iter, payload_size[i]);

			/* cache clean and invalidate */
			data_cache_clean(op.op_auth_args.digest.virt_addr,
					 op.op_auth_args.digest.len, 0);

			/* prepare op for hmac verify operation */
			op.op_auth_args.dir = CRYPTO_AUTH_OP_HMAC_VERIFY;

			/* clear the time structure */
			memset(&t_perf, 0, sizeof(t_perf));
			unused_ops = iter;

			ITEST_LOG("HMAC_SHA%d verification on %d byte blocks\n",
				   digest_sz[t] * 8, payload_size[i]);
			for (j = 0; j < iter; j = j + enq_ops) {
				/* calculate number of ops to be enqueued */
				enq_ops = (unused_ops > BURST_SZ) ? BURST_SZ : unused_ops;

				/* Start the timer */
				start_timer(&t_perf);

				/* invoke fast crypto engine */
				prime_process_ops(serv_hdl, op_ptr, enq_ops);

				/* Stop the timer */
				stop_timer(&t_perf);

				/* update remaining ops */
				unused_ops = unused_ops - enq_ops;
			}

			if (unused_ops > 0)
				ITEST_LOG("PRIME: %u operations not processed\n", unused_ops);

			/* Finalize time to get stats */
			finalize_timer(&t_perf, iter);
			print_perf_prime(&t_perf, iter, payload_size[i]);


			/* cache clean and invalidate */
			data_cache_clean(op.op_auth_args.digest.virt_addr,
					 op.op_auth_args.digest.len, 0);

			/* free memory*/
			prime_mfree(serv_hdl, op.op_auth_args.digest.len);
			prime_mfree(serv_hdl, op.src.len);
		}
	}

out:
	/* close prime service */
	prime_close_service(serv_hdl);

	if (err)
		return FALSE_TEST;

	return TRUE_TEST;
}
