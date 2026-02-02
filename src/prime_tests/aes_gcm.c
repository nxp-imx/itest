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
#define NUM_KEY_SIZE    3
#define MAX_KEY_SZ      0x20
#define IV_SZ		12
#define AAD_SZ		16
#define TAG_SZ		16

static uint16_t key_sz[NUM_KEY_SIZE] = {
	0x10,
	0x18,
	0x20,
};

int aes_gcm(void)
{
	int err = 0;
	aes_key_t key_args = {0};
	crypto_op_args_t op  = {0};
	uint8_t test_msg[MAX_PAYLOAD_SIZE] = {0};
	uint32_t payload_size[] = {32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384};
	timer_perf_t t_perf = {0};
	uint32_t i = 0, j = 0, k = 0, t = 0, iter = NUM_OPERATIONS;
	uint8_t aes_key[MAX_KEY_SZ] = {0};
	uint8_t iv[IV_SZ] = {0};
	uint8_t aad[AAD_SZ] = {0};
	open_service_args_t op_serv_args = {0};
	uint32_t unused_ops = iter, enq_ops = 0;
	uint16_t burst_sz = BURST_SZ;

	if (itest_ctx.iterations != 0)
		iter  = itest_ctx.iterations;

	if (itest_ctx.burst_size != 0)
		burst_sz = itest_ctx.burst_size;

	crypto_op_args_t *op_ptr[burst_sz];

	memset(op_ptr, 0, sizeof(op_ptr));

	/* open prime service */
	op_serv_args.serv_type = SERVICE_TYPE_ALL;
	serv_hdl = prime_open_service(&op_serv_args, &serv_hdl);

	ASSERT_EQUAL(randomize(aad, sizeof(aad)), sizeof(aad));
	ASSERT_EQUAL(randomize(iv, sizeof(iv)), sizeof(iv));
	ASSERT_EQUAL(randomize(test_msg, sizeof(test_msg)), sizeof(test_msg));
	ASSERT_EQUAL(randomize(aes_key, sizeof(aes_key)), sizeof(aes_key));

	for (t = 0; t < NUM_KEY_SIZE; t++) {
		/* load aes key */
		key_args.keylen = key_sz[t];
		key_args.key = aes_key;
		key_args.keyslot = 0;
		err = prime_cipher_init(&key_args);
		if (err) {
			printf("prime_cipher_init failed err: 0x%x\n", err);
			goto out;
		}

		for (i = 0; i < NUM_PAYLOAD_SIZE; i++) {
			/* allocate input buffer from reserved memory */
			op.src.len = payload_size[i];
			prime_malloc(serv_hdl,
					 &op.src.virt_addr,
					 &op.src.phys_addr,
					 op.src.len);

			/* allocate output buffer from reserved memory */
			op.dst.len = op.src.len;
			prime_malloc(serv_hdl,
					&op.dst.virt_addr,
					&op.dst.phys_addr,
					op.dst.len);

			/* copy the test vector input data */
			prime_mcopy(op.src.virt_addr, test_msg, op.src.len);

			/* cache clean */
			data_cache_clean(op.src.virt_addr, op.src.len, 1);

			/* allocate aad buffer */
			op.op_aead_args.aad.len = sizeof(aad);
			prime_malloc(serv_hdl,
					 &op.op_aead_args.aad.virt_addr,
					 &op.op_aead_args.aad.phys_addr,
					 op.op_aead_args.aad.len);

			/* copy aad & cache clean */
			prime_mcopy(op.op_aead_args.aad.virt_addr, aad,
					op.op_aead_args.aad.len);
			data_cache_clean(op.op_aead_args.aad.virt_addr,
					 op.op_aead_args.aad.len, 1);

			/* allocate tag buffer from reserved memory  */
			op.op_aead_args.tag.len = TAG_SZ;
			prime_malloc(serv_hdl,
					 &op.op_aead_args.tag.virt_addr,
					 &op.op_aead_args.tag.phys_addr,
					 op.op_aead_args.tag.len);

			/* prepare op for encrypt operation */
			op.op_type = CRYPTO_OP_TYPE_AEAD;
			op.op_aead_args.algo = CRYPTO_AEAD_AES_GCM;
			op.op_aead_args.keyslot = key_args.keyslot;
			op.op_aead_args.enc = CRYPTO_CIPHER_OP_ENCRYPT;
			op.op_aead_args.iv = iv;
			op.op_aead_args.ivlen = sizeof(iv);

			/* invoke fast crypto engine */
			for (k = 0; k < burst_sz; k++)
				op_ptr[k] = &op;

			/* clear the time structure */
			memset(&t_perf, 0, sizeof(t_perf));
			unused_ops = iter;

			ITEST_LOG("AES-%d-GCM encryption for 1s on %d byte blocks\n",
				  key_sz[t] * 8, payload_size[i]);
			for (j = 0; j < iter; j = j + enq_ops) {
				/* calculate number of ops to be enqueued */
				enq_ops = (unused_ops > burst_sz) ? burst_sz : unused_ops;

				/* Start the timer */
				start_timer(&t_perf);

				/* invoke fast crypto engine */
				err = prime_process_ops(serv_hdl, op_ptr, enq_ops);
				if (err) {
					ITEST_LOG("prime_process_ops failed err: 0x%x\n", err);
					goto out;
				}

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
			data_cache_clean(op.dst.virt_addr, op.dst.len, 0);
			data_cache_clean(op.op_aead_args.tag.virt_addr, op.op_aead_args.tag.len, 0);

			/* prepare op for decrypt operation */
			op.op_aead_args.enc = CRYPTO_CIPHER_OP_DECRYPT;

			/* clear the time structure */
			memset(&t_perf, 0, sizeof(t_perf));
			unused_ops = iter;

			for (k = 0; k < payload_size[i]; k++) {
				uint8_t virt_buff =  op.dst.virt_addr[k];

				op.dst.virt_addr[k] = op.src.virt_addr[k];
				op.src.virt_addr[k] = virt_buff;
			}

			ITEST_LOG("AES-%d-GCM decryption for 1s on %d byte blocks\n",
				  key_sz[t] * 8, payload_size[i]);
			for (j = 0; j < iter; j = j + enq_ops) {
				/* calculate number of ops to be enqueued */
				enq_ops = (unused_ops > burst_sz) ? burst_sz : unused_ops;

				/* Start the timer */
				start_timer(&t_perf);

				/* invoke fast crypto engine */
				err = prime_process_ops(serv_hdl, op_ptr, enq_ops);
				if (err) {
					ITEST_LOG("prime_process_ops failed err: 0x%x\n", err);
					goto out;
				}

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
			data_cache_clean(op.dst.virt_addr, op.dst.len, 0);

			/* check decrypted output */
			if (prime_mcompare(op.dst.virt_addr, test_msg,
					   op.dst.len))
				printf("Decryption failed\n");

			/* free memory*/
			if (op.dst.virt_addr != op.src.virt_addr)
				prime_mfree(serv_hdl, op.dst.len);

			prime_mfree(serv_hdl, op.src.len);
			prime_mfree(serv_hdl, op.op_aead_args.aad.len);
			prime_mfree(serv_hdl, op.op_aead_args.tag.len);
		}
	}

out:
	/* close prime service */
	prime_close_service(serv_hdl);

	if (err)
		return FALSE_TEST;

	return TRUE_TEST;
}
