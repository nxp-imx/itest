/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2025-2026 NXP
 */

#ifndef PRIME_FUNCTIONS_H
#define PRIME_FUNCTIONS_H

#include "prime.h"

#define NUM_OPERATIONS 100000
#define BURST_SZ        252
#define SIZE_256MB	0x10000000

#define DMA_ALIGN_SIZE	64
#define ALIGN_UP(x, align) ({           \
	typeof(align) _align = (align); \
	(((x) + (_align - 1)) & ~(_align - 1)); \
})

extern uint8_t *input_msg;
extern prime_hdl_t serv_hdl;

void data_cache_clean(uint8_t *buf, uint32_t len, int clean_only);
void print_perf_prime(timer_perf_t *timer, uint32_t nb_iter,
		      uint32_t payload_size);
void prime_mcopy(void *dst, void *src, size_t size);
int prime_mcompare(void *dst, void *src, size_t size);
#endif
