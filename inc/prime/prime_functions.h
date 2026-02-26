/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2025-2026 NXP
 */

#ifndef PRIME_FUNCTIONS_H
#define PRIME_FUNCTIONS_H

#include "prime.h"
#include "internal/prime_mem.h"

#define NUM_OPERATIONS 100000
#define BURST_SZ        252

extern uint8_t *input_msg;
extern prime_hdl_t serv_hdl;

void data_cache_clean(uint8_t *buf, uint32_t len, int clean_only);
void print_perf_prime(timer_perf_t *timer, uint32_t nb_iter,
		      uint32_t payload_size);
#endif
