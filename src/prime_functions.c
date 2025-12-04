// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "itest.h"
#include "prime/prime_functions.h"

#define dccivac(p)      { asm volatile("dc civac, %0" : : "r"(p) : "memory"); }
#define dcbf(p)         { asm volatile("dc cvac, %0" : : "r"(p) : "memory"); }

#define PRIME_CACHE_LINE_SIZE     32

prime_hdl_t serv_hdl;

int get_soc(void)
{
	char soc_val[MAX_SOC_VAL];

	FILE *file = fopen("/sys/devices/soc0/soc_id", "r");

	if (file == NULL) {
		perror("Error opening the /sys/devices/soc0/soc_id file");
		return -1;
	}

	if (fgets(soc_val, MAX_SOC_VAL, file) == NULL) {
		perror("Error reading the /sys/devices/soc0/soc_id file");
		fclose(file);
		return -1;
	}

	fclose(file);

	soc_val[strcspn(soc_val, "\t\n")] = 0;

	if (strcmp(soc_val, "i.MX943") == 0)
		soc = SOC_IMX943;
	else if (strcmp(soc_val, "i.MX952") == 0)
		soc = SOC_IMX952;
	else {
		perror("Undefined SOC\n");
		return -1;
	}
	return soc;
}

void data_cache_clean(uint8_t *buf, uint32_t len, int clean_only)
{
	uint32_t i;

	if (clean_only) {
		for (i = 0; i <= len; i += PRIME_CACHE_LINE_SIZE)
			dcbf(buf + i);
	} else {
		/* clean and invalidate */
		for (i = 0; i <= len; i += PRIME_CACHE_LINE_SIZE)
			dccivac(buf + i);
	}
}

void print_perf_prime(timer_perf_t *timer, uint32_t nb_iter, uint32_t payload_size)
{
	double throughput_MBps = (((double)timer->op_sec * payload_size) / 1000000);

	ITEST_LOG("%15s %24s %15s %17s %15s\n",
		  "Buf Size", "Enqueued/Dequeued",
		  "MOps/s", "MB/s", "us/op");

	ITEST_LOG("%12d %21d %20.2lf %18.2lf %15.2lf\n",
		  payload_size,
		  nb_iter,
		  (double)timer->op_sec/1000000,
		  throughput_MBps,
		  timer->t_per_op);
}
