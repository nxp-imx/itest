// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#include "itest.h"
#include "prime/prime_functions.h"

#define dccivac(p)      { asm volatile("dc civac, %0" : : "r"(p) : "memory"); }
#define dcbf(p)         { asm volatile("dc cvac, %0" : : "r"(p) : "memory"); }

#define PRIME_CACHE_LINE_SIZE     32

prime_hdl_t serv_hdl;

uint16_t get_soc(void)
{
	char soc_val[MAX_SOC_VAL];

	FILE *file = fopen("/sys/devices/soc0/soc_id", "r");

	if (file == NULL) {
		perror("Error opening the /sys/devices/soc0/soc_id file");
		return 1;
	}

	if (fgets(soc_val, MAX_SOC_VAL, file) == NULL) {
		perror("Error reading the /sys/devices/soc0/soc_id file");
		if (fclose(file) != 0)
			perror("Error closing /sys/devices/soc0/soc_id file");
		return 1;
	}

	if (fclose(file) != 0)
		printf("Error closing /sys/devices/soc0/soc_id file");

	soc_val[strcspn(soc_val, "\t\n")] = 0;

	if (strcmp(soc_val, "i.MX943") == 0)
		soc = SOC_IMX943;
	else if (strcmp(soc_val, "i.MX952") == 0)
		soc = SOC_IMX952;
	else if (strcmp(soc_val, "i.MX937") == 0)
		soc = SOC_IMX937;
	else {
		perror("Undefined SOC\n");
		return 1;
	}

	return soc;
}

void print_help(void)
{
	ITEST_LOG("\nitest_prime Help Menu:\n\n");
	ITEST_LOG("$ ./itest_prime [OPTION] <argument>\n\n");
	ITEST_LOG("OPTIONS:\n");
	ITEST_LOG("  -h : Print this help\n");
	ITEST_LOG("  -v : Print test suite version\n");
	ITEST_LOG("  -l : List all tests\n");
	ITEST_LOG("  -t <test_name> [-b <burst size[1, 252]> -i <iteration count[1, 100000]>] : ");
	ITEST_LOG("Run test test_name\n");
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

int prime_mcompare(void *dst, void *src, size_t size)
{
	size_t aligned_size = 0;
	char *d8 = (char *)dst;
	char *s8 = (char *)src;
	uint32_t *d32, *s32;

	/* Fast path: Compare 16-byte aligned chunks using memcmp */
	if (((uintptr_t)src % 16) == 0 && ((uintptr_t)dst % 16) == 0) {
		aligned_size = (size / 16) * 16;
		if (aligned_size > 0) {
			if (memcmp(dst, src, aligned_size) != 0)
				return -1;
			d8  += aligned_size;
			s8  += aligned_size;
			size -= aligned_size;
		}
	}

	/* Medium path: Compare remaining 32-bit word aligned chunks */
	if (size >= sizeof(uint32_t)) {
		d32 = (uint32_t *)d8;
		s32 = (uint32_t *)s8;

		while (size >= sizeof(uint32_t)) {
			if (*d32++ != *s32++)
				return -1;
			size -= sizeof(uint32_t);
		}

		d8 = (char *)d32;
		s8 = (char *)s32;
	}

	/* Slow path: Compare remaining bytes */
	while (size--) {
		if (*d8++ != *s8++)
			return -1;
	}

	return 0;
}

void prime_mcopy(void *dst, void *src, size_t size)
{
	size_t aligned_size = 0;
	char *d8 = (char *)dst;
	char *s8 = (char *)src;
	uint32_t *d32, *s32;

	/* Fast path: Copy 16-byte aligned chunks using memcpy */
	if (((uintptr_t)src % 16) == 0 && ((uintptr_t)dst % 16) == 0) {
		aligned_size = (size / 16) * 16;
		if (aligned_size > 0) {
			memcpy(dst, src, aligned_size);
			size -= aligned_size;
		}
	}

	d8 += aligned_size;
	s8 += aligned_size;

	/* Medium path: Copy remaining 32-bit word aligned chunks */
	if (size >= sizeof(uint32_t)) {
		d32 = (uint32_t *)d8;
		s32 = (uint32_t *)s8;

		while (size >= sizeof(uint32_t)) {
			*d32++ = *s32++;
			size -= sizeof(uint32_t);
		}

		d8 = (char *)d32;
		s8 = (char *)s32;
	}

	/* Slow path: Copy remaining bytes */
	while (size--)
		*d8++ = *s8++;
}
