// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2025 NXP
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>
#include "itest.h"
#include <stdarg.h>

/* Log function */
void outputLog(const char *const format, ...)
{
	va_list ap;

	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
	fflush(stdout);
}

size_t randomize(void *out, size_t count){

    FILE *fout = fopen ("/dev/urandom","r");
    size_t rout = 0;
    if (fout == NULL)
    {
        ITEST_LOG("Fail to open /dev/urandom\n");
        return 0;
    }
    rout = fread(out, 1, count, fout);
    fclose (fout);
    return rout;
}

void init_timer(timer_perf_t *timer) {
    timer->min_time_us = UINT64_MAX;
    timer->max_time_us = 0U;
    timer->time_us = 0U;
    timer->op_sec = 0U;
    timer->t_per_op = 0U;
    timer->nb_iter = 0U;
}

void start_timer(timer_perf_t *timer)
{
    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &timer->ts1);
}

void stop_timer(timer_perf_t *timer)
{
	double latency_us = 0;

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &timer->ts2);

	struct time_frame perf_time = {0};
	uint32_t err = 0;

	err = get_perf_timer(timer->session_hdl, &perf_time);

	if (err) {
		ITEST_LOG("Get Performance timer failed\n");
		return;
	}

	timer->fw_t += timespec_elapse_usec(&perf_time.t_start, &perf_time.t_end);
	timer->lib_request_t += timespec_elapse_usec(&timer->ts1, &perf_time.t_start);
	timer->lib_response_t += timespec_elapse_usec(&perf_time.t_end, &timer->ts2);

	/* Compute the latency of a single operation */
	latency_us = timespec_elapse_usec(&timer->ts1, &timer->ts2);
	/* Add the latency to the total */
	timer->time_us += latency_us;
	/* Update min/max latency if lower/greater */
	if (latency_us < timer->min_time_us)
		timer->min_time_us = latency_us;
	if (latency_us > timer->max_time_us)
		timer->max_time_us = latency_us;
}

void finalize_timer(timer_perf_t *timer, uint32_t nb_iter)
{
	timer->op_sec = 1000000*nb_iter/timer->time_us;
	timer->t_per_op = timer->time_us/nb_iter;
	timer->nb_iter = nb_iter;
}

double timespec_elapse_usec(struct timespec *ts1, struct timespec *ts2)
{
	double diff_microsec = 0;
	struct timespec res = {0};

	res.tv_sec = ts2->tv_sec - ts1->tv_sec;
	res.tv_nsec = ts2->tv_nsec - ts1->tv_nsec;

	if (res.tv_nsec < 0) {
		res.tv_sec--;
		res.tv_nsec += 1000000000;
	}

	diff_microsec = res.tv_sec * 1000000 + ((double)res.tv_nsec * 0.001);

	return diff_microsec;
}

void print_perf(timer_perf_t *timer, uint32_t nb_iter)
{
	double lib_request_t_per_op = timer->lib_request_t/nb_iter;
	double lib_response_t_per_op = timer->lib_response_t/nb_iter;
	double fw_t_per_op = timer->fw_t/nb_iter;

	ITEST_LOG("%d ops (%.2lfus/op)\n", timer->op_sec,
					   timer->t_per_op);
	ITEST_LOG("%20s %12s %23s\n", "SE LIB -> Kernel",
#ifdef PSA_COMPLIANT
				      "ELE FW",
#else
				      "V2X FW",
#endif
				      "Kernel -> SE LIB");
	ITEST_LOG("%14.2lfus", lib_request_t_per_op);
	ITEST_LOG("%16.2lfus", fw_t_per_op);
	ITEST_LOG("%17.2lfus\n\n", lib_response_t_per_op);
}
