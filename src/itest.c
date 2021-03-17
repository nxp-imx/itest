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

static uint32_t nvm_status_v2x = NVM_STATUS_STOPPED;
static uint32_t nvm_status_seco = NVM_STATUS_STOPPED;
static pthread_t tid_v2x;
static pthread_t tid_seco;
static char ITEST_CTX_PATH[] = "/etc/itest/";

#define TIMEOUT_START_NVM 10000
#define T_NVM_WAIT 1000

/* Log function */
void outputLog(const char *const format, ...)
{
	va_list ap;

	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
	fflush(stdout);
}

static void *hsm_storage_thread(void *arg)
{
    if(*(uint8_t *)arg == (NVM_FLAGS_V2X | NVM_FLAGS_HSM))
	seco_nvm_manager(*(uint8_t *)arg, &nvm_status_v2x);
    else
	seco_nvm_manager(*(uint8_t *)arg, &nvm_status_seco);
    return (void *) NULL;
}

static hsm_err_t start_nvm(uint8_t arg, uint32_t *nvm_status, pthread_t *tid){

    int i = 0;
    *nvm_status = NVM_STATUS_UNDEF;
    (void)pthread_create(tid, NULL, hsm_storage_thread, &arg);
    while (*nvm_status <= NVM_STATUS_STARTING) {
        usleep(T_NVM_WAIT);
        if ((i += T_NVM_WAIT) > TIMEOUT_START_NVM){
            *nvm_status = NVM_STATUS_UNDEF;
            break;
        }
    }
    return *nvm_status;
}

hsm_err_t start_nvm_v2x(void){
    return start_nvm(NVM_FLAGS_V2X | NVM_FLAGS_HSM, &nvm_status_v2x, &tid_v2x);
}

hsm_err_t start_nvm_seco(void){
    return start_nvm(NVM_FLAGS_HSM, &nvm_status_seco, &tid_seco);
}

hsm_err_t stop_nvm_v2x(void){
    if (nvm_status_v2x != NVM_STATUS_STOPPED) {
        pthread_cancel(tid_v2x);
    }
    seco_nvm_close_session();
    return nvm_status_v2x;
}

hsm_err_t stop_nvm_seco(void){
    if (nvm_status_seco != NVM_STATUS_STOPPED) {
        pthread_cancel(tid_seco);
    }
    seco_nvm_close_session();
    return nvm_status_seco;
}


size_t save_test_ctx(void *ctx, size_t count, char *file)
{
    int fd;
    int32_t wout = 0;
    char file_and_path[64];
    int nb;
    struct stat st = {0};

    if (stat(ITEST_CTX_PATH, &st) == -1) {
        mkdir(ITEST_CTX_PATH, 0777);
    }
    nb = snprintf(file_and_path, 64, "%s%s", ITEST_CTX_PATH, file);
    if (nb <= 0) {
        ITEST_LOG("Fail to compose file path\n");
        return 0;
    }
    ITEST_LOG("Saving context to file %s\n", file_and_path);
    fd = open(file_and_path, O_CREAT|O_WRONLY|O_SYNC, S_IRUSR|S_IWUSR);
    if (fd >= 0) {
        /* Write the data. */
        wout = (int32_t)write(fd, ctx, count);
        ITEST_LOG("%d bytes written\n", wout);
        system("sync");
        close(fd);
    } else
        ITEST_LOG("Failed to save test ctx\n");

    return wout;
}

size_t load_test_ctx(void *ctx, size_t count, char *file)
{
    int fd;
    int32_t rout = 0;
    char file_and_path[64];
    int nb;

    nb = snprintf(file_and_path, 64, "%s%s", ITEST_CTX_PATH, file);
    if (nb <= 0) {
        ITEST_LOG("Fail to compose file path\n");
        return 0;
    }
    ITEST_LOG("Loading context from file %s\n", file_and_path);
    /* Open the file as read only. */
    fd = open(file_and_path, O_RDONLY);
    if (fd >= 0) {
        /* Read the data. */
        rout = (int32_t)read(fd, ctx, count);
        ITEST_LOG("%d bytes read\n", rout);
        (void)close(fd);
    } else
        ITEST_LOG("Failed to load test ctx\n");

    return rout;
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

uint32_t clear_v2x_nvm(void) {

    system("rm -rf /etc/v2x_hsm");
    system("sync");
    return 0;
}

uint32_t clear_seco_nvm(void) {

    system("rm -rf /etc/seco_hsm");
    system("sync");
    return 0;
}

void init_timer(timer_perf_t *timer) {
    timer->min_time_us = UINT64_MAX;
    timer->max_time_us = 0U;
    timer->time_us = 0U;
    timer->op_sec = 0U;
    timer->t_per_op = 0U;
    timer->nb_iter = 0U;
}

void start_timer(timer_perf_t *timer) {
    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &timer->ts1);
}

void stop_timer(timer_perf_t *timer) {
    uint64_t latency_us;

    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &timer->ts2);
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

void finalize_timer(timer_perf_t *timer, uint32_t nb_iter) {
    timer->op_sec = (uint32_t)((uint64_t)1000000*(uint64_t)nb_iter/timer->time_us);
    timer->t_per_op = (uint32_t)(timer->time_us/nb_iter);
    timer->nb_iter = nb_iter;
}

uint64_t timespec_elapse_usec(struct timespec *ts1, struct timespec *ts2) {
    return (uint64_t)(ts2->tv_sec - ts1->tv_sec)*1000000u + (ts2->tv_nsec - ts1->tv_nsec)/1000;
}

void print_perf(timer_perf_t *timer) {
    ITEST_LOG("=== Perf ===\n");
    ITEST_LOG("Op/s = %u, Max latency = %lu us\n",
        timer->op_sec, timer->max_time_us);
    ITEST_LOG("Average time single op = %u us, Min latency = %lu us, Total time = %lu us, Num of op = %d\n",
        timer->t_per_op, timer->min_time_us, timer->time_us, timer->nb_iter);
    ITEST_LOG("============\n");
}
