#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include "test_api.h"

static uint32_t nvm_status;
static pthread_t tid;

#define TIMEOUT_START_NVM 10000
#define T_NVM_WAIT 1000

static void *hsm_storage_thread(void *arg)
{
    seco_nvm_manager(*(uint8_t *)arg, &nvm_status);
    return (void *) NULL;
}

static hsm_err_t start_nvm(uint8_t arg){

    int i = 0;
    nvm_status = NVM_STATUS_UNDEF;
    (void)pthread_create(&tid, NULL, hsm_storage_thread, &arg);
    while (nvm_status <= NVM_STATUS_STARTING) {
        usleep(T_NVM_WAIT);
        if ((i += T_NVM_WAIT) > TIMEOUT_START_NVM){
            nvm_status = NVM_STATUS_UNDEF;
            break;
        }
    }
    return nvm_status;
}

hsm_err_t start_nvm_v2x(void){
    return start_nvm(NVM_FLAGS_V2X | NVM_FLAGS_HSM);
}

hsm_err_t start_nvm_seco(void){
    return start_nvm(NVM_FLAGS_HSM);
}

hsm_err_t stop_nvm_v2x(void){
    if (nvm_status != NVM_STATUS_STOPPED) {
        pthread_cancel(tid);
    }
    seco_nvm_close_session();
    return nvm_status;
}


size_t save_test_ctx(void *ctx, size_t count, char *file){

    FILE *fout = fopen (file,"w");
    size_t wout = 0;
    if (fout == NULL)
    {
        printf("Fail to save test ctx\n");
        return 0;
    }
    wout = fwrite(ctx, count, 1, fout); 
    fclose (fout);
    return wout;
}

size_t load_test_ctx(void *ctx, size_t count, char *file){

    FILE *fout = fopen (file,"r");
    size_t rout = 0;
    if (fout == NULL)
    {
        printf("Fail to load test ctx\n");
        return 0;
    }
    rout = fread(ctx, count, 1, fout); 
    fclose (fout);
    return rout;
}

size_t randomize(void *out, size_t count){

    FILE *fout = fopen ("/dev/urandom","r");
    size_t rout = 0;
    if (fout == NULL)
    {
        printf("Fail to open /dev/urandom\n");
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

void start_timer(timer_perf_t *timer) {
    timer->min_time_us = UINT64_MAX;
    timer->max_time_us = 0U;
    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &timer->ts1);
}

void timer_latency_start(timer_perf_t *timer) {
    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &timer->ts_last);
}

// this function refresh the min and max latency time
void timer_latency_stop(timer_perf_t *timer) {
    struct timespec ts_tmp;
    uint64_t elapse_us;
    
    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts_tmp);
    elapse_us = timespec_elapse_usec(&timer->ts_last, &ts_tmp);
    if (elapse_us < timer->min_time_us)
        timer->min_time_us = elapse_us;
    if (elapse_us > timer->max_time_us)
        timer->max_time_us = elapse_us;
}

void stop_timer(timer_perf_t *timer, uint32_t nb_iter) {
    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &timer->ts2);
    timer->time_us = timespec_elapse_usec(&timer->ts1, &timer->ts2);
    timer->op_sec = (uint32_t)((uint64_t)1000000*(uint64_t)nb_iter/timer->time_us);
    timer->t_per_op = (uint32_t)(timer->time_us/nb_iter);
    timer->nb_iter = nb_iter;
}

uint64_t timespec_elapse_usec(struct timespec *ts1, struct timespec *ts2) {
    return (uint64_t)(ts2->tv_sec - ts1->tv_sec)*1000000u + (ts2->tv_nsec - ts1->tv_nsec)/1000;
}

void print_perf(timer_perf_t *timer) {
    printf("%lu microsec for %d iter.\n", timer->time_us, timer->nb_iter);
    printf("%u op/sec.\n", timer->op_sec);
    printf("%u microseconds/op.\n", timer->t_per_op);
    printf("Latency -> min=%luus max=%luus\n", timer->min_time_us, timer->max_time_us);
}
