#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include "test_api.h"

static uint32_t nvm_status;
static pthread_t tid;

#define TIMEOUT_START_NVM 10000
#define T_NVM_WAIT 1000

static void *v2x_hsm_storage_thread(void *arg)
{
    seco_nvm_manager(NVM_FLAGS_V2X | NVM_FLAGS_HSM, &nvm_status);
    return (void *) NULL;
}

hsm_err_t start_nvm_v2x(void){

    int i = 0;
    nvm_status = NVM_STATUS_UNDEF;
    (void)pthread_create(&tid, NULL, v2x_hsm_storage_thread, NULL);
    while (nvm_status <= NVM_STATUS_STARTING) {
        usleep(T_NVM_WAIT);
        if ((i += T_NVM_WAIT) > TIMEOUT_START_NVM){
            nvm_status = NVM_STATUS_UNDEF;
            break;
        }
    }
    return nvm_status;
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
