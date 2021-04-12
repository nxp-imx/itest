#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "itest.h"
#include "dut_conf.h"

#define ITEST_VERSION "2.0"

/* Used to store total test run and test failures */
static int total_run = 0, fails = 0;

static inline void print_version()
{
    ITEST_LOG("itest %s\n", ITEST_VERSION);
}

static inline void print_stats()
{
    ITEST_LOG("+------------------------------------------------------\n");
    ITEST_LOG("Tests Run  : %d\n", total_run);
    ITEST_LOG("Tests Fail : %d\n", fails);
    ITEST_LOG("itest done!\n");
}

void gen_lava_test(testsuite *ts, char *ker_dl_link, char *ram_dl_link, char *mod_dl_link, char *dtb_dl_link, char *addr_ts, char *bootimg_dl_link){

    int i;

    ITEST_LOG(lava_get_test_suite_dxl, ker_dl_link, ram_dl_link, mod_dl_link, dtb_dl_link, addr_ts);
    if (bootimg_dl_link != NULL)
        ITEST_LOG(lava_dl_flash_bootimg_dxl, bootimg_dl_link);
    for ( i = 0; ts[i].tc_ptr != NULL; i++){
        ITEST_LOG(lava_test_dxl, ts[i].name, ts[i].name, ts[i].name, ts[i].name);
    }
}

static void print_help(void) {

    ITEST_LOG("\nitest Help Menu:\n\n\
$ ./itest [OPTION] <argument>\n\n\
OPTIONS:\n\
  -h: Print this help\n\
  -v: Print test suite version\n\
  -l: List all tests\n\
  -c: <dut config> DXL_A1 - QXP_C0 - QXP_B0\n\
  -t <test_name> : Run test test_name\n\
  -b <bootimg download link>: Add in lava .yaml the bootimg link where lava can download the new bootimg to download\n\
  -g <test suite download link>: Generate the .yaml file for lava to run all tests, in param the link where lava can download this test suite\n");
}

void print_test_suite(testsuite *ts){
    int i;
        
    for ( i = 0; ts[i].tc_ptr != NULL; i++){
        ITEST_LOG("%s\n", ts[i].name);
    }
}

itest_ctx_t itest_ctx;

static void catch_failure(int signo) {
    fails++;
    ITEST_LOG("FAIL: tests interrupted by signal %d\n", signo);
    print_stats();
    sleep(2);
    exit(signo);
}

static void catch_failure_continue(int signo) {
    (void)(signo);
    itest_ctx.nb_assert_fails++;
}

static void itest_init(void) {
    itest_ctx.test_name = NULL;
    itest_ctx.nb_assert_fails = 0;
    itest_ctx.ts = dxl_ts; // dxl_ts as default

    itest_ctx.ker_dl_link = "https://bamboo1.sw.nxp.com/browse/IM-LBLKFA2/latest/artifact/shared/Image/Image";
    itest_ctx.ram_dl_link = "https://bamboo1.sw.nxp.com/browse/IM-LBLKFA2/latest/artifact/shared/rootfs.cpio.gz/rootfs.cpio.gz";
    itest_ctx.mod_dl_link = "https://bamboo1.sw.nxp.com/browse/IM-LBLKFA2/latest/artifact/shared/modules_lite.tar.bz2/modules_lite.tar.bz2";
    itest_ctx.dtb_dl_link = "https://bamboo1.sw.nxp.com/browse/IM-LBLKFA2/latest/artifact/shared/dtb/imx8dxl-evk.dtb";
    itest_ctx.ts_dl_link = NULL;
    itest_ctx.bootimg_dl_link = NULL;

}

int init_conf(char *target) {

    if (!strcmp(target, "DXL_A1")) {
        itest_ctx.ts = dxl_ts;
    }
    else if (!strcmp(target, "QXP_B0")) {
        itest_ctx.ts = qxp_b0_ts;
    }
    else if (!strcmp(target, "QXP_C0")) {
        itest_ctx.ts = qxp_c0_ts;
    }
    else {
        ITEST_LOG(" unknow target (DXL_A1 / QXP_B0 / QXP_C0) \n");
        return 0;
    }
    return 1;
}

int main(int argc, char *argv[]){
        
    int i = 0;
    int status = 0;
    int c;
    int print_ts = 0;

    itest_init();
    opterr = 0;

    while ((c = getopt (argc, argv, "hlvd:m:r:k:b:g:t:c:")) != -1) {
        switch (c)
        {
        case 't':
            itest_ctx.test_name = optarg;
            break;
        case 'v':
            print_version();
            return 0;
        case 'l':
            print_ts = 1;
            break;
        case 'g':
            itest_ctx.ts_dl_link = optarg;
            break;
        case 'b':
            itest_ctx.bootimg_dl_link = optarg;
            break;
        case 'k':
            itest_ctx.ker_dl_link = optarg;
            break;
        case 'r':
            itest_ctx.ram_dl_link = optarg;
            break;
        case 'm':
            itest_ctx.mod_dl_link = optarg;
            break;
        case 'd':
            itest_ctx.dtb_dl_link = optarg;
            break;
        case 'c':
            if (!init_conf(optarg))
                return 0;
            break;
        case 'h':
            print_help();
            return 0;
        case '?':
            if ((optopt == 't') || (optopt == 'g') || (optopt == 'c')){
                fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                print_help();
                return 0;
            }
            else{
                fprintf (stderr, "Unknown option character -%c.\n", optopt);
                print_help();
                return 0;
            }
        default:
            abort();
        }
    }

    if (print_ts == 1) {
        print_test_suite(itest_ctx.ts);
        return 0;
    }

    if (itest_ctx.ts_dl_link != NULL) {
        gen_lava_test(itest_ctx.ts, itest_ctx.ker_dl_link, itest_ctx.ram_dl_link, itest_ctx.mod_dl_link, itest_ctx.dtb_dl_link, itest_ctx.ts_dl_link, itest_ctx.bootimg_dl_link);
        return 0;
    }
    /* Print itest version at the beginning of the test */
    print_version();
    if (itest_ctx.test_name == NULL){
        ITEST_LOG("No tests provided! Please, insert a test:\n");
        print_test_suite(itest_ctx.ts);
        return 0;
    }
    if ((signal(SIGINT, catch_failure) == SIG_ERR)
        || (signal(SIGUSR1, catch_failure_continue) == SIG_ERR)) {
        fputs("An error occurred while setting a signal handler.\n", stderr);
        return 0;
    }
    for ( i = 0; itest_ctx.ts[i].tc_ptr != NULL; i++){
        if (!strcmp(itest_ctx.ts[i].name, itest_ctx.test_name)){
            ITEST_LOG("#######################################################\n");
            ITEST_LOG("# Running test: %s\n", itest_ctx.ts[i].name);
            ITEST_LOG("#######################################################\n");
            total_run++;
            status = itest_ctx.ts[i].tc_ptr();
            ITEST_LOG("#######################################################\n");
            if (!status || (itest_ctx.nb_assert_fails > 0)){
                ITEST_LOG("%s: FAIL ===> %d fails\n",
                    itest_ctx.test_name, itest_ctx.nb_assert_fails);
                fails++;
            }
            else
                ITEST_LOG("%s: PASS\n", itest_ctx.test_name);
        }
    }
    print_stats();

    return fails;
}
