#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "ijson_utils.h"
#include "itest.h"
#include "imx8_tests_list.h"

#define ITEST_VERSION "2.0"
#ifndef GIT_COMMIT
#define GIT_COMMIT "no commit id"
#endif

int parse_test(int argc, char **argv);

/* Itest ctx*/
itest_ctx_t itest_ctx;
/* Used to store total test run and test failures */
static int total_run = 0, fails = 0;

static inline void print_version()
{
    ITEST_LOG("itest %s, commit %s\n", ITEST_VERSION, GIT_COMMIT);
}

static inline void print_stats()
{
    ITEST_LOG("+------------------------------------------------------\n");
    ITEST_LOG("Tests Run  : %d\n", total_run);
    ITEST_LOG("Tests Fail : %d\n", fails);
    ITEST_LOG("itest done!\n");
}
static void print_help(void) {

    ITEST_LOG("\nitest Help Menu:\n\n\
$ ./itest [OPTION] <argument>\n\n\
OPTIONS:\n\
  -h: Print this help\n\
  -v: Print test suite version\n\
  -j <json file> : Run json test vector from wycheproof tv\n\
  -l: List all tests\n\
  -c: <dut config> DXL_A1 - QXP_C0 - QXP_B0\n\
  -t <test_name> : Run test test_name\n");
}

void print_test_suite(testsuite *ts){
    int i;
        
    for ( i = 0; ts[i].tc_ptr != NULL; i++){
        if (ts[i].target & itest_ctx.target)
            ITEST_LOG("%s\n", ts[i].name);
    }
}

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
    itest_ctx.ts = imx8_ts;
    itest_ctx.target = DXL_A1; // dxl_ts as default
}

int init_conf(char *target) {

    if (!strcmp(target, "DXL_A1")) {
        itest_ctx.target = DXL_A1;
    }
    else if (!strcmp(target, "DXL_B0")) {
        itest_ctx.target = DXL_B0;
    }
    else if (!strcmp(target, "QXP_B0")) {
        itest_ctx.target = QXP_B0;
    }
    else if (!strcmp(target, "QXP_C0")) {
        itest_ctx.target = QXP_C0;
    }
    else if (!strcmp(target, "DBG")) {
        itest_ctx.target = DBG;
    }
    else {
        ITEST_LOG(" unknow target (DXL_A1 / DXL_B0 / QXP_B0 / QXP_C0 / DBG) \n");
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

    while ((c = getopt (argc, argv, "hlvd:m:r:k:b:g:t:c:j:")) != -1) {
        switch (c)
        {
        case 't':
            itest_ctx.test_name = optarg;
            break;
        case 'j':
            run_wycheproof_json(optarg);
            break;
        case 'v':
            print_version();
            return 0;
        case 'l':
            print_ts = 1;
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
            if (!(itest_ctx.ts[i].target & itest_ctx.target)) {
                ITEST_LOG("#######################################################\n");
                ITEST_LOG("# BAD TARGET FOR TEST: %s\n", itest_ctx.ts[i].name);
                ITEST_LOG("#######################################################\n");
                fails++;
                break;
            }
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
