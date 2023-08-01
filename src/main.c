#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "ijson_utils.h"
#include "itest.h"
#include "version.h"
#include "imx8_tests_list.h"

int parse_test(int argc, char **argv);

/* Itest ctx*/
itest_ctx_t itest_ctx;
/* Used to store total test run and test failures */
static int total_run = 0, fails = 0;

static inline void print_version()
{
	ITEST_LOG("itest %d.%d commit: %s %s\nsecure_enclave commit: %s %s\n",
Itest_VERSION_MAJOR, Itest_VERSION_MINOR, GIT_SHA1, GIT_DATE, GIT_SHA1_ELE_LIB, GIT_DATE_ELE_LIB);
}

static inline void print_stats()
{
    ITEST_LOG("+------------------------------------------------------\n");
    ITEST_LOG("Tests Run  : %d\n", total_run);
    ITEST_LOG("Tests Fail : %d\n", fails);
    ITEST_LOG("itest done!\n");
}
static void print_help(void) {

	ITEST_LOG("\nitest Help Menu:\n\n");
	ITEST_LOG("$ ./itest [OPTION] <argument>\n\n");
	ITEST_LOG("OPTIONS:\n");
	ITEST_LOG("  -h : Print this help\n");
	ITEST_LOG("  -v : Print test suite version\n");
	ITEST_LOG("  -j < json file > : Run json test vector from wycheproof tv\n");
	ITEST_LOG("  -l : List all tests\n");
	ITEST_LOG("  -c : < dut config > MX8ULP_A2 - MX93_A1\n");
	ITEST_LOG("  -t < test_name > : Run test test_name\n");
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
	itest_ctx.target = MX8ULP_A2; // MX8ULP as default
}

int init_conf(char *target) {

	if (!strcmp(target, "MX8ULP_A2")) {
		itest_ctx.target = MX8ULP_A2;
	} else if (!strcmp(target, "MX93_A1")) {
		itest_ctx.target = MX93_A1;
	} else if (!strcmp(target, "DBG")) {
		itest_ctx.target = DBG;
	} else {
		ITEST_LOG("unknown target (MX8ULP_A2 / MX93_A1 / DBG)\n");
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
            if ((optopt == 't') || (optopt == 'g') || (optopt == 'c') || (optopt == 'm')){
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
