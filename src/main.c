#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "test_api.h"
#include "8dxl_conf.h"

void gen_lava_test(testsuite *ts, char *ker_dl_link, char *ram_dl_link, char *mod_dl_link, char *dtb_dl_link, char *addr_ts, char *bootimg_dl_link){

    int i;

    printf(lava_get_test_suite_dxl, ker_dl_link, ram_dl_link, mod_dl_link, dtb_dl_link, addr_ts);
    if (bootimg_dl_link != NULL)
        printf(lava_dl_flash_bootimg_dxl, bootimg_dl_link);
    for ( i = 0; ts[i].tc_ptr != NULL; i++){
        printf(lava_test_dxl, ts[i].name, ts[i].name, ts[i].name, ts[i].name);
    }
}

static void print_help(void) {

    printf("Sentinel test suite linux\n\
-h: print this help\n\
-l: list all tests\n\
-v: print test suite version\n\
-b <bootimg download link>: to add in lava .yaml the bootimg link where lava can download the new bootimg to download\n\
-g <test suite download link>: to generate the .yaml file for lava to run all tests, in param the link where lava can download this test suite\n");
}

void print_test_suite(testsuite *ts){
    int i;
        
    for ( i = 0; ts[i].tc_ptr != NULL; i++){
        printf("test %d: %s\n", i, ts[i].name);
    }
}

static void catch_failure(int signo) {
    printf("FAIL\n");
    printf("end of tests by signal %d\n", signo);
    sleep(2);
    exit(0);
}

int main(int argc, char *argv[]){
        
    int i = 0;
    int status = 0;
    testsuite *ts = dxl_ts;
    char *test_name = NULL;
    char *ts_dl_link = NULL;
    char *bootimg_dl_link = NULL;
    char *ker_dl_link = "https://bamboo1.sw.nxp.com/browse/IM-LBLKFA2/latest/artifact/shared/Image/Image";
    char *ram_dl_link = "https://bamboo1.sw.nxp.com/browse/IM-LBLKFA2/latest/artifact/shared/rootfs.cpio.gz/rootfs.cpio.gz";
    char *mod_dl_link = "https://bamboo1.sw.nxp.com/browse/IM-LBLKFA2/latest/artifact/shared/modules_lite.tar.bz2/modules_lite.tar.bz2";
    char *dtb_dl_link = "https://bamboo1.sw.nxp.com/browse/IM-LBLKFA2/latest/artifact/shared/dtb/imx8dxl-evk.dtb";
    int c;
        
    opterr = 0;

    while ((c = getopt (argc, argv, "hlvd:m:r:k:b:g:t:")) != -1) {
        switch (c)
        {
        case 't':
            test_name = optarg;
            break;
        case 'v':
            printf("testsuite v1.0\n");
            return 0;
        case 'l':
            print_test_suite(ts);
            return 0;
        case 'g':
            ts_dl_link = optarg;
            break;
        case 'b':
            bootimg_dl_link = optarg;
            break;
        case 'k':
            ker_dl_link = optarg;
            break;
        case 'r':
            ram_dl_link = optarg;
            break;
        case 'm':
            mod_dl_link = optarg;
            break;
        case 'd':
            dtb_dl_link = optarg;
            break;
        case 'h':
            print_help();
            return 0;
        case '?':
            if ((optopt == 't') || (optopt == 'g')){
                fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            }
            else{
                fprintf (stderr,
                         "Unknown option character -%c.\n",
                         optopt);
                return 0;
            }
        default:
            abort();
        }
    }

    if (ts_dl_link != NULL) {
        gen_lava_test(ts, ker_dl_link, ram_dl_link, mod_dl_link, dtb_dl_link, ts_dl_link, bootimg_dl_link);
	return 0;
    }
    printf("Test Suite 1.0\n");
    if (test_name == NULL){
        printf("no test in param...\n");
        print_test_suite(ts);
        return 0;
    }
    if (signal(SIGINT, catch_failure) == SIG_ERR) {
        fputs("An error occurred while setting a signal handler.\n", stderr);
        return 0;
    }
    for ( i = 0; ts[i].tc_ptr != NULL; i++){
        if (!strcmp(ts[i].name, test_name)){
            printf("%s: ", ts[i].name);
            status = ts[i].tc_ptr();
            if (!status){
                printf("FAIL\n");
            }
            else
                printf("PASS\n");
        }
    }
    printf("end of tests\n");
    return !status;
}
