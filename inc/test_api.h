#ifndef TEST_API_H
#define TEST_API_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "hsm_api.h"
#include "seco_nvm.h"

#define TRUE 1
#define FALSE 0
#define ASSERT_TRUE(x)  if (!x) {printf("Fail ==> #x expected True => " );printf(#x);printf(" @%s line:%d\n",__FILE__,__LINE__); return FALSE;}
#define ASSERT_FALSE(x) if (x) {printf("Fail ==> #x expected False => " );printf(#x);printf(" @%s line:%d\n",__FILE__,__LINE__); return FALSE;}
#define ASSERT_EQUAL(x, y) if ( x != y) {printf("assert_equal Fail ==> ");printf(#x);printf(" != ");printf(#y);printf(" @%s line:%d\n",__FILE__,__LINE__); return FALSE;}
#define ASSERT_NOT_EQUAL(x, y) if ( x == y) {printf("assert_not_equal Fail ==> ");printf(#x);printf(" == ");printf(#y);printf(" @%s line:%d\n",__FILE__,__LINE__); return FALSE;}

hsm_err_t start_nvm_v2x(void);
hsm_err_t stop_nvm_v2x(void);
size_t save_test_ctx(void *ctx, size_t count, char *file);
size_t load_test_ctx(void *ctx, size_t count, char *file);
size_t randomize(void *out, size_t count);
uint32_t print_perf(struct timespec *ts1, struct timespec *ts2, uint32_t nb_iter);

#endif

