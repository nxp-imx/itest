#ifndef __IJSON_UTILS_H__
#define __IJSON_UTILS_H__

#include "json_util.h"
int parse_file(char *f_in, int (*callback)(struct json_object *));
int run_wycheproof_json(char *f_in);

#endif /* __IJSON_UTILS_H__*/