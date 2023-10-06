/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef DGST_H
#define DGST_H

int icrypto_hash_one_go(unsigned char *in, unsigned char *out, char *dgst_type, int size);

#endif