/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2017-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Header for all digest list generators.
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

void *tlv_list_gen_new(int dirfd, char *input, char *output,
		       enum hash_algo algo);
int tlv_list_gen_add(int dirfd, void *ptr, char *input);
void tlv_list_gen_close(void *ptr);
