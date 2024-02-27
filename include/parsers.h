/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2017-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Header for all digest list parsers.
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

int tlv_list_parse(const char *digest_list_path, __u8 *data, size_t data_len,
		   enum ops op);
int rpm_list_parse(const char *digest_list_path, __u8 *data, size_t data_len,
		   enum ops op);
