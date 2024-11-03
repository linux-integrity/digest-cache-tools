/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Header file of TLV parser.
 */

#ifndef _TLV_PARSER_H
#define _TLV_PARSER_H

#include <stdio.h>
#include <errno.h>
#include <stddef.h>
#include <asm/byteorder.h>
#include <linux/tlv_parser.h>

#include "common.h"

#ifdef TLV_DEBUG
#define pr_debug(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define pr_debug(fmt, ...) { }
#endif

typedef int (*callback)(void *callback_data, __u16 field,
			const __u8 *field_data, __u32 field_len);

int tlv_parse(callback callback, void *callback_data, const __u8 *data,
	      size_t data_len, const char **fields, __u32 num_fields);

#endif /* _TLV_PARSER_H */
