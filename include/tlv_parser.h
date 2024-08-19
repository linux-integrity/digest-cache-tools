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

typedef int (*hdr_callback)(void *callback_data, __u64 data_type,
			    __u64 num_entries, __u64 total_len);
typedef int (*data_callback)(void *callback_data, __u64 field,
			     const __u8 *field_data, __u64 field_len);

int tlv_parse(hdr_callback hdr_callback, void *hdr_callback_data,
	      data_callback data_callback, void *data_callback_data,
	      const __u8 *data, size_t data_len, const char **data_types,
	      __u64 num_data_types, const char **fields, __u64 num_fields);

#endif /* _TLV_PARSER_H */
