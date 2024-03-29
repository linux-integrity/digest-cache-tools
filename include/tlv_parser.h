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

typedef int (*parse_callback)(void *, __u64, const __u8 *, __u64);

int tlv_parse_hdr(const __u8 **data, size_t *data_len, __u64 *parsed_data_type,
		  __u64 *parsed_num_fields, __u64 *parsed_total_len,
		  const char **data_types, __u64 num_data_types);
int tlv_parse_data(parse_callback callback, void *callback_data,
		   __u64 parsed_num_fields, const __u8 *data, size_t data_len,
		   const char **fields, __u64 num_fields);
int tlv_parse(__u64 expected_data_type, parse_callback callback,
	      void *callback_data, const __u8 *data, size_t data_len,
	      const char **data_types, __u64 num_data_types,
	      const char **fields, __u64 num_fields);

#endif /* _TLV_PARSER_H */
