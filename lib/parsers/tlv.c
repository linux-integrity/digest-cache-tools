// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Parse tlv digest lists.
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#include <limits.h>
#include <sys/mman.h>
#include <sys/xattr.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <linux/hash_info.h>
#include <linux/xattr.h>
#include <linux/tlv_digest_list.h>
#include <asm/byteorder.h>

#include "tlv_parser.h"
#include "common.h"
#include "parsers.h"

struct tlv_parse_ctx {
	const char *digest_list_path;
	size_t digest_list_path_len;
	__u64 parsed_num_entries;
	enum hash_algo algo;
	enum ops op;
};

const char *digest_list_types_str[] = {
	FOR_EACH_DIGEST_LIST_TYPE(GENERATE_STRING)
};

const char *digest_list_fields_str[] = {
	FOR_EACH_DIGEST_LIST_FIELD(GENERATE_STRING)
};

const char *digest_list_entry_types_str[] = {
	FOR_EACH_DIGEST_LIST_ENTRY_TYPE(GENERATE_STRING)
};

const char *digest_list_entry_fields_str[] = {
	FOR_EACH_DIGEST_LIST_ENTRY_FIELD(GENERATE_STRING)
};

static int parse_digest_list_algo(struct tlv_parse_ctx *ctx,
				  enum digest_list_fields __unused field,
				  const __u8 *field_data, __u64 field_data_len)
{
	if (field_data_len != sizeof(__u64))
		return -EINVAL;

	ctx->algo = __be64_to_cpu(*(__u64 *)field_data);
	return 0;
}

static int parse_entry_digest(struct tlv_parse_ctx *ctx,
			      enum digest_list_entry_fields __unused field,
			      const __u8 *field_data, __u64 field_data_len)
{
	int i;

	if (ctx->op != OP_SHOW)
		return 0;

	if (field_data_len != (__u64)hash_digest_size[ctx->algo])
		return -EINVAL;

	printf("%s:", hash_algo_name[ctx->algo]);

	for (i = 0; i < hash_digest_size[ctx->algo]; i++)
		printf("%02x", field_data[i]);

	return 0;
}

static int parse_entry_path(struct tlv_parse_ctx *ctx,
			    enum digest_list_entry_fields __unused field,
			    const __u8 *field_data,
			    __u64 __unused field_data_len)
{
	char *entry_path = (char *)field_data;
	char *digest_list_filename = strrchr(ctx->digest_list_path, '/') + 1;
	int ret, digest_list_filename_len = strlen(digest_list_filename);

	switch (ctx->op) {
	case OP_SHOW:
		printf(" %s\n", entry_path);
		ret = 0;
		break;
	case OP_UPDATE_XATTR:
		ret = lgetxattr(entry_path, digest_list_xattr_name(), NULL, 0);
		if (ret <= 0) {
			ret = 0;
			break;
		}
		__attribute__ ((fallthrough));
	case OP_ADD_XATTR:
		ret = lsetxattr(entry_path, digest_list_xattr_name(),
				digest_list_filename, digest_list_filename_len,
				0);
		if (ret < 0)
			printf("Error setting %s on %s, %s\n",
			       digest_list_xattr_name(), entry_path,
			       strerror(errno));
		ret = 0;
		break;
	case OP_RM_XATTR:
		ret = lremovexattr(entry_path, digest_list_xattr_name());
		if (ret < 0 && errno != ENODATA)
			printf("Error removing %s from %s, %s\n",
			       digest_list_xattr_name(), entry_path,
			       strerror(errno));
		ret = 0;
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

	return ret;
}

static int digest_list_entry_hdr_callback(void *callback_data __unused,
					  __u64 data_type,
					  __u64 num_entries __unused,
					  __u64 total_len __unused)
{
	if (data_type != DIGEST_LIST_ENTRY_DATA)
		return 0;

	return 1;
}

static int digest_list_entry_data_callback(void * callback_data, __u64 field,
					   const __u8 *field_data,
					   __u64 field_data_len)
{
	struct tlv_parse_ctx *ctx = (struct tlv_parse_ctx *)callback_data;
	int ret;

	switch (field) {
	case DIGEST_LIST_ENTRY_DIGEST:
		ret = parse_entry_digest(ctx, field, field_data,
					 field_data_len);
		break;
	case DIGEST_LIST_ENTRY_PATH:
		ret = parse_entry_path(ctx, field, field_data, field_data_len);
		break;
	default:
		pr_debug("Unhandled field %llu\n", field);
		/* Just ignore non-relevant fields. */
		ret = 0;
		break;
	}

	return ret;
}

static int parse_digest_list_entry(struct tlv_parse_ctx *ctx,
				   enum digest_list_fields __unused field,
				   const __u8 *field_data, __u64 field_data_len)
{
	return tlv_parse(digest_list_entry_hdr_callback, NULL,
			 digest_list_entry_data_callback, ctx, field_data,
			 field_data_len, digest_list_entry_types_str,
			 DIGEST_LIST_ENTRY__LAST, digest_list_entry_fields_str,
			 DIGEST_LIST_ENTRY_FIELD__LAST);
}

static int digest_list_hdr_callback(void *callback_data, __u64 data_type,
				    __u64 num_entries, __u64 total_len __unused)
{
	struct tlv_parse_ctx *ctx = (struct tlv_parse_ctx *)callback_data;

	if (data_type != DIGEST_LIST_FILE)
		return 0;

	/* At the moment we process only one block. */
	if (ctx->parsed_num_entries)
		return -EINVAL;

	ctx->parsed_num_entries = num_entries;
	return 1;
}

static int digest_list_data_callback(void *callback_data, __u64 field,
				     const __u8 *field_data,
				     __u64 field_data_len)
{
	struct tlv_parse_ctx *ctx = (struct tlv_parse_ctx *)callback_data;
	int ret;

	switch (field) {
	case DIGEST_LIST_ALGO:
		ret = parse_digest_list_algo(ctx, field, field_data,
					     field_data_len);
		break;
	case DIGEST_LIST_ENTRY:
		ret = parse_digest_list_entry(ctx, field, field_data,
					      field_data_len);
		break;
	default:
		pr_debug("Unhandled field %llu\n", field);
		/* Just ignore non-relevant fields. */
		ret = 0;
		break;
	}

	return ret;
}

int tlv_list_parse(const char *digest_list_path, __u8 *data, size_t data_len,
		   enum ops op)
{
	struct tlv_parse_ctx ctx = {
		.op = op, .digest_list_path = digest_list_path,
		.digest_list_path_len = strlen(digest_list_path)
	};

	return tlv_parse(digest_list_hdr_callback, &ctx,
			 digest_list_data_callback, &ctx, data, data_len,
			 digest_list_types_str, DIGEST_LIST__LAST,
			 digest_list_fields_str, DIGEST_LIST_FIELD__LAST);
}
