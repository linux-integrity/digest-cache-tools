// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the TLV parser.
 */

#define pr_fmt(fmt) "tlv_parser: "fmt
#include <tlv_parser.h>

#include "common.h"

/**
 * tlv_parse - Parse TLV data
 * @callback: Callback function to call to parse the entries
 * @callback_data: Opaque data to supply to the callback function
 * @data: Data to parse
 * @data_len: Length of @data
 * @fields: Array of field strings
 * @num_fields: Number of elements of @fields
 *
 * Parse the TLV data format and call the supplied callback function for each
 * entry, passing also the opaque data pointer.
 *
 * The callback function decides how to process data depending on the field.
 *
 * Return: 0 on success, a negative value on error.
 */
int tlv_parse(callback callback, void *callback_data, const __u8 *data,
	      size_t data_len, const char **fields __unused, __u32 num_fields)
{
	const __u8 *data_ptr = data;
	struct tlv_entry *entry;
	__u16 parsed_field;
	__u32 len;
	int ret;

	if (data_len > UINT32_MAX) {
		pr_debug("Data too big, size: %zd\n", data_len);
		return -E2BIG;
	}

	while (data_len) {
		if (data_len < sizeof(*entry))
			return -EBADMSG;

		entry = (struct tlv_entry *)data_ptr;
		data_ptr += sizeof(*entry);
		data_len -= sizeof(*entry);

		parsed_field = __be16_to_cpu(entry->field);
		if (parsed_field >= num_fields) {
			pr_debug("Invalid field %u, max: %u\n",
				 parsed_field, num_fields - 1);
			return -EBADMSG;
		}

		len = __be32_to_cpu(entry->length);

		if (data_len < len)
			return -EBADMSG;

		pr_debug("Data: field: %s, len: %u\n", fields[parsed_field],
			 len);

		if (!len)
			continue;

		ret = callback(callback_data, parsed_field, data_ptr, len);
		if (ret < 0) {
			pr_debug("Parsing of field %s failed, ret: %d\n",
				 fields[parsed_field], ret);
			return ret;
		}

		data_ptr += len;
		data_len -= len;
	}

	if (data_len) {
		pr_debug("Excess data: %zu bytes\n", data_len);
		return -EBADMSG;
	}

	return 0;
}
