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
 * tlv_parse_hdr - Parse TLV header
 * @hdr_callback: Callback function to call after parsing header
 * @hdr_callback_data: Opaque data to supply to the header callback function
 * @data: Data to parse (updated)
 * @data_len: Length of @data (updated)
 * @parsed_num_entries: Parsed number of data entries (updated)
 * @parsed_total_len: Parsed length of TLV data, excluding the header (updated)
 * @data_types: Array of data type strings
 * @num_data_types: Number of elements of @data_types
 *
 * Parse the header of the TLV data format, move the data pointer to the TLV
 * data part, decrease the data length by the length of the header, and provide
 * the data type, number of entries and the total data length extracted from the
 * header.
 *
 * Return: 1 to process the data entries, 0 to skip, a negative value on error.
 */
static int tlv_parse_hdr(hdr_callback hdr_callback, void *hdr_callback_data,
			 const __u8 **data, size_t *data_len,
			 __u64 *parsed_num_entries, __u64 *parsed_total_len,
			 const char **data_types __unused, __u64 num_data_types)
{
	__u64 parsed_data_type;
	struct tlv_hdr *hdr;

	if (*data_len < sizeof(*hdr)) {
		pr_debug("Data blob too short, %lu bytes, expected %lu\n",
			 *data_len, sizeof(*hdr));
		return -EBADMSG;
	}

	hdr = (struct tlv_hdr *)*data;

	*data += sizeof(*hdr);
	*data_len -= sizeof(*hdr);

	parsed_data_type = __be64_to_cpu(hdr->data_type);
	if (parsed_data_type >= num_data_types) {
		pr_debug("Invalid data type %llu, max: %llu\n",
			 parsed_data_type, num_data_types - 1);
		return -EBADMSG;
	}

	*parsed_num_entries = __be64_to_cpu(hdr->num_entries);

	if (hdr->_reserved != 0) {
		pr_debug("_reserved must be zero\n");
		return -EBADMSG;
	}

	*parsed_total_len = __be64_to_cpu(hdr->total_len);
	if (*parsed_total_len > *data_len) {
		pr_debug("Invalid total length %llu, expected: %lu\n",
			 *parsed_total_len, *data_len);
		return -EBADMSG;
	}

	pr_debug("Header: type: %s, num entries: %llu, total len: %lld\n",
		 data_types[parsed_data_type], *parsed_num_entries,
		 *parsed_total_len);

	return hdr_callback(hdr_callback_data, parsed_data_type,
			    *parsed_num_entries, *parsed_total_len);
}

/**
 * tlv_parse_data - Parse TLV data
 * @data_callback: Callback function to call to parse the data entries
 * @data_callback_data: Opaque data to supply to the data callback function
 * @num_entries: Number of data entries to parse
 * @data: Data to parse
 * @data_len: Length of @data
 * @fields: Array of field strings
 * @num_fields: Number of elements of @fields
 *
 * Parse the data part of the TLV data format and call the supplied callback
 * function for each data entry, passing also the opaque data pointer.
 *
 * The data callback function decides how to process data depending on the
 * field.
 *
 * Return: 0 on success, a negative value on error.
 */
static int tlv_parse_data(data_callback data_callback, void *data_callback_data,
			  __u64 num_entries, const __u8 *data, size_t data_len,
			  const char **fields __unused, __u64 num_fields)
{
	const __u8 *data_ptr = data;
	struct tlv_data_entry *entry;
	__u64 parsed_field, len, i, max_num_entries;
	int ret;

	max_num_entries = data_len / sizeof(*entry);

	/* Possibly lower limit on num_entries loop. */
	if (num_entries > max_num_entries)
		return -EBADMSG;

	for (i = 0; i < num_entries; i++) {
		if (data_len < sizeof(*entry))
			return -EBADMSG;

		entry = (struct tlv_data_entry *)data_ptr;
		data_ptr += sizeof(*entry);
		data_len -= sizeof(*entry);

		parsed_field = __be64_to_cpu(entry->field);
		if (parsed_field >= num_fields) {
			pr_debug("Invalid field %llu, max: %llu\n",
				 parsed_field, num_fields - 1);
			return -EBADMSG;
		}

		len = __be64_to_cpu(entry->length);

		if (data_len < len)
			return -EBADMSG;

		pr_debug("Data: field: %s, len: %llu\n", fields[parsed_field],
			 len);

		if (!len)
			continue;

		ret = data_callback(data_callback_data, parsed_field, data_ptr,
				    len);
		if (ret < 0) {
			pr_debug("Parsing of field %s failed, ret: %d\n",
				 fields[parsed_field], ret);
			return ret;
		}

		data_ptr += len;
		data_len -= len;
	}

	if (data_len) {
		pr_debug("Excess data: %lu bytes\n", data_len);
		return -EBADMSG;
	}

	return 0;
}

/**
 * tlv_parse - Parse data in TLV format
 * @hdr_callback: Callback function to call after parsing header
 * @hdr_callback_data: Opaque data to supply to the header callback function
 * @data_callback: Callback function to call to parse the data entries
 * @data_callback_data: Opaque data to supply to the data callback function
 * @data: Data to parse
 * @data_len: Length of @data
 * @data_types: Array of data type strings
 * @num_data_types: Number of elements of @data_types
 * @fields: Array of field strings
 * @num_fields: Number of elements of @fields
 *
 * Parse data in TLV format and call tlv_parse_data() each time tlv_parse_hdr()
 * returns 1.
 *
 * Return: 0 on success, a negative value on error.
 */
int tlv_parse(hdr_callback hdr_callback, void *hdr_callback_data,
	      data_callback data_callback, void *data_callback_data,
	      const __u8 *data, size_t data_len, const char **data_types,
	      __u64 num_data_types, const char **fields, __u64 num_fields)
{
	__u64 parsed_num_entries, parsed_total_len;
	const __u8 *data_ptr = data;
	int ret = 0;

	pr_debug("Start parsing data blob, size: %lu\n", data_len);

	while (data_len) {
		ret = tlv_parse_hdr(hdr_callback, hdr_callback_data, &data_ptr,
				    &data_len, &parsed_num_entries,
				    &parsed_total_len, data_types,
				    num_data_types);
		switch (ret) {
		case 0:
			/*
			 * tlv_parse_hdr() already checked that
			 * parsed_total_len <= data_len.
			 */
			data_ptr += parsed_total_len;
			data_len -= parsed_total_len;
			continue;
		case 1:
			break;
		default:
			goto out;
		}

		ret = tlv_parse_data(data_callback, data_callback_data,
				     parsed_num_entries, data_ptr,
				     parsed_total_len, fields, num_fields);
		if (ret < 0)
			goto out;

		data_ptr += parsed_total_len;
		data_len -= parsed_total_len;
	}
out:
	pr_debug("End of parsing data blob, ret: %d\n", ret);
	return ret;
}
