// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Generate tlv digest lists.
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/xattr.h>
#include <linux/xattr.h>
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
#include "generators.h"

struct tlv_struct {
	__u8 *digest_list;
	struct tlv_hdr *outer_hdr;
	struct tlv_data_entry *outer_entry;
	enum hash_algo algo;
	int fd;
};

static int new_digest_list(int dirfd, const char *input, const char *output,
			   struct tlv_struct *tlv)
{
	char filename[NAME_MAX + 1];
	struct tlv_hdr *hdr;
	const char *input_ptr = output;
	int ret;

	if (!output) {
		input_ptr = strrchr(input, '/');
		if (input_ptr)
			input_ptr++;
		else
			input_ptr = input;
	}

	snprintf(filename, sizeof(filename), "tlv-%s", input_ptr);

	tlv->fd = openat(dirfd, filename, O_RDWR, 0644);
	if (tlv->fd != -1) {
		printf("File %s exists\n", filename);
		close(tlv->fd);
		return -EEXIST;
	}

	tlv->fd = openat(dirfd, filename, O_RDWR | O_CREAT, 0644);
	if (tlv->fd < 0) {
		printf("Unable to create %s\n", filename);
		return -errno;
	}

	ret = ftruncate(tlv->fd, DIGEST_LIST_SIZE_MAX);
	if (ret == -1) {
		printf("Unable to truncate %s\n", filename);
		close(tlv->fd);
		return -errno;
	}

	tlv->digest_list = mmap(NULL, DIGEST_LIST_SIZE_MAX,
				PROT_READ | PROT_WRITE, MAP_SHARED, tlv->fd, 0);

	if (tlv->digest_list == MAP_FAILED) {
		printf("Cannot allocate buffer\n");
		close(tlv->fd);
		return -ENOMEM;
	}

	hdr = (struct tlv_hdr *)tlv->digest_list;
	memset(hdr, 0, sizeof(*hdr));

	hdr->data_type = __cpu_to_be64(DIGEST_LIST_FILE);
	hdr->num_entries = 0;
	hdr->total_len = 0;
	return 0;
}

static void write_entry(struct tlv_hdr *hdr, struct tlv_data_entry **entry,
			__u16 field, __u8 *data, __u32 data_len,
			bool update_data)
{
	__u16 num_entries;
	__u32 total_len;
	__u32 entry_len;

	num_entries = __be32_to_cpu(hdr->num_entries);
	total_len = __be32_to_cpu(hdr->total_len);

	(*entry)->field = __cpu_to_be16(field);
	(*entry)->length = __cpu_to_be32(data_len);

	if (update_data)
		memcpy((*entry)->data, data, data_len);

	num_entries++;
	entry_len = sizeof(*(*entry)) + data_len;
	total_len += entry_len;

	hdr->num_entries = __cpu_to_be32(num_entries);
	hdr->total_len = __cpu_to_be32(total_len);
	(*entry) = (struct tlv_data_entry *)((__u8 *)*entry + entry_len);
}

void *tlv_list_gen_new(int __unused dirfd, char *input, char *output,
		       enum hash_algo algo)
{
	struct tlv_struct *tlv;
	__u16 _algo;
	int ret;

	tlv = malloc(sizeof(*tlv));
	if (!tlv)
		return NULL;

	ret = new_digest_list(dirfd, input, output, tlv);
	if (ret < 0) {
		free(tlv);
		return NULL;
	}

	tlv->outer_hdr = (struct tlv_hdr *)tlv->digest_list;
	tlv->outer_entry = (struct tlv_data_entry *)(tlv->outer_hdr + 1);
	tlv->algo = algo;

	_algo = __cpu_to_be16(algo);
	write_entry(tlv->outer_hdr, &tlv->outer_entry, DIGEST_LIST_ALGO,
		    (__u8 *)&_algo, sizeof(_algo), true);
	return tlv;
}

int tlv_list_gen_add(int dirfd __unused, void *ptr, char *input)
{
	struct tlv_struct *tlv = (struct tlv_struct *)ptr;
	__u8 digest[SHA512_DIGEST_SIZE];
	struct tlv_hdr *inner_hdr;
	struct tlv_data_entry *inner_entry;
	int ret;

	ret = calc_file_digest(digest, input, tlv->algo);
	if (ret < 0) {
		printf("Cannot calculate digest of %s\n", input);
		return ret;
	}

	inner_hdr = (struct tlv_hdr *)(tlv->outer_entry + 1);
	inner_hdr->data_type = __cpu_to_be64(DIGEST_LIST_ENTRY_DATA);

	inner_entry = (struct tlv_data_entry *)(inner_hdr + 1);

	write_entry(inner_hdr, &inner_entry, DIGEST_LIST_ENTRY_DIGEST, digest,
		    hash_digest_size[tlv->algo], true);
	write_entry(inner_hdr, &inner_entry, DIGEST_LIST_ENTRY_PATH,
		    (__u8 *)input, strlen(input) + 1, true);

	write_entry(tlv->outer_hdr, &tlv->outer_entry, DIGEST_LIST_ENTRY, NULL,
		    (__u8 *)inner_entry - (__u8 *)inner_hdr, false);
	return 0;
}

void tlv_list_gen_close(void *ptr)
{
	struct tlv_struct *tlv = (struct tlv_struct *)ptr;
	int ret __unused;

	munmap(tlv->digest_list, DIGEST_LIST_SIZE_MAX);
	ret = ftruncate(tlv->fd,
			(__u8 *)tlv->outer_entry - (__u8 *)tlv->outer_hdr);
	close(tlv->fd);
	free(tlv);
}
