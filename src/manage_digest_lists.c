// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement a tool to manage digest lists.
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/hash_info.h>
#include <linux/xattr.h>
#include <fts.h>
#include <stdbool.h>
#include <sys/mman.h>

#include "common.h"
#include "list.h"
#include "generators.h"
#include "parsers.h"

#define BUF_SIZE 8192

struct filename_entry {
	struct list_head list;
	char *name;
	unsigned int seq_num;
};

const char *ops_str[OP__LAST] = {
	[OP_GEN] = "gen",
	[OP_SHOW] = "show",
	[OP_ADD_XATTR] = "add-xattr",
	[OP_RM_XATTR] = "rm-xattr",
	[OP_UPDATE_XATTR] = "update-xattr",
	[OP_ADD_SEQNUM] = "add-seqnum",
	[OP_RM_SEQNUM] = "rm-seqnum",
};

struct generator generators[] = {
	{ .name = "tlv", .new = tlv_list_gen_new, .add = tlv_list_gen_add,
	  .close = tlv_list_gen_close },
	{ .name = "rpm", .add = rpm_list_gen_add },
};

struct parser parsers[] = {
	{ .name = "tlv", .parse = tlv_list_parse },
	{ .name = "rpm", .parse = rpm_list_parse },
};

static char *get_path_ima(char *line)
{
	char *path, *separator;
	int i;

	for (i = 0, path = line;
	     i < 4 && (path = strchr(path, ' ')); i++, path++)
		;

	separator = path;
	strsep(&separator, " \n");

	if (!path || path[0] != '/')
		return NULL;

	return path;
}

static int generator_add(struct generator *generator, int dirfd,
			 void *ptr, char *input)
{
	char *full_path = input;
	int ret;

	if (!generator->add)
		return -ENOENT;

	if (strncmp(input, "rpmdb", 5)) {
		full_path = realpath(input, NULL);
		if (!full_path) {
			printf("Error generating full path of %s, skipping\n",
			       input);
			return 0;
		}
	}

	ret = generator->add(dirfd, ptr, full_path);

	if (full_path != input)
		free(full_path);

	return ret;
}

static int gen_digest_list(char *digest_list_format, char *digest_list_dir,
			   char *input, int input_is_list, char *output,
			   enum hash_algo algo)
{
	struct generator *generator;
	void *ptr = NULL;
	FTS *fts = NULL;
	FTSENT *ftsent;
	FILE *fp;
	int fts_flags = (FTS_PHYSICAL | FTS_COMFOLLOW | FTS_NOCHDIR | FTS_XDEV);
	char *paths[2] = { input, NULL };
	char *line, *path, *separator;
	bool is_ima;
	int ret = 0, i, dirfd;

	for (i = 0; i < ARRAY_SIZE(generators); i++)
		if (!strcmp(generators[i].name, digest_list_format))
			break;

	if (i == ARRAY_SIZE(generators)) {
		printf("Cannot find generator for %s\n", digest_list_format);
		return -ENOENT;
	}

	generator = &generators[i];

	dirfd = open(digest_list_dir, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		printf("Unable to open %s, ret: %d\n", digest_list_dir, -errno);
		return -errno;
	}

	if (generator->new) {
		ptr = generator->new(dirfd, input, output, algo);
		if (!ptr) {
			ret = -ENOMEM;
			goto out;
		}
	}

	if (input_is_list) {
		is_ima = !strcmp(basename(input), "ascii_runtime_measurements");

		fp = fopen(input, "rb");
		if (!fp) {
			ret = -errno;
			goto out_close;
		}

		line = malloc(BUF_SIZE);
		if (!line) {
			ret = -ENOMEM;
			goto out_close;
		}

		while (fgets(line, BUF_SIZE, fp)) {
			path = is_ima ? get_path_ima(line) : line;
			if (!path)
				continue;

			separator = path;
			strsep(&separator, "\n");

			ret = generator_add(generator, dirfd, ptr, path);
			if (ret < 0)
				printf("Error generating entry for %s, ret: %d\n",
				       path, ret);
		}

		free(line);
		fclose(fp);
		goto out_close;
	} else if (!strncmp(input, "rpmdb", 5)) {
		ret = generator_add(generator, dirfd, ptr, input);
		if (ret < 0)
			printf("Error generating entry for %s, ret: %d\n",
			       input, ret);

		goto out_close;
	}

	fts = fts_open(paths, fts_flags, NULL);
	if (!fts) {
		printf("Unable to open %s\n", input);
		ret = -EACCES;
		goto out_close;
	}

	while ((ftsent = fts_read(fts)) != NULL) {
		switch (ftsent->fts_info) {
		case FTS_F:
			ret = generator_add(generator, dirfd, ptr,
					    ftsent->fts_path);
			if (ret < 0)
				printf("Error generating entry for %s, ret: %d\n",
				       ftsent->fts_path, ret);

			break;
		default:
			break;
		}
	}

	fts_close(fts);
out_close:
	if (generator->close)
		generator->close(ptr);
out:
	close(dirfd);
	return ret;
}

static struct parser *get_parser(const char *filename)
{
	const char *separator;
	int i;

	if (filename[0] >= '0' && filename[0] <= '9') {
		separator = strchr(filename, '-');
		if (separator)
			filename = separator + 1;
	}

	separator = strchr(filename, '-');
	if (!separator)
		return NULL;

	for (i = 0; i < ARRAY_SIZE(parsers); i++)
		if (!strncmp(parsers[i].name, filename, separator - filename))
			break;

	if (i == ARRAY_SIZE(parsers)) {
		printf("Cannot find parser for file %s\n", filename);
		return NULL;
	}

	return &parsers[i];
}

static int parse_digest_list(char *digest_list_path, enum ops op)
{
	struct parser *parser;
	__u8 *data;
	size_t data_len, data_len_stripped;
	int ret;

	parser = get_parser(basename(digest_list_path));
	if (!parser)
		return -ENOENT;

	ret = read_file(digest_list_path, &data_len, &data);
	if (ret < 0)
		return ret;

	data_len_stripped = strip_modsig(data, data_len);

	ret = parser->parse(digest_list_path, data, data_len_stripped, op);

	munmap(data, data_len);
	return ret;
}

static int parse_digest_lists(char *digest_list_path, enum ops op)
{

	FTS *fts = NULL;
	FTSENT *ftsent;
	int fts_flags = (FTS_PHYSICAL | FTS_COMFOLLOW | FTS_NOCHDIR | FTS_XDEV);
	char *paths[2] = { NULL, NULL };
	char *full_path = NULL;
	int ret = 0;

	full_path = realpath(digest_list_path, NULL);
	if (!full_path)
		return -ENOMEM;

	paths[0] = full_path;

	fts = fts_open(paths, fts_flags, NULL);
	if (!fts) {
		printf("Unable to open %s\n", digest_list_path);
		free(full_path);
		return -EACCES;
	}

	while ((ftsent = fts_read(fts)) != NULL) {
		switch (ftsent->fts_info) {
		case FTS_F:
			ret = parse_digest_list(ftsent->fts_accpath, op);
			if (ret < 0)
				printf("Error parsing %s for op %s, ret: %d\n",
				       ftsent->fts_accpath, ops_str[op], ret);

			break;
		default:
			break;
		}
	}

	fts_close(fts);
	free(full_path);
	return ret;
}

static int init_filenames(struct list_head *head, char *input)
{
	unsigned int seq_num = 0;
	struct filename_entry *new_entry;
	char *line = NULL, *path, *filename, *separator;
	bool is_ima = false;
	FILE *fp;
	int ret = 0;

	is_ima = !strcmp(basename(input), "ascii_runtime_measurements");

	fp = fopen(input, "rb");
	if (!fp)
		return -EACCES;

	line = malloc(PATH_MAX);
	if (!line) {
		ret = -ENOMEM;
		goto out;
	}

	while (fgets(line, PATH_MAX, fp)) {
		path = is_ima ? get_path_ima(line) : line;
		if (!path)
			continue;

		separator = path;
		strsep(&separator, "\n");
		filename = basename(path);

		new_entry = malloc(sizeof(*new_entry));
		if (!new_entry) {
			ret = -ENOMEM;
			goto out;
		}

		INIT_LIST_HEAD(&new_entry->list);

		if (filename[0] >= '0' && filename[0] <= '9') {
			separator = strchr(filename, '-');
			if (separator)
				filename = separator + 1;
		}

		new_entry->name = strdup(filename);
		if (!new_entry->name) {
			ret = -ENOMEM;
			goto out;
		}

		new_entry->seq_num = seq_num++;
		list_add_tail(&new_entry->list, head);
	}
out:
	free(line);
	fclose(fp);
	return ret;
}

static void free_filenames(struct list_head *head)
{
	struct filename_entry *p, *q;

	list_for_each_entry_safe(p, q, head, list) {
		list_del(&p->list);
		free(p->name);
		free(p);
	}
}

static struct filename_entry *search_filename(struct list_head *head,
					      const char *filename)
{
	struct filename_entry *entry;

	list_for_each_entry(entry, head, list) {
		if (!strcmp(entry->name, filename))
			return entry;
	}

	return NULL;
}

static int add_remove_seq_num(char *digest_list_dir, char *input, bool remove)
{
	FTS *fts = NULL;
	FTSENT *ftsent;
	int fts_flags = (FTS_PHYSICAL | FTS_COMFOLLOW | FTS_NOCHDIR | FTS_XDEV);
	char *paths[2] = { NULL, NULL };
	char new_filename_buf[NAME_MAX + 1];
	char *filename, *new_filename, *separator, *new_digest_list_path;
	struct filename_entry *found;
	LIST_HEAD(filenames);
	int ret = 0, dirfd;

	paths[0] = digest_list_dir;

	fts = fts_open(paths, fts_flags, NULL);
	if (!fts) {
		printf("Unable to open %s\n", digest_list_dir);
		return -EACCES;
	}

	dirfd = open(digest_list_dir, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		printf("Unable to open %s, ret: %d\n", digest_list_dir, -errno);
		ret = -errno;
		goto out;
	}

	if (!remove) {
		ret = init_filenames(&filenames, input);
		if (ret < 0)
			goto out;
	}

	new_digest_list_path = malloc(PATH_MAX);
	if (!new_digest_list_path) {
		ret = -ENOMEM;
		goto out;
	}

	while ((ftsent = fts_read(fts)) != NULL) {
		switch (ftsent->fts_info) {
		case FTS_F:
			filename = ftsent->fts_name;

			if (filename[0] >= '0' && filename[0] <= '9') {
				separator = strchr(filename, '-');
				if (separator)
					filename = separator + 1;
			}

			if (!remove) {
				found = search_filename(&filenames, filename);
				if (!found) {
					new_filename = filename;
				} else {
					new_filename = new_filename_buf;
					snprintf(new_filename_buf,
						 sizeof(new_filename_buf),
						 "%d-%s", found->seq_num,
						 filename);
				}
			} else {
				new_filename = filename;
			}

			if (!strcmp(ftsent->fts_name, new_filename))
				break;

			if (remove) {
				ret = unlinkat(dirfd, new_filename, 0);
				if (ret < 0)
					printf("Failed to unlink %s/%s, ret: %d\n",
					       digest_list_dir, new_filename,
					       ret);
			}

			ret = renameat(dirfd, ftsent->fts_name, dirfd,
				       new_filename);
			if (ret < 0) {
				printf("Failed to rename %s/%s to %s/%s, ret: %d\n",
				       digest_list_dir, ftsent->fts_name,
				       new_filename, digest_list_dir, ret);
				break;
			}

			snprintf(new_digest_list_path, PATH_MAX, "%s/%s",
				 digest_list_dir, new_filename);

			ret = parse_digest_list(new_digest_list_path,
						OP_UPDATE_XATTR);
			if (ret < 0)
				printf("Error parsing %s for op %s, ret: %d\n",
				       new_digest_list_path,
				       ops_str[OP_UPDATE_XATTR], ret);

			if (!remove) {
				ret = symlinkat(new_filename, dirfd, filename);
				if (ret < 0)
					printf("Failed to symlink %s/%s to %s/%s, ret: %d\n",
					       digest_list_dir, filename,
					       digest_list_dir, new_filename,
					       ret);
			}

			break;
		default:
			break;
		}
	}

	free(new_digest_list_path);
out:
	if (!remove)
		free_filenames(&filenames);

	fts_close(fts);
	close(dirfd);
	return ret;
}

static void usage(char *progname)
{
	printf("Usage: %s <options>\n", progname);
	printf("Options:\n");
	printf("\t-d <directory>: directory digest lists are written to\n"
	       "\t-i <input>: input digest list for an operation"
	       "\t-L: input is a list of files/directories\n"
	       "\t-a <algo>: digest list algorithm\n"
	       "\t-f <format>: digest list format\n"
	       "\t-o <operation>: operation to perform\n"
	       "\t\tgen: generate a digest list\n"
	       "\t\tshow: show the content of a digest list\n"
	       "\t\tadd-xattr: set the " XATTR_NAME_DIGEST_LIST " xattr to the digest list path\n"
	       "\t\trm-xattr: remove the " XATTR_NAME_DIGEST_LIST " xattr\n"
	       "\t\tupdate-xattr: update the " XATTR_NAME_DIGEST_LIST " xattr if exists\n"
	       "\t\tadd-seqnum: prepend a sequence number to each digest list file name\n"
	       "\t\trm-seqnum: remove sequence number from each digest list file name\n"
	       "\t-O <output>: output file name of the digest list (in addition to <format>-)\n"
	       "\t-t: testing mode\n"
	       "\t-h: display help\n");
}

int main(int argc, char *argv[])
{
	char *digest_list_dir = NULL, *digest_list_format = NULL, *input = NULL;
	char *output = NULL;
	enum hash_algo algo = HASH_ALGO_SHA256;
	enum ops op = OP__LAST;
	struct stat st;
	int c, i;
	int ret, input_is_list = 0;

	while ((c = getopt(argc, argv, "d:i:La:f:o:O:th")) != -1) {
		switch (c) {
		case 'd':
			digest_list_dir = optarg;
			break;
		case 'i':
			input = optarg;
			break;
		case 'L':
			input_is_list = 1;
			break;
		case 'a':
			for (i = 0; i < HASH_ALGO__LAST; i++)
				if (!strcmp(hash_algo_name[i], optarg))
					break;
			if (i == HASH_ALGO__LAST) {
				printf("Invalid algo %s\n", optarg);
				return -EINVAL;
			}
			algo = i;
			break;
		case 'f':
			digest_list_format = optarg;
			break;
		case 'o':
			for (op = 0; op < OP__LAST; op++)
				if (!strcmp(ops_str[op], optarg))
					break;
			if (op == OP__LAST) {
				printf("Invalid op %s\n", optarg);
				return -EINVAL;
			}
			break;
		case 'O':
			output = optarg;
			break;
		case 't':
			testing = true;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			printf("Invalid option %c\n", c);
			return -EINVAL;
		}
	}

	if (op == OP__LAST) {
		printf("Operation not specified\n");
		return -ENOENT;
	}

	switch (op) {
	case OP_GEN:
		if (!digest_list_format || !input || !digest_list_dir) {
			printf("Missing format/input/digest list directory\n");
			return -ENOENT;
		}

		if (stat(digest_list_dir, &st) == -1) {
			ret = mkdir(digest_list_dir, 0755);
			if (ret < 0) {
				printf("Unable to create %s, ret: %d\n",
				       digest_list_dir, -errno);
				return -errno;
			}
		}

		ret = gen_digest_list(digest_list_format, digest_list_dir,
				      input, input_is_list, output, algo);
		break;
	case OP_SHOW:
	case OP_ADD_XATTR:
	case OP_RM_XATTR:
	case OP_UPDATE_XATTR:
		if (!input) {
			printf("Missing input\n");
			return -ENOENT;
		}

		ret = parse_digest_lists(input, op);
		break;
	case OP_ADD_SEQNUM:
		if (!input || !digest_list_dir) {
			printf("Missing parameters\n");
			return -ENOENT;
		}

		ret = add_remove_seq_num(digest_list_dir, input, false);
		break;
	case OP_RM_SEQNUM:
		if (!digest_list_dir) {
			printf("Missing parameters\n");
			return -ENOENT;
		}

		ret = add_remove_seq_num(digest_list_dir, NULL, true);
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

	return ret;
}
