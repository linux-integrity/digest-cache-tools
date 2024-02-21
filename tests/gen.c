// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * File: gen.c
 *      Test manage_digest_lists.c.
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <limits.h>
#include <fts.h>
#include <cmocka.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <linux/xattr.h>

#include "common.h"

struct test_state {
	char *temp_dir;
	int fd;
};

static void free_test_state(struct test_state *s)
{
	free(s->temp_dir);

	if (s->fd != -1)
		close(s->fd);

	free(s);
}

static void test_gen_tlv(void **state)
{
	char file_template[] = "/tmp/digest-cache-tools-fileXXXXXX";
	char list_template[] = "/tmp/digest-cache-tools-listXXXXXX";
	char digest_list_filename[NAME_MAX + 1];
	char digest_list_filename_renamed[NAME_MAX + 1];
	char xattr_value[NAME_MAX + 1];
	struct test_state *s = *state;
	char cmd[1024], output[1024], digest[65];
	struct stat st;
	FILE *fp;
	int ret, fd;

	fd = mkstemp(file_template);
	assert_return_code(fd, 0);

	ret = write(fd, "abcd", 4);
	assert_int_equal(ret, 4);

	close(fd);

	snprintf(cmd, sizeof(cmd),
		 "../src/manage_digest_lists -t -i %s -d %s -o gen -f tlv -a sha512",
		 file_template, s->temp_dir);
	assert_int_equal(system(cmd), 0);

	snprintf(digest_list_filename, sizeof(digest_list_filename), "tlv-%s",
		 strrchr(file_template, '/') + 1);

	ret = fstatat(s->fd, digest_list_filename, &st, 0);
	assert_int_equal(ret, 0);

	snprintf(cmd, sizeof(cmd),
		 "../src/manage_digest_lists -t -i %s/%s -o show", s->temp_dir,
		 digest_list_filename);

	fp = popen(cmd, "r");
	assert_non_null(fgets(output, sizeof(output), fp));
	pclose(fp);

	assert_non_null(strstr(output, file_template));

	snprintf(cmd, sizeof(cmd), "sha512sum %s | awk '{print $1}'",
		 file_template);

	fp = popen(cmd, "r");
	assert_non_null(fgets(digest, sizeof(digest), fp));
	pclose(fp);

	assert_non_null(strstr(output, digest));

	fd = mkstemp(list_template);
	assert_return_code(fd, 0);

	ret = write(fd, digest_list_filename, strlen(digest_list_filename) + 1);
	assert_int_equal(ret, strlen(digest_list_filename) + 1);

	close(fd);

	snprintf(cmd, sizeof(cmd),
		 "../src/manage_digest_lists -t -i %s -o add-xattr",
		 s->temp_dir);
	assert_int_equal(system(cmd), 0);

	snprintf(cmd, sizeof(cmd),
		 "../src/manage_digest_lists -t -i %s -d %s -o add-seqnum",
		 list_template, s->temp_dir);
	assert_int_equal(system(cmd), 0);

	snprintf(digest_list_filename_renamed,
		 sizeof(digest_list_filename_renamed), "0-tlv-%s",
		 strrchr(file_template, '/') + 1);

	ret = fstatat(s->fd, digest_list_filename_renamed, &st,
		      AT_SYMLINK_NOFOLLOW);
	assert_return_code(ret, 0);
	assert_int_not_equal(0, S_ISREG(st.st_mode));

	ret = lgetxattr(file_template, TESTING_XATTR, xattr_value,
			sizeof(xattr_value) - 1);
	assert_return_code(ret, 0);
	xattr_value[ret] = '\0';

	assert_string_equal(xattr_value, digest_list_filename_renamed);

	ret = fstatat(s->fd, digest_list_filename, &st, AT_SYMLINK_NOFOLLOW);
	assert_return_code(ret, 0);
	assert_int_not_equal(0, S_ISLNK(st.st_mode));

	snprintf(cmd, sizeof(cmd),
		 "../src/manage_digest_lists -t -i %s -d %s -o rm-seqnum",
		 list_template, s->temp_dir);
	assert_int_equal(system(cmd), 0);

	ret = fstatat(s->fd, digest_list_filename, &st, AT_SYMLINK_NOFOLLOW);
	assert_return_code(ret, 0);
	assert_int_not_equal(0, S_ISREG(st.st_mode));

	ret = lgetxattr(file_template, TESTING_XATTR, xattr_value,
			sizeof(xattr_value) - 1);
	assert_return_code(ret, 0);
	xattr_value[ret] = '\0';

	assert_string_equal(xattr_value, digest_list_filename);

	snprintf(cmd, sizeof(cmd),
		 "../src/manage_digest_lists -t -i %s -d %s -o gen -f tlv -O new_digest_list",
		 file_template, s->temp_dir);
	assert_int_equal(system(cmd), 0);

	fd = openat(s->fd, "tlv-new_digest_list", O_RDONLY);
	assert_int_not_equal(fd, -1);
	close(fd);

	fd = openat(s->fd, list_template, O_WRONLY | O_TRUNC);
	assert_int_not_equal(fd, -1);

	ret = write(fd, s->temp_dir, strlen(s->temp_dir));
	assert_int_equal(ret, strlen(s->temp_dir));

	ret = write(fd, "/tlv-new_digest_list",
		    strlen("/tlv-new_digest_list") + 1);
	assert_int_equal(ret, strlen("/tlv-new_digest_list") + 1);

	close(fd);

	snprintf(cmd, sizeof(cmd),
		 "../src/manage_digest_lists -t -i %s -L -d %s -o gen -f tlv -a sha512 -O gen.c -O new_digest_list2",
		 list_template, s->temp_dir);
	assert_int_equal(system(cmd), 0);

	ret = fstatat(s->fd, "tlv-new_digest_list2", &st, AT_SYMLINK_NOFOLLOW);
	assert_return_code(ret, 0);

	snprintf(cmd, sizeof(cmd),
		 "../src/manage_digest_lists -t -i %s/tlv-new_digest_list2 -o show",
		 s->temp_dir);

	fp = popen(cmd, "r");
	assert_non_null(fgets(output, sizeof(output), fp));
	pclose(fp);

	assert_non_null(strstr(output, "tlv-new_digest_list"));
}


static void test_gen_rpm(void **state)
{
	char list_template[] = "/tmp/digest-cache-tools-listXXXXXX";
	struct test_state *s = *state;
	char cmd[1024], output[2048];
	char *digest = "d4494442be4c8460c461c55d0efa2edae1fdaff94986ee3fb0cd859da3303b76";
	char *test_filename = "fedora-release-identity-workstation-38-34.noarch.rpm";
	char *digest_list_filename = "rpm-fedora-release-identity-workstation-38-34.noarch";
	char *digest_list_filename_seq_num = "0-rpm-fedora-release-identity-workstation-38-34.noarch";
	struct stat st;
	FILE *fp;
	int ret, fd;

	snprintf(cmd, sizeof(cmd),
		 "../src/manage_digest_lists -i %s -d %s -o gen -f rpm",
		 test_filename, s->temp_dir);
	assert_int_equal(system(cmd), 0);

	ret = fstatat(s->fd, digest_list_filename, &st, AT_SYMLINK_NOFOLLOW);
	assert_return_code(ret, 0);

	snprintf(cmd, sizeof(cmd),
		 "../src/manage_digest_lists -t -i %s/%s -o show",
		 s->temp_dir, digest_list_filename);

	fp = popen(cmd, "r");
	assert_non_null(fgets(output, sizeof(output), fp));
	pclose(fp);

	assert_non_null(strstr(output, "fedora-workstation.conf"));

	assert_non_null(strstr(output, digest));

	fd = mkstemp(list_template);
	assert_int_not_equal(fd, -1);

	ret = write(fd, digest_list_filename, strlen(digest_list_filename) + 1);
	assert_int_equal(ret, strlen(digest_list_filename) + 1);

	close(fd);

	snprintf(cmd, sizeof(cmd),
		 "../src/manage_digest_lists -t -i %s -d %s -o add-seqnum",
		 list_template, s->temp_dir);
	assert_int_equal(system(cmd), 0);

	ret = fstatat(s->fd, digest_list_filename_seq_num, &st,
		      AT_SYMLINK_NOFOLLOW);
	assert_return_code(ret, 0);

	snprintf(cmd, sizeof(cmd),
		 "../src/manage_digest_lists -t -i %s -d %s -o rm-seqnum",
		 list_template, s->temp_dir);
	assert_int_equal(system(cmd), 0);

	ret = fstatat(s->fd, digest_list_filename, &st, AT_SYMLINK_NOFOLLOW);
	assert_return_code(ret, 0);
}

static int test_gen_init(void **state)
{
	char template[] = "/tmp/digest-cache-tools-testXXXXXX";
	struct test_state *s;
	char *dir_ptr;

	dir_ptr = mkdtemp(template);
	if (!dir_ptr)
		return -errno;

	s = malloc(sizeof(*s));
	if (!s)
		return -ENOMEM;

	s->fd = -1;
	s->temp_dir = malloc(strlen(dir_ptr) + 1);
	if (!s->temp_dir) {
		free_test_state(s);
		return -ENOMEM;
	}

	strcpy(s->temp_dir, dir_ptr);

	s->fd = open(s->temp_dir, O_RDONLY | O_DIRECTORY);
	if (s->fd == -1) {
		free_test_state(s);
		return -errno;
	}

	*state = s;
	return 0;
}

static int test_gen_cleanup(void **state)
{
	FTS *fts = NULL;
	FTSENT *ftsent;
	int fts_flags = (FTS_PHYSICAL | FTS_COMFOLLOW | FTS_NOCHDIR | FTS_XDEV);
	struct test_state *s = *state;
	char *paths[2] = { s->temp_dir, NULL };

	/* Delete files and directories. */
	fts = fts_open(paths, fts_flags, NULL);
	if (fts) {
		while ((ftsent = fts_read(fts)) != NULL) {
			switch (ftsent->fts_info) {
			case FTS_DP:
				rmdir(ftsent->fts_accpath);
				break;
			case FTS_F:
			case FTS_SL:
			case FTS_SLNONE:
			case FTS_DEFAULT:
				unlink(ftsent->fts_accpath);
				break;
			default:
				break;
			}
		}
	}

	free_test_state(s);
	return 0;
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_gen_tlv),
		cmocka_unit_test(test_gen_rpm),
	};

	return cmocka_run_group_tests(tests, test_gen_init, test_gen_cleanup);
}
