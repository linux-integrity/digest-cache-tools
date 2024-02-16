// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Plugin to create/remove digest lists and label files.
 */

#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <stdbool.h>
#include <sys/xattr.h>
#include <sys/stat.h>
#include <linux/xattr.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmts.h>
#include <rpm/header.h>
#include <rpm/rpmpgp.h>
#include <rpm/rpmfileutil.h>

#include "rpmplugin.h"

#include "common.h"
#include "rpm.h"
#include "parsers.h"

#define DIGEST_LIST_PATH "/etc/digest_lists"
#define DIGEST_LIST_ADD 0
#define DIGEST_LIST_DEL 1

char digest_list_filename[NAME_MAX + 1];
int dir_fd = -1, digest_list_filename_len;

static rpmRC digest_cache_init(rpmPlugin plugin __unused, rpmts ts __unused)
{
	char *digest_list_path = DIGEST_LIST_PATH;
	char *custom_digest_list_path = rpmExpand("%{?_digest_list_path}", NULL);
	struct stat st;
	int ret;

	if (custom_digest_list_path && custom_digest_list_path[0] != '\0')
		digest_list_path = custom_digest_list_path;

	if (stat(digest_list_path, &st) == -1) {
		ret = mkdir(digest_list_path, 0775);
		if (ret < 0) {
			rpmlog(RPMLOG_WARNING,
			       "digest_cache: cannot create directory %s\n",
			       digest_list_path);
			goto out;
		}
	}

	dir_fd = open(digest_list_path, O_RDONLY | O_DIRECTORY);
out:
	free(custom_digest_list_path);
	return RPMRC_OK;
}

static void digest_cache_cleanup(rpmPlugin plugin __unused)
{
	if (dir_fd != -1)
		close(dir_fd);
}

static int process_digest_list(rpmte te, enum ops op)
{
	char digest_list_filename_link[NAME_MAX + 1];
	bool digest_list_exists = false;
	int ret, fd;

	ret = rpm_gen_filename(rpmteHeader(te), digest_list_filename,
			       sizeof(digest_list_filename));
	if (ret < 0) {
		rpmlog(RPMLOG_WARNING,
		       "digest_cache: could not generate digest list file name\n");
		return RPMRC_OK;
	}

	fd = openat(dir_fd, digest_list_filename, O_RDONLY);
	digest_list_exists = (fd != -1);
	close(fd);

	/* The rpm digest list has been already processed. */
	if ((op == DIGEST_LIST_ADD && digest_list_exists) ||
	    (op == DIGEST_LIST_DEL && !digest_list_exists))
		return RPMRC_OK;

	if (op == DIGEST_LIST_ADD) {
		ret = rpm_gen_write_digest_list(rpmteHeader(te), dir_fd,
						digest_list_filename);
		if (ret < 0)
			rpmlog(RPMLOG_WARNING,
			       "digest_cache: could not generate digest list %s\n",
			       digest_list_filename);
		else
			digest_list_filename_len = strlen(digest_list_filename);

		return RPMRC_OK;
	}

	ret = readlinkat(dir_fd, digest_list_filename,
			 digest_list_filename_link,
			 sizeof(digest_list_filename_link) - 1);
	if (ret > 0) {
		digest_list_filename_link[ret] = '\0';

		ret = unlinkat(dir_fd, digest_list_filename_link, 0);
		if (ret < 0)
			rpmlog(RPMLOG_WARNING,
			       "digest_cache: could not unlink %s\n",
			       digest_list_filename_link);
	}

	ret = unlinkat(dir_fd, digest_list_filename, 0);
	if (ret < 0)
		rpmlog(RPMLOG_WARNING, "digest_cache: could not unlink %s\n",
		       digest_list_filename);

	return RPMRC_OK;
}

static rpmRC digest_cache_psm_pre(rpmPlugin plugin __unused, rpmte te)
{
	if (rpmteType(te) != TR_ADDED || dir_fd == -1)
		return RPMRC_OK;

	return process_digest_list(te, DIGEST_LIST_ADD);
}

static rpmRC digest_cache_psm_post(rpmPlugin plugin __unused, rpmte te,
				   int res  __unused)
{
	if (rpmteType(te) != TR_REMOVED || dir_fd == -1)
		return RPMRC_OK;

	return process_digest_list(te, DIGEST_LIST_DEL);
}

static rpmRC digest_cache_file_prepare(rpmPlugin plugin __unused,
				       rpmfi fi  __unused,
				       int fd, const char *path,
				       const char *dest __unused,
				       mode_t file_mode __unused,
				       rpmFsmOp op)
{
	rpmFileAction action = XFO_ACTION(op);
	int ret;

	/* Ignore skipped files and unowned directories */
	if (XFA_SKIPPING(action) || (op & FAF_UNOWNED))
		return RPMRC_OK;

	/* Ignore ghost files. */
	if (rpmfiFFlags(fi) & RPMFILE_GHOST)
		return RPMRC_OK;

	if (fd >= 0)
		ret = fsetxattr(fd, XATTR_NAME_DIGEST_LIST,
				digest_list_filename,
				digest_list_filename_len + 1, 0);
	else
		ret = lsetxattr(path, XATTR_NAME_DIGEST_LIST,
				digest_list_filename,
				digest_list_filename_len + 1, 0);

	if (ret == -EOPNOTSUPP)
		ret = 0;

	if (ret < 0)
		rpmlog(RPMLOG_WARNING, "digest_cache: could not set %s xattr to  %s\n",
		       XATTR_NAME_DIGEST_LIST, path);

	return RPMRC_OK;
}

struct rpmPluginHooks_s digest_cache_hooks = {
	.init = digest_cache_init,
	.cleanup = digest_cache_cleanup,
	.psm_pre = digest_cache_psm_pre,
	.psm_post = digest_cache_psm_post,
	.fsm_file_prepare = digest_cache_file_prepare,
};
