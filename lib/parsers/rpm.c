// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Parse rpm digest lists.
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <libgen.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <rpm/rpmlib.h>
#include <rpm/header.h>
#include <rpm/rpmts.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmtag.h>
#include <rpm/rpmpgp.h>
#include <rpm/rpmmacro.h>
#include <asm/byteorder.h>
#include <linux/xattr.h>

#include "common.h"
#include "parsers.h"

static const enum hash_algo pgp_hash_algorithms[PGPHASHALGO_SHA224 + 1] = {
	[PGPHASHALGO_MD5]		= HASH_ALGO_MD5,
	[PGPHASHALGO_SHA1]		= HASH_ALGO_SHA1,
	[PGPHASHALGO_RIPEMD160]		= HASH_ALGO_RIPE_MD_160,
	[PGPHASHALGO_SHA256]		= HASH_ALGO_SHA256,
	[PGPHASHALGO_SHA384]		= HASH_ALGO_SHA384,
	[PGPHASHALGO_SHA512]		= HASH_ALGO_SHA512,
	[PGPHASHALGO_SHA224]		= HASH_ALGO_SHA224,
};

int rpm_list_parse(const char *digest_list_path, __u8 *data __unused,
		   size_t data_len __unused, enum ops op)
{
	rpmtd filedigestalgo, filedigests, basenames, dirnames, dirindexes;
	rpmtd filesflags;
	rpmts ts = NULL;
	Header hdr;
	FD_t fd;
	rpmVSFlags vsflags = 0;
	char file_path[PATH_MAX];
	enum hash_algo algo = HASH_ALGO_MD5;
	const char *digest_str, *basename, *dirname;
	__u32 dirindex, fileflags, *pgp_algo_ptr;
	char *digest_list_filename = strrchr(digest_list_path, '/') + 1;
	int digest_list_filename_len = strlen(digest_list_filename);
	int ret;

	ts = rpmtsCreate();
	if (!ts) {
		rpmlog(RPMLOG_NOTICE, "rpmtsCreate() error..\n");
		ret = -EACCES;
		goto out;
	}

	ret = rpmReadConfigFiles(NULL, NULL);
	if (ret != RPMRC_OK) {
		rpmlog(RPMLOG_NOTICE, "Unable to read RPM configuration.\n");
		ret = -EACCES;
		goto out_ts;
	}

	vsflags |= _RPMVSF_NODIGESTS;
	vsflags |= _RPMVSF_NOSIGNATURES;
	rpmtsSetVSFlags(ts, vsflags);

	fd = Fopen(digest_list_path, "r.ufdio");
	if (!fd || Ferror(fd)) {
		rpmlog(RPMLOG_NOTICE, "Failed to open package file %s, %s\n",
		       digest_list_path, Fstrerror(fd));
		ret = -EACCES;
		goto out_rpm;
	}

	ret = rpmReadHeader(ts, fd, &hdr, NULL);
	Fclose(fd);

	if (ret != RPMRC_OK) {
		rpmlog(RPMLOG_NOTICE, "Could not read package file %s\n",
		       digest_list_path);
		goto out_rpm;
	}

	filedigestalgo = rpmtdNew();
	filedigests = rpmtdNew();
	basenames = rpmtdNew();
	dirnames = rpmtdNew();
	dirindexes = rpmtdNew();
	filesflags = rpmtdNew();

	headerGet(hdr, RPMTAG_FILEDIGESTALGO, filedigestalgo, 0);
	headerGet(hdr, RPMTAG_FILEDIGESTS, filedigests, 0);
	headerGet(hdr, RPMTAG_BASENAMES, basenames, 0);
	headerGet(hdr, RPMTAG_DIRNAMES, dirnames, 0);
	headerGet(hdr, RPMTAG_DIRINDEXES, dirindexes, 0);
	headerGet(hdr, RPMTAG_FILEFLAGS, filesflags, 0);

	pgp_algo_ptr = rpmtdGetUint32(filedigestalgo);
	if (pgp_algo_ptr && *pgp_algo_ptr <= PGPHASHALGO_SHA224)
		algo = pgp_hash_algorithms[*pgp_algo_ptr];

	while ((digest_str = rpmtdNextString(filedigests))) {
		basename = rpmtdNextString(basenames);
		dirindex = *rpmtdNextUint32(dirindexes);
		fileflags = *rpmtdNextUint32(filesflags);

		if (fileflags & RPMFILE_GHOST)
			continue;

		rpmtdSetIndex(dirnames, dirindex);
		dirname = rpmtdGetString(dirnames);

		snprintf(file_path, sizeof(file_path), "%s%s", dirname,
			 basename);

		if (!strlen(digest_str))
			continue;

		switch (op) {
		case OP_SHOW:
			printf("%s:%s %s\n", hash_algo_name[algo], digest_str,
			       file_path);
			ret = 0;
			break;
		case OP_UPDATE_XATTR:
			ret = lgetxattr(file_path, digest_list_xattr_name(),
					NULL, 0);
			if (ret <= 0) {
				ret = 0;
				break;
			}
			__attribute__ ((fallthrough));
		case OP_ADD_XATTR:
			ret = lsetxattr(file_path, digest_list_xattr_name(),
					digest_list_filename,
					digest_list_filename_len, 0);
			if (ret < 0)
				printf("Error setting %s on %s, %s\n",
				       digest_list_xattr_name(), file_path,
				       strerror(errno));
			ret = 0;
			break;
		case OP_RM_XATTR:
			ret = lremovexattr(file_path, digest_list_xattr_name());
			if (ret < 0 && errno != ENODATA)
				printf("Error removing %s from %s, %s\n",
				       digest_list_xattr_name(), file_path,
				       strerror(errno));
			ret = 0;
			break;
		default:
			ret = -EOPNOTSUPP;
			break;
		}

		if (ret < 0)
			break;
	}

	rpmtdFree(filedigestalgo);
	rpmtdFree(filedigests);
	rpmtdFree(basenames);
	rpmtdFree(dirnames);
	rpmtdFree(dirindexes);
	rpmtdFree(filesflags);
	headerFree(hdr);
out_rpm:
	rpmFreeRpmrc();
	rpmFreeCrypto();
	rpmFreeMacros(NULL);
out_ts:
	rpmtsFree(ts);
out:
	return ret;
}
