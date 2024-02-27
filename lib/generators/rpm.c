// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Generate rpm digest lists.
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <linux/xattr.h>
#include <asm/byteorder.h>

#include "rpm.h"
#include "common.h"
#include "generators.h"

int rpm_gen_filename(Header rpm, char *filename, int filename_len)
{
	char *_filename = headerFormat(rpm, "rpm-%{nvra}", NULL);

	if (!_filename)
		return -ENOMEM;

	snprintf(filename, filename_len, "%s", _filename);
	free(_filename);
	return 0;
}

static int write_rpm_header(Header rpm, int dirfd, char *filename)
{
	rpmtd immutable;
	ssize_t ret;
	int fd;

	fd = openat(dirfd, filename, O_WRONLY, 0644);
	if (fd != -1) {
		printf("File %s exists\n", filename);
		close(fd);
		return -EEXIST;
	}

	fd = openat(dirfd, filename, O_WRONLY | O_CREAT, 0644);
	if (fd < 0)
		return -EACCES;

	ret = _write(fd, (void *)rpm_header_magic, sizeof(rpm_header_magic));
	if (ret != sizeof(rpm_header_magic)) {
		ret = -EIO;
		goto out;
	}

	immutable = rpmtdNew();
	headerGet(rpm, RPMTAG_HEADERIMMUTABLE, immutable, 0);
	ret = _write(fd, immutable->data, immutable->count);
	if (ret != immutable->count)
		ret = -EIO;

	rpmtdFree(immutable);
out:
	close(fd);

	if (ret < 0)
		unlinkat(dirfd, filename, 0);

	return ret;
}

static int write_rpm_header_signature(Header rpm, int dirfd, char *filename)
{
	struct module_signature modsig = { 0 };
	rpmtd signature = rpmtdNew();
	int ret, fd;

	headerGet(rpm, RPMTAG_RSAHEADER, signature, 0);
	if (!signature->count) {
		printf("Warning: no RPM signature for %s\n", filename);
		ret = 0;
		goto out_get;
	}

	fd = openat(dirfd, filename, O_WRONLY | O_APPEND);
	if (fd < 0) {
		ret = -errno;
		goto out_get;
	}

	ret = _write(fd, signature->data, signature->count);
	if (ret != (int)signature->count)
		goto out_get;

	modsig.id_type = PKEY_ID_PGP;
	modsig.sig_len = signature->count;
	modsig.sig_len = __cpu_to_be32(modsig.sig_len);

	ret = _write(fd, (__u8 *)&modsig, sizeof(modsig));
	if (ret != sizeof(modsig))
		goto out_fd;

	ret = _write(fd, (__u8 *)MODULE_SIG_STRING,
		     sizeof(MODULE_SIG_STRING) - 1);
	if (ret != sizeof(MODULE_SIG_STRING) - 1)
		goto out_fd;

	ret = 0;
out_fd:
	close(fd);

	if (ret < 0)
		unlinkat(dirfd, filename, 0);
out_get:
	rpmtdFree(signature);
	return ret;
}

int rpm_gen_write_digest_list(Header rpm, int dirfd, char *filename)
{
	int ret;

	ret = write_rpm_header(rpm, dirfd, filename);
	if (ret < 0) {
		printf("Cannot dump RPM header of %s\n", filename);
		return ret;
	}

	ret = write_rpm_header_signature(rpm, dirfd, filename);
	if (ret < 0)
		printf("Cannot add signature to %s\n", filename);

	return ret;
}

int rpm_list_gen_add(int dirfd, void *ptr __unused, char *input)
{
	char filename[NAME_MAX + 1], *selection;
	rpmts ts = NULL;
	Header hdr;
	FD_t fd;
	rpmdbMatchIterator mi;
	rpmVSFlags vsflags = 0;
	int ret;

	ts = rpmtsCreate();
	if (!ts) {
		rpmlog(RPMLOG_NOTICE, "rpmtsCreate() error\n");
		ret = -EACCES;
		goto out;
	}

	ret = rpmReadConfigFiles(NULL, NULL);
	if (ret != RPMRC_OK) {
		rpmlog(RPMLOG_NOTICE, "Unable to read RPM configuration\n");
		ret = -EACCES;
		goto out_ts;
	}

	if (strncmp(input, "rpmdb", 5)) {
		vsflags |= _RPMVSF_NODIGESTS;
		vsflags |= _RPMVSF_NOSIGNATURES;
		rpmtsSetVSFlags(ts, vsflags);

		fd = Fopen(input, "r.ufdio");
		if (!fd || Ferror(fd)) {
			rpmlog(RPMLOG_NOTICE,
			       "Failed to open package file %s, %s\n", input,
			       Fstrerror(fd));
			ret = -EACCES;
			goto out_rpm;
		}

		ret = rpmReadPackageFile(ts, fd, "rpm", &hdr);
		Fclose(fd);

		if (ret != RPMRC_OK) {
			rpmlog(RPMLOG_NOTICE,
			       "Could not read package file %s\n", input);
			goto out_rpm;
		}

		ret = rpm_gen_filename(hdr, filename, sizeof(filename));
		if (ret < 0) {
			rpmlog(RPMLOG_NOTICE,
			       "Could not generate digest list file name\n");
			headerFree(hdr);
			goto out_rpm;
		}

		ret = rpm_gen_write_digest_list(hdr, dirfd, filename);
		if (ret < 0) {
			rpmlog(RPMLOG_NOTICE,
			       "Could not generate digest list %s\n", filename);
			headerFree(hdr);
			goto out_rpm;
		}

		headerFree(hdr);
		goto out_rpm;
	}

	mi = rpmtsInitIterator(ts, RPMDBI_PACKAGES, NULL, 0);
	while ((hdr = rpmdbNextIterator(mi)) != NULL) {
		ret = rpm_gen_filename(hdr, filename, sizeof(filename));
		if (ret < 0) {
			rpmlog(RPMLOG_NOTICE,
			       "Could not generate digest list file name\n");
			continue;
		}

		if (strstr(filename, "gpg-pubkey"))
			continue;

		selection = strchr(input, ':');
		if (selection && !strstr(filename + 4, selection + 1))
			continue;

		ret = rpm_gen_write_digest_list(hdr, dirfd, filename);
		if (ret < 0)
			rpmlog(RPMLOG_NOTICE,
			       "Could not generate digest list %s\n", filename);
	}

	rpmdbFreeIterator(mi);
out_rpm:
	rpmFreeRpmrc();
	rpmFreeCrypto();
	rpmFreeMacros(NULL);
out_ts:
	rpmtsFree(ts);
out:
	return ret;
}
