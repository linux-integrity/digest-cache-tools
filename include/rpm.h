/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2017-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Header for rpm digest list generator.
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <rpm/rpmlib.h>
#include <rpm/header.h>
#include <rpm/rpmts.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmtag.h>
#include <rpm/rpmpgp.h>
#include <rpm/rpmmacro.h>

int rpm_gen_filename(Header rpm, char *filename, int filename_len);
int rpm_gen_write_digest_list(Header rpm, int dirfd, char *filename);
