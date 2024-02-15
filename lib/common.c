// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2005,2006,2007,2008 IBM Corporation
 * Copyright (C) 2017-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Common functions and data.
 */

#include <sys/mman.h>
#include <sys/random.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include <malloc.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <linux/xattr.h>
#include <linux/hash_info.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <asm/byteorder.h>

#include "common.h"

bool testing;

const char *const hash_algo_name[HASH_ALGO__LAST] = {
	[HASH_ALGO_MD4]		= "md4",
	[HASH_ALGO_MD5]		= "md5",
	[HASH_ALGO_SHA1]	= "sha1",
	[HASH_ALGO_RIPE_MD_160]	= "rmd160",
	[HASH_ALGO_SHA256]	= "sha256",
	[HASH_ALGO_SHA384]	= "sha384",
	[HASH_ALGO_SHA512]	= "sha512",
	[HASH_ALGO_SHA224]	= "sha224",
	[HASH_ALGO_RIPE_MD_128]	= "rmd128",
	[HASH_ALGO_RIPE_MD_256]	= "rmd256",
	[HASH_ALGO_RIPE_MD_320]	= "rmd320",
	[HASH_ALGO_WP_256]	= "wp256",
	[HASH_ALGO_WP_384]	= "wp384",
	[HASH_ALGO_WP_512]	= "wp512",
	[HASH_ALGO_TGR_128]	= "tgr128",
	[HASH_ALGO_TGR_160]	= "tgr160",
	[HASH_ALGO_TGR_192]	= "tgr192",
	[HASH_ALGO_SM3_256]	= "sm3",
	[HASH_ALGO_STREEBOG_256] = "streebog256",
	[HASH_ALGO_STREEBOG_512] = "streebog512",
};

const int hash_digest_size[HASH_ALGO__LAST] = {
	[HASH_ALGO_MD4]		= MD5_DIGEST_SIZE,
	[HASH_ALGO_MD5]		= MD5_DIGEST_SIZE,
	[HASH_ALGO_SHA1]	= SHA1_DIGEST_SIZE,
	[HASH_ALGO_RIPE_MD_160]	= RMD160_DIGEST_SIZE,
	[HASH_ALGO_SHA256]	= SHA256_DIGEST_SIZE,
	[HASH_ALGO_SHA384]	= SHA384_DIGEST_SIZE,
	[HASH_ALGO_SHA512]	= SHA512_DIGEST_SIZE,
	[HASH_ALGO_SHA224]	= SHA224_DIGEST_SIZE,
	[HASH_ALGO_RIPE_MD_128]	= RMD128_DIGEST_SIZE,
	[HASH_ALGO_RIPE_MD_256]	= RMD256_DIGEST_SIZE,
	[HASH_ALGO_RIPE_MD_320]	= RMD320_DIGEST_SIZE,
	[HASH_ALGO_WP_256]	= WP256_DIGEST_SIZE,
	[HASH_ALGO_WP_384]	= WP384_DIGEST_SIZE,
	[HASH_ALGO_WP_512]	= WP512_DIGEST_SIZE,
	[HASH_ALGO_TGR_128]	= TGR128_DIGEST_SIZE,
	[HASH_ALGO_TGR_160]	= TGR160_DIGEST_SIZE,
	[HASH_ALGO_TGR_192]	= TGR192_DIGEST_SIZE,
	[HASH_ALGO_SM3_256]	= SM3256_DIGEST_SIZE,
	[HASH_ALGO_STREEBOG_256] = STREEBOG256_DIGEST_SIZE,
	[HASH_ALGO_STREEBOG_512] = STREEBOG512_DIGEST_SIZE,
};

int read_file(const char *path, size_t *len, unsigned char **data)
{
	struct stat st;
	int rc = 0, fd;

	if (stat(path, &st) == -1)
		return -errno;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;

	*len = st.st_size;
	if (!*len)
		goto out;

	*data = mmap(NULL, *len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (*data == MAP_FAILED)
		rc = -ENOMEM;
out:
	close(fd);
	return rc;
}

int calc_digest(__u8 *digest, void *data, __u64 len, enum hash_algo algo)
{
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	int ret = -EINVAL;

	OpenSSL_add_all_algorithms();

	md = EVP_get_digestbyname(hash_algo_name[algo]);
	if (!md)
		goto out;

	mdctx = EVP_MD_CTX_create();
	if (!mdctx)
		goto out;

	if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
		goto out_mdctx;

	if (len && EVP_DigestUpdate(mdctx, data, len) != 1)
		goto out_mdctx;

	if (EVP_DigestFinal_ex(mdctx, digest, NULL) != 1)
		goto out_mdctx;

	ret = 0;
out_mdctx:
	EVP_MD_CTX_destroy(mdctx);
out:
	EVP_cleanup();
	return ret;
}

int calc_file_digest(__u8 *digest, const char *path, enum hash_algo algo)
{
	unsigned char *data;
	size_t len;
	int ret;

	ret = read_file(path, &len, &data);
	if (ret < 0)
		return ret;

	ret = calc_digest(digest, data, len, algo);

	munmap(data, len);
	return ret;
}

ssize_t _write(int fd, __u8 *buf, size_t buf_len)
{
	ssize_t len;
	size_t offset = 0;

	while (offset < buf_len) {
		len = write(fd, buf + offset, buf_len - offset);
		if (len < 0)
			return -errno;

		offset += len;
	}

	return buf_len;
}

/* Same as security/digest_cache/modsig.c */
size_t strip_modsig(__u8 *data, size_t data_len)
{
	const size_t marker_len = strlen(MODULE_SIG_STRING);
	const struct module_signature *sig;
	size_t parsed_data_len = data_len;
	size_t sig_len;
	const __u8 *p;

	/* From ima_modsig.c */
	if (data_len <= marker_len + sizeof(*sig))
		return data_len;

	p = data + parsed_data_len - marker_len;
	if (memcmp(p, MODULE_SIG_STRING, marker_len))
		return data_len;

	parsed_data_len -= marker_len;
	sig = (const struct module_signature *)(p - sizeof(*sig));

	/* From module_signature.c */
	if (__be32_to_cpu(sig->sig_len) >= parsed_data_len - sizeof(*sig))
		return data_len;

	/* Unlike for module signatures, accept all signature types. */
	if (sig->algo != 0 ||
	    sig->hash != 0 ||
	    sig->signer_len != 0 ||
	    sig->key_id_len != 0 ||
	    sig->__pad[0] != 0 ||
	    sig->__pad[1] != 0 ||
	    sig->__pad[2] != 0) {
		printf("Signature info has unexpected non-zero params\n");
		return data_len;
	}

	sig_len = __be32_to_cpu(sig->sig_len);
	parsed_data_len -= sig_len + sizeof(*sig);
	return parsed_data_len;
}

const char *digest_list_xattr_name(void)
{
	if (testing)
		return TESTING_XATTR;

	return XATTR_NAME_DIGEST_LIST;
}
