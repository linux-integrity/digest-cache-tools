/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2005,2006,2007,2008 IBM Corporation
 * Copyright (C) 2017-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Header of common.c
 */

#ifndef _COMMON_H
#define _COMMON_H
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <linux/hash_info.h>

#define MD5_DIGEST_SIZE 16
#define SHA1_DIGEST_SIZE 20
#define RMD160_DIGEST_SIZE 20
#define SHA256_DIGEST_SIZE 32
#define SHA384_DIGEST_SIZE 48
#define SHA512_DIGEST_SIZE 64
#define SHA224_DIGEST_SIZE 28
#define RMD128_DIGEST_SIZE 16
#define RMD256_DIGEST_SIZE 32
#define RMD320_DIGEST_SIZE 40
#define WP256_DIGEST_SIZE 32
#define WP384_DIGEST_SIZE 48
#define WP512_DIGEST_SIZE 64
#define TGR128_DIGEST_SIZE 16
#define TGR160_DIGEST_SIZE 20
#define TGR192_DIGEST_SIZE 24
#define SM3256_DIGEST_SIZE 32
#define STREEBOG256_DIGEST_SIZE 32
#define STREEBOG512_DIGEST_SIZE 64

#define ARRAY_SIZE(x) (int)(sizeof(x) / sizeof(*(x)))

#define DIGEST_LIST_SIZE_MAX (64 * 1024 * 1024 - 1)

#define TESTING_XATTR "user.digest_list"

/* In stripped ARM and x86-64 modules, ~ is surprisingly rare. */
#define MODULE_SIG_STRING "~Module signature appended~\n"

enum pkey_id_type {
	PKEY_ID_PGP,		/* OpenPGP generated key ID */
	PKEY_ID_X509,		/* X.509 arbitrary subjectKeyIdentifier */
	PKEY_ID_PKCS7,		/* Signature in PKCS#7 message */
};

/*
 * Module signature information block.
 *
 * The constituents of the signature section are, in order:
 *
 *	- Signer's name
 *	- Key identifier
 *	- Signature data
 *	- Information block
 */
struct module_signature {
	__u8	algo;		/* Public-key crypto algorithm [0] */
	__u8	hash;		/* Digest algorithm [0] */
	__u8	id_type;	/* Key identifier type [PKEY_ID_PKCS7] */
	__u8	signer_len;	/* Length of signer's name [0] */
	__u8	key_id_len;	/* Length of key identifier [0] */
	__u8	__pad[3];
	__be32	sig_len;	/* Length of signature data */
};

enum ops { OP_GEN, OP_SHOW, OP_ADD_XATTR, OP_RM_XATTR, OP_UPDATE_XATTR,
	   OP_ADD_SEQNUM, OP_RM_SEQNUM, OP__LAST };

struct generator {
	const char *name;
	void *(*new)(int dirfd, char *input, char *output, enum hash_algo algo);
	int (*add)(int dirfd, void *ptr, char *input);
	void (*close)(void *ptr);
};

struct parser {
	const char *name;
	int (*parse)(const char *digest_list_path, __u8 *data, size_t data_len,
		     enum ops op);
};

extern const char *ops_str[OP__LAST];
extern const char *const hash_algo_name[HASH_ALGO__LAST];
extern const int hash_digest_size[HASH_ALGO__LAST];
extern bool testing;

int read_file(const char *path, size_t *len, unsigned char **data);
int calc_digest(__u8 *digest, void *data, __u64 len, enum hash_algo algo);
int calc_file_digest(__u8 *digest, const char *path, enum hash_algo algo);
ssize_t _write(int fd, __u8 *buf, size_t buf_len);
size_t strip_modsig(__u8 *data, size_t data_len);
const char *digest_list_xattr_name(void);

#endif /* _COMMON_H */
