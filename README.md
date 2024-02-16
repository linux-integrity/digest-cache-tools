# digest-cache-tools

## Introduction

digest-cache-tools is the companion software of the recently developed
digest_cache LSM.

The digest_cache LSM is a new LSM that collects digests from various sources
(called digest lists), and stores them on demand in kernel memory, in a set of
hash tables forming a digest cache. Extracted digests can be used as reference
values for integrity verification of file content or metadata.

The digest_cache LSM helps IMA to extend a PCR in a deterministic way. IMA
measures the list of digests coming from the distribution (e.g. RPM package
headers), and subsequently measures a file if it is not found in that list.

The digest_cache LSM also helps IMA for appraisal. IMA can simply lookup in the
list of digests extracted from package headers, once the signature of those
headers has been verified.


## Content

digest-cache-tools includes the following software:

- ```manage_digest_lists```: a tool to generate/manage digest lists
- ```digest_cache.so```: a rpm plugin to generate/delete digest lists when
  software is installed/removed through rpm

## Supported Digest List Formats

The digest_cache LSM supports two formats:

- ```tlv```: a TLV-based format that can be extended later with more fields;
- ```rpm```: RPM package headers (RPMTAG_IMMUTABLE)

Digest lists can have a module-style appended signature in PKCS#7 format,
or PGP (for the 'rpm' digest list, extracted from RPMTAG_RSAHEADER). PGP is
currently not supported by the kernel, and requires additional patches.


## Install

### From Source

```
$ autoreconf -fvi
$ ./configure <options>
$ make
$ sudo make install
```

### From Packages

Built packages for openSUSE Tumbleweed can be found
[here](https://download.opensuse.org/repositories/home:/roberto.sassu:/digest_cache/openSUSE_Tumbleweed/).

After adding the new repository, install the packages by executing:

```
# zypper in kernel-default digest-cache-tools dracut
```

This command needs to be executed again, since zypper requires to specify the
exact version of the software to be installed.


## Configuration


### 1. Generate digest lists from the RPM database

The first step is to generate a digest list for each installed package, so that
existing software is recognized by the digest_cache LSM.

```
manage_digest_lists -o gen -d /etc/digest_lists -i rpmdb -f rpm
```

### 2. Generate more digest lists (optional)

An installed system might have additional software installed, or modified files
(e.g. configuration files). If they are measured/appraised with IMA, it is
necessary to put their digest in a digest list.

#### From a file or a list

```
manage_digest_lists -o gen -i <input file> -d /etc/digest_lists -f tlv
```

Alternatively:
```
manage_digest_lists -o gen -i <list> -L -d /etc/digest_lists -f tlv
```

#### From an RPM package in a file or RPM database

To create a digest list from an RPM package, it is sufficient to execute:
```
manage_digest_lists -o gen -i <RPM pkg> -d /etc/digest_lists -f rpm
```

To create a digest list from the RPM DB, but for a specific package, it is
sufficient to execute:
```
manage_digest_lists -o gen -i rpmdb:<RPM pkg> -d /etc/digest_lists -f rpm
```


### 3. Sign digest lists (optional)

Digest lists need to be signed, if they are used for IMA appraisal.

#### RPMs

If RPMs are signed, the module-style signature is automatically appended at the
end of the file by manage_digest_lists.

If RPMs are not signed, it is necessary to sign them first with own GPG key, and
the public part must be installed to the kernel (more details later).

#### Custom digest lists

It is possible to append a PKCS#7 signature, by using the sign-file tool from
the Linux kernel sources (the same used to sign kernel modules):

```
scripts/sign-file sha256 certs/signing_key.pem certs/signing_key.pem <digest list path>
```


### 4. Adding signing key to kernel keyring (optional)

#### PGP

On own kernel, it is possible to embed any PGP key in the kernel image. The
built openSUSE kernel has only the official PGP signing keys.

##### From a file

```
gpg --dearmor <PGP key file> >> certs/pubring.gpg
```
The certs/ directory is in the kernel sources.

##### From own GPG keyring

```
gpg --export=minimal <key ID> >> certs/pubring.gpg
```

##### From MOK database

Currently not supported (mokutil expects a DER-encoded certificate).

##### From firmware

To be verified.

#### X.509 certificates

##### From kernel configuration

X.509 certificates can be added through the kernel configuration menu
(CONFIG_SYSTEM_TRUSTED_KEYS option).

##### From MOK database

New keys can be enrolled through mokutil --import. Cannot be used by IMA in the
openSUSE kernel.

##### From firmware

To be verified.


### 5. Configure IMA policy

#### 5a. New policy (examples)

The policies below should be written to /etc/ima/ima-policy, and will be
automatically loaded by systemd at boot time.

Measurement:

```
measure func=DIGEST_LIST_CHECK template=ima-modsig pcr=12
# Temporarily excluded as memfd is not properly handled.
dont_measure fsmagic=0x01021994
measure func=BPRM_CHECK digest_cache=content pcr=12
measure func=MMAP_CHECK digest_cache=content pcr=12
measure func=MODULE_CHECK digest_cache=content pcr=12
```

Appraisal:

```
appraise func=DIGEST_LIST_CHECK appraise_type=imasig|modsig
# Temporarily excluded as memfd is not properly handled.
dont_appraise fsmagic=0x01021994
appraise func=BPRM_CHECK digest_cache=content
appraise func=MMAP_CHECK digest_cache=content
appraise func=MODULE_CHECK digest_cache=content
```

#### 5b. Existing policy

It is necessary to append the following rules, to ensure that digest lists are
measured/appraised.

For measurement:

```
measure func=DIGEST_LIST_CHECK pcr=12
```

For appraisal:

```
appraise func=DIGEST_LIST_CHECK appraise_type=imasig|modsig
```

In addition, it is necessary to add:

```
digest_cache=content pcr=12
```

to the measurement rules for which the digest_cache LSM should be used, and:

```
digest_cache=content
```

to the appraisal rules.

### 6. Label files

After all digest lists have been generated, it is necessary to label all files
included in those digest lists.

```
manage_digest_lists -i /etc/digest_lists -o add-xattr
```

### 7. Reboot with digest caches

The previous steps are sufficient to boot a system and measure/appraise files
with the digest lists since systemd is executed from the disk (not the initial
ram disk).

If the measurement policy was selected, it is possible to verify that IMA used
the digest_cache LSM, by looking at the IMA measurement list.

```
cat /sys/kernel/security/ima/ascii_runtime_measurements
```

It should contain only digest lists. If there are additional files (other than
boot_aggregate), those files need to be added to a digest list (steps 2-4).

If the appraisal policy was selected, the system might not boot at all or some
services suddenly fail (due to files not found in the digest lists). In that
case, it is necessary to reboot the system and add the following option to the
kernel command line:

```
ima_appraise=log
```

In the openSUSE kernel, this option is disabled. Alternatively, it should be
possible to boot another kernel with the rd.break=pre-pivot in the kernel
command line. After remounting read-write /sysroot, it should be possible to
rename /etc/ima/ima-policy, so that it is not automatically loaded by systemd
at boot.

### 8. Enable prefetching to make PCR predictable (optional)

The steps above are not yet sufficient to make the PCR predictable. This can be
achieved by setting the security.dig_prefetch xattr.

```
setfattr -n security.dig_prefetch -v 1 /etc/digest_lists
```

The only problem of the prefetching mechanism is that it can degrade the
performance, since it sequentially searches digest lists in a directory, until
it finds the desired one.

Performance can be improved by ordering digest lists in a directory by their
appearance in the IMA measurement list. This steps requires that the system was
booted with the measurement policy.

```
manage_digest_lists -i /sys/kernel/security/ima/ascii_runtime_measurements -d /etc/digest_lists -o add-seqnum
```

### 9. Reboot with digest caches (optional)

Since the prefetching mechanism was enabled, one should get the same PCR value
just after logging in the system (after executing more binaries, the PCR changes
again).

```
cat /sys/devices/LNXSYSTM:00/LNXSYBUS:00/MSFT0101:00/tpm/tpm0/pcr-sha256/12
```

The PCR path might be different in another system.

### 10. Enable IMA at boot time

The previous policies are loaded by systemd only when the real filesystem has
been mounted. Anything that happens before that in the initial ram disk is not
considered.

To ensure that any file access is evaluated, IMA must be activated from the
kernel command line by adding policy keywords (separated by |) to the
ima_policy= option.

For measurement:

```
tcb|digest_cache_measure
```

For appraisal:

```
appraise_tcb|digest_cache_appraise
```

The secure_boot policy cannot be included yet, due to a bug (to be fixed).

### 11. Copy IMA policy and digest lists to the initial ram disk

The command to execute is (-i option not necessary with dracut SUSE package,
since it automatically includes needed digest lists):

```
dracut -f -I /etc/ima/ima-policy " -i /etc/digest_lists/ /etc/digest_lists/ --nostrip --kver <your kernel version>
```

The --nostrip option is necessary to avoid that the copied files are different
from the original (due to stripping debugging symbols). Can be automatically
included at every initial ram disk generation by creating a file named
/etc/dracut.conf.d/digest_list.conf with the content:

```
do_strip=no
```

### 12. Reboot with digest caches

In this final reboot, all files have been measured/appraised from the very
beginning of the boot.


### 13. Install additional packages

Additional packages can be installed. The included rpm plugin digest_cache
automatically creates the rpm digest list and sets the digest_list xattr on new
files. Thus, IMA is able to measure/appraise new software with digest lists.


## Author
Written by Roberto Sassu, <roberto.sassu at huawei.com\>.


## Copying
Copyright (C) 2017-2024 Huawei Technologies Duesseldorf GmbH. Free use of this
software is granted under the terms of the GNU Public License 2.0 (GPLv2).
