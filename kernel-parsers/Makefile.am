BUILT_SOURCES = rpm.ko

rpm.ko: rpm/rpm.c
	make -C /lib/modules/`uname -r`/build INSTALL_MOD_DIR=kernel/security/integrity/digest_cache/parsers M=$(shell pwd)/rpm

install-exec-hook:
	make -C /lib/modules/`uname -r`/build INSTALL_MOD_DIR=kernel/security/integrity/digest_cache/parsers M=$(shell pwd)/rpm modules_install

clean-local:
	make -C /lib/modules/`uname -r`/build INSTALL_MOD_DIR=kernel/security/integrity/digest_cache/parsers M=$(shell pwd)/rpm clean

uninstall-local:
	rm -f /lib/modules/`uname -r`/kernel/security/integrity/digest_cache/rpm.ko
