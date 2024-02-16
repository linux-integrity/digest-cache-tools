dist_pkgdata_DATA = manage_digest_lists.txt ../README.md

man1_MANS = manage_digest_lists.1 digest-cache-tools.1

digest-cache-tools.1: ../README.md
	ronn --manual digest-cache-tools --roff $^ --pipe > $@

%.1: %.txt
	a2x --doctype manpage --format manpage $^
