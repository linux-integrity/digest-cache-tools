dist_pkgdata_DATA = manage_digest_lists.txt

man1_MANS = manage_digest_lists.1

%.1: %.txt
	a2x --doctype manpage --format manpage $^
