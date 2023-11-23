
EXTRA_DIST = strongswan-dataplane.service.in
CLEANFILES = strongswan-dataplane.service

systemdsystemunit_DATA = strongswan-dataplane.service

strongswan-dataplane.service : strongswan-dataplane.service.in
	$(AM_V_GEN) \
	sed \
	-e "s:@SBINDIR@:$(sbindir):g" \
	$(srcdir)/$@.in > $@
