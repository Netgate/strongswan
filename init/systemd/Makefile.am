
EXTRA_DIST = strongswan.service.in strongswan-dataplane.service.in
CLEANFILES = strongswan.service strongswan-dataplane.service

systemdsystemunit_DATA = strongswan.service strongswan-dataplane.service

strongswan.service : strongswan.service.in
	$(AM_V_GEN) \
	sed \
	-e "s:@SBINDIR@:$(sbindir):" \
	$(srcdir)/$@.in > $@

strongswan-dataplane.service : strongswan-dataplane.service.in
	$(AM_V_GEN) \
	sed \
	-e "s:@SBINDIR@:$(sbindir):g" \
	$(srcdir)/$@.in > $@
