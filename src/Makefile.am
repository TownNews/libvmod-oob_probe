AM_CPPFLAGS = @VMOD_INCLUDES@ -Wall -Werror

vmoddir = @VMOD_DIR@
vmod_LTLIBRARIES = libvmod_oob_probe.la

libvmod_oob_probe_la_LDFLAGS = -module -export-dynamic -avoid-version -shared

libvmod_oob_probe_la_SOURCES = \
	vmod.c

nodist_libvmod_oob_probe_la_SOURCES = \
	vcc_if.c \
	vcc_if.h

vmod_oob_probe.lo: vcc_if.c vcc_if.h

vcc_if.c: vcc_if.h

vcc_if.h: @VMODTOOL@ $(top_srcdir)/src/vmod.vcc
	@VMODTOOL@ $(top_srcdir)/src/vmod.vcc

VMOD_TESTS = $(top_srcdir)/src/tests/*.vtc
.PHONY: $(VMOD_TESTS)

$(top_srcdir)/src/tests/*.vtc: libvmod_oob_probe.la
	@VARNISHTEST@ -Dvarnishd=@VARNISHD@ -Dvmod_topbuild=$(abs_top_builddir) $@

check: $(VMOD_TESTS)

EXTRA_DIST = \
	vmod.vcc \
	$(VMOD_TESTS)

CLEANFILES = \
	$(builddir)/vcc_if.c \
	$(builddir)/vcc_if.h \
	$(builddir)/vmod_oob_probe.rst \
	$(builddir)/vmod_oob_probe.man.rst
