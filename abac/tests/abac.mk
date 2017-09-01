#
# abac.mk
#
ABAC_BUILD_CREDDY_VAL = CREDDY_LOCATION=$(abs_top_builddir)/creddy
ABAC_BUILD_PROVER_VAL = PROVER_LOCATION=$(abs_top_builddir)/libabac
ABAC_BUILD_PYTHON_VAL = PYTHONPATH=$(abs_top_builddir)/swig/python:$(abs_top_builddir)/swig/python/.libs:$(abs_top_builddir)/tests
ABAC_BUILD_PATH_VAL = LD_LIBRARY_PATH=$(abs_top_builddir)/libabac/.libs
ABAC_BUILD_PERL_VAL = PERLLIB=$(abs_top_builddir)/swig/perl:$(abs_top_builddir)/swig/perl/.libs
ABAC_BUILD_INCLUDES_VAL = -I$(abs_top_srcdir)/libabac
ABAC_BUILD_LDFLAGS_VAL = -L$(abs_top_srcdir)/libabac/.libs -labac -lm -lpthread -Wl,-rpath

ABAC_INSTALL_CREDDY_VAL = CREDDY_LOCATION=$(bindir)
ABAC_INSTALL_PROVER_VAL = PROVER_LOCATION=$(bindir)
ABAC_INSTALL_PYTHON_VAL = PYTHONPATH=$(pythondir):$(abs_top_builddir)/tests
ABAC_INSTALL_PERL_VAL = PERLLIB=$(SITE_PERL)
ABAC_INSTALL_INCLUDES_VAL = -I$(includedir)
ABAC_INSTALL_LDFLAGS_VAL = -L$(libdir) -labac -lm -lpthread -Wl,-rpath

MY_BUILD_ENV=env $(ABAC_BUILD_CREDDY_VAL) $(ABAC_BUILD_PROVER_VAL) $(ABAC_BUILD_PYTHON_VAL) $(ABAC_BUILD_PERL_VAL) $(ABAC_BUILD_PATH_VAL)
MY_INSTALL_ENV=env $(ABAC_INSTALL_CREDDY_VAL) $(ABAC_INSTALL_PROVER_VAL) $(ABAC_INSTALL_PYTHON_VAL) $(ABAC_INSTALL_PERL_VAL)

