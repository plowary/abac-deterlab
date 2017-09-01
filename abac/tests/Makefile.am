
#
# tests directory for libabac
#
# default, executable/lib are accessed from build directory but
# in case where rpm/debian binary packages were used, only access
# to install directory is available..
# In that case, the call,
#    make tests_with_install
# will force the testing to be run with install directory
#
# special note: for Cento5 machines that is tightly coupled with
# python 2.4, need to sed out the invocation python to python2.6
# (the required version) with
# find . -type f -print | xargs sed -i 's/env python$/env python2.6/'

include abac.mk

MY_SH_ENV = env $(ABAC_BUILD_CREDDY_VAL) $(ABAC_BUILD_PROVER_VAL) 
MY_PY_ENV = env $(ABAC_BUILD_PROVER_VAL) $(ABAC_BUILD_PYTHON_VAL)
MY_PL_ENV = env $(ABAC_BUILD_PERL_VAL)

DIRECTORY = example_scripts python_tests scaling_tests \
          creddy_tests creddy_prover_tests attr_tests

SUBDIRS = $(DIRECTORY)

.PHONY: tests tests_with_install clean clean-local check_sh_env check_py_env 
all: tests

tests:
	@for i in $(DIRECTORY); do \
	  here=`pwd`; \
	  export RUN_WITH_BUILD=1; \
          export TESTDIR=$(abs_top_builddir)/tests; \
          export MY_ENV="$(MY_BUILD_ENV)"; \
          export MY_LDFLAGS_VAL="$(ABAC_BUILD_LDFLAGS_VAL)"; \
          export MY_INCLUDES_VAL="$(ABAC_BUILD_INCLUDES_VAL)"; \
	  cd $$i; \
	  make -i -s runcheck | tee -a $$here/result; \
	  cd $$here; \
	done

tests_with_install:
	@touch result
	@for i in $(DIRECTORY); do \
	  export TESTDIR=$(abs_top_builddir)/tests; \
          export MY_ENV="$(MY_INSTALL_ENV)"; \
          export MY_LDFLAGS_VAL="$(ABAC_INSTALL_LDFLAGS_VAL)"; \
          export MY_INCLUDES_VAL="$(ABAC_INSTALL_INCLUDES_VAL)"; \
	  here=`pwd`; \
	  cd $$i; \
	  make -i -s runcheck | tee -a $$here/result; \
	  cd $$here; \
	done


check_sh_env:
	@rc=`$(MY_SH_ENV) ./test_util.sh`; \
	if [ $$? -eq 0 ]; then \
	  echo "sh_env, okay"; \
	else \
	  echo "sh_env, not okay"; \
	  echo "perhap you did not configure&build libabac's c api??"; \
	fi

check_py_env:
	@rc=`$(MY_PY_ENV) ./test_util.py`; \
	if [ $$? -eq 0 ]; then \
	  echo "py_env, okay"; \
	else \
	  echo "py_env, not okay"; \
	  echo "perhap you did not configure&build libabac's swig/python api??"; \
	fi

check_pl_env:
	@rc=`$(MY_PL_ENV) ./test_util.pl`; \
	if [ $$? -eq 0 ]; then \
	  echo "pl_env, okay"; \
	else \
	  echo "pl_env, not okay"; \
	  echo "perhap you did not configure&build libabac's swig/perl api??"; \
	fi
	
	
clean:
	@export TESTDIR=$(abs_top_builddir)/tests; \
	for i in $(DIRECTORY); do \
	  here=`pwd`; \
	  cd $$i; \
	  make -s clean; \
	  cd $$here; \
	done
	rm -rf result
	rm -rf test_util.pyc

clean-local:
	rm -rf result
	rm -rf test_util.pyc
