#
# example_scripts/perl
#

include  ../../abac.mk

.PHONY: clean-local

all: run bad prove

clean-local:
	@rm -rf *.pem *.xml 

run: 
	echo '---running (perl) id script'
	make clean
	$(MY_ENV) ./setup.sh 1>/dev/null 2>&1
	(rc=`$(MY_ENV) ./abac_keyid.pl IceCream_ID.pem | grep OKAY` ; \
	if [ -z "$$rc" ]; then \
	  echo "BAD:example_scripts/perl/abac_keyid.pl:using libabac perl to make principal"; \
	else \
	  echo "GOOD:example_scripts/perl/abac_keyid.pl:using libabac perl to make principal"; \
	fi)

bad: 
	echo '---running (perl) id2 script, expected failure'
	make clean
	$(MY_ENV) ./setup.sh 1>/dev/null 2>&1
	(rc=`$(MY_ENV) ./abac_keyid.pl IceCream_private.pem | grep "std::invalid_argument"`; \
	if [ -z "$$rc" ]; then \
	  echo "BAD:example_scripts/perl/abac_keyid.pl:supplied with just privkey"; \
	else \
	  echo "GOOD:example_scripts/perl/abac_keyid.pl:supplied with just privkey"; \
	fi)

attr: 
	echo '---running (perl) attr script'
	make clean
	$(MY_ENV) ./setup.sh 1>/dev/null 2>&1
	(rc=`$(MY_ENV) ./run_attr | grep chocolate` ; \
	if [ -z "$$rc" ]; then \
	  echo "BAD:example_scripts/perl/abac_attr.pl:creating attribute"; \
	else \
	  echo "GOOD:example_scripts/perl/abac_keyid.pl:creating attribute"; \
	fi)

prove: 
	echo '---running (perl) attr script'
	make clean
	$(MY_ENV) ./setup.sh 1>/dev/null 2>&1
	$(MY_ENV) ./run_attr 1>/dev/null 2>&1
	(rc=`$(MY_ENV) ./run_prover | grep Success` ; \
	if [ -z "$$rc" ]; then \
	  echo "BAD:example_scripts/perl/abac_prover.pl:prover in perl"; \
	else \
	  echo "GOOD:example_scripts/perl/abac_prover.pl:prover in perl"; \
	fi)


