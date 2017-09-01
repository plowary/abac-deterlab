#
# creddy_prover_tests
#

include  ../abac.mk

EXPECTED_OKAY=14

DIRECTORY=acme_rockets_intersection_rt0 acme_rockets_rt0 \
          experiment_create_rt0 ice_cream_rt0

.PHONY: clean clean-local runcheck
all: runcheck

runcheck:
	@echo 'running libabac CREDDY_PROVER testing...' | tee result
	@touch error
	@for i in $(DIRECTORY); do \
	  here=`pwd`; \
	  cd $$i; \
	  printf "\n ==> RUN on %s\n" "$$i" >> $$here/result ; \
	  $(MY_ENV) ./README 1>/dev/null 2>&1; \
	  $(MY_ENV) ./run_query |tee -a $$here/result |grep BAD >> $$here/error; \
	  cd $$here; \
	done
	@if test -f error ; \
          then \
            (if test `cat error | wc -l ` -eq 0 ; \
              then \
                (if test `grep GOOD result | wc -l ` -eq $(EXPECTED_OKAY) ; \
                  then echo "   PASSED!!!"; \
                  else echo "   ERROR, no error but not enough good results!!!"; \
                fi); \
              else (echo "   ERROR!!!"; cat error;); \
            fi); \
          else echo "   PASSED"; \
        fi

clean:
	@for i in $(DIRECTORY); do \
	  here=`pwd`; \
	  cd $$i; \
	  rm -rf *.pem *.xml; \
	  cd $$here; \
	done
	@rm -rf result error

clean-local: 
	@rm -rf result error
