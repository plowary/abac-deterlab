#
# python_tests
#

include  ../abac.mk

EXPECTED_OKAY=11

DIRECTORY=acme_rockets_intersection_rt0 acme_rockets_rt0 experiment_create_rt0
OTHER=basic_attribute basic_id 

.PHONY: clean-local runcheck clean
all: runcheck

clean:
	@for i in $(DIRECTORY); do \
	  here=`pwd`; \
	  cd $$i; \
	  rm -rf *.pem *.xml; \
	  cd $$here; \
        done
	@(cd basic_id; rm -rf *.pem *.xml)
	@(cd basic_attribute; rm -rf *.pem *.xml)
	@rm -rf result error

runcheck :
	@touch error
	@echo 'running libabac PYTHON testing...' | tee result
	@make clean
	@for i in $(DIRECTORY); do \
	  here=`pwd`; \
	  cd $$i; \
	  printf "\n ==> RUN on %s\n" "$$i" >> $$here/result ; \
	  $(MY_ENV) ./setup.py 1>/dev/null 2>&1; \
	  $(MY_ENV) ./attr.py 1>/dev/null 2>&1; \
	  $(MY_ENV) ./query.py |tee -a $$here/result |grep BAD >> $$here/error; \
	  cd $$here; \
        done
	make -i ids
	make -i attrs
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

ids:
	@printf "\n ==> RUN on basic_id\n" >> result
	@(cd basic_id; \
	$(MY_ENV) ./setup.py 1>/dev/null 2>&1; \
	$(MY_ENV) ./query.py |tee -a ../result |grep BAD >> ../error; \
	cd ..)

attrs:
	@printf "\n ==> RUN on basic_attr\n" >> result
	@(cd basic_attribute; \
	$(MY_ENV) ./setup.py 1>/dev/null 2>&1; \
	$(MY_ENV) ./query.py |tee -a ../result |grep BAD >> ../error; \
	cd ..)

clean-local: 
	@rm -rf result error
