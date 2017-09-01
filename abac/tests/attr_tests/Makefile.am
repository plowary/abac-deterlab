#
# attr_tests
#

include  ../abac.mk

EXPECTED_OKAY=3

.PHONY: runcheck clean-local setup
all: runcheck

runcheck: setup.sh
	@make clean
	@echo 'running libabac ATTRS testing...' | tee result
	@touch error
	@$(MY_ENV) ./setup.sh 
	@($(MY_ENV) ./show.sh |tee -a result |grep BAD >> error; cd .)
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
	@rm -rf *.xml *.pem error result

clean-local:
	@rm -rf *.xml *.pem error result


