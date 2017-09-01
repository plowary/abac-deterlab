#
# creddy_tests
#
include  ../abac.mk

EXPECTED_OKAY=49
#Commented out display.sh test9, ProtoGENI is considered obsolete and certs are expired
all: runcheck

.PHONY: runcheck clean-local setup

SCRIPT=verify roles attribute keyid generate display attribute_rule 

runcheck: setup.sh
	@echo 'running libabac CREDDY testing...' | tee result
	@make clean
	@$(MY_ENV) ./setup.sh
	@touch error
	@for i in $(SCRIPT); do \
	  echo "---running $$i script"  >> result; \
	  $(MY_ENV) ./$$i.sh | tee -a result |grep BAD >> error; cd .; \
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
	@rm -rf *.xml *.pem error result

clean-local:
	@rm -rf *.xml *.pem error result


