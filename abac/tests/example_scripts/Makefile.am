#
# example_scripts
#

EXPECTED_OKAY = 23

DIRECTORY = c perl python wiki
SUBDIRS = $(DIRECTORY)

.PHONY : runcheck clean-local clean
all: runcheck

clean-local:
clean:
	@for i in $(DIRECTORY); do \
	  here=`pwd`; \
	  cd $$i; \
	  make -s clean; \
	  cd $$here; \
	done
	@rm -rf result error

runcheck:
	@echo 'running libabac SCRIPT testing...' | tee result
	@touch error;
	@for i in $(DIRECTORY); do \
	  here=`pwd`; \
	  cd $$i; \
	  printf "\n ==> RUN on %s\n" "$$i" >> $$here/result ; \
	  make -i -s |tee -a $$here/result |grep BAD >> $$here/error; \
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

