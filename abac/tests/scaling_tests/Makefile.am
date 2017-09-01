#
# scaling_tests
#

EXPECTED_OKAY=6

DIRECTORY=daisychain haystack
#PLOT= daisychain/likes_python haystack/ralphs_python

SUBDIRS=$(DIRECTORY)

.PHONY : runcheck clean-local plot clean
all:runcheck

clean:
	@for i in $(DIRECTORY); do \
	  here=`pwd`; \
	  cd $$i; \
	  make clean; \
	  cd $$here; \
	done; 
	rm -rf error result
	rm -rf jpegs

local-clean:
	rm -rf error result
	rm -rf jpegs

runcheck: 
	@echo 'running libabac SCALING testing...' | tee result
	@touch error
	@for i in $(DIRECTORY); do \
	  here=`pwd`; \
	  printf "\n ==> RUN on %s\n" "$$i" >> result; \
	  cd $$i; \
	  make -i runcheck | tee -a $$here/result |grep BAD >> $$here/error; \
	  cd $$here; \
	done; 
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

plot:
	make clean
	mkdir jpegs
	@for i in $(PLOT); do \
	  here=`pwd`; \
	  cd $$i; \
	  make -s plot; \
	  cd $$here; \
	done;

