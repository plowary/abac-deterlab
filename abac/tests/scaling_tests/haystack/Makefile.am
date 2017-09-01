#
# haystack
#

DIRECTORY=ralphs_prover
SUBDIRS=$(DIRECTORY)

.PHONY : runcheck clean
all: runcheck

clean:
	@for i in $(DIRECTORY); do \
	here=`pwd`; \
	cd $$i; \
	make clean; \
	cd $$here;\
	done;

runcheck: 
	@for i in $(DIRECTORY); do \
	  here=`pwd`; \
	  cd $$i; \
	  make -i -s test; \
	  cd $$here;\
	done;
