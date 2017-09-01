#
# example_scripts/c
#

include  ../../abac.mk

.PHONY: clean-local 

all: attr prove 

abac_attr.o: abac_attr.c
	gcc -g $(MY_INCLUDES_VAL) -c abac_attr.c -o abac_attr.o

abac_attr: abac_attr.o
	gcc -g -o abac_attr abac_attr.o $(MY_LDFLAGS_VAL)

abac_prover.o: abac_prover.c
	gcc -g $(MY_INCLUDES_VAL) -c abac_prover.c -o abac_prover.o

abac_prover: abac_prover.o
	gcc -g -o abac_prover abac_prover.o $(MY_LDFLAGS_VAL)

tchunk: tchunk.c
	gcc -g $(MY_INCLUDES_VAL) -c tchunk.c -o tchunk.o
	gcc -g -o tchunk tchunk.o $(MY_LDFLAGS_VAL)
	./tchunk 0 IceCream_ID.pem IceCream_private.pem
	./tchunk 1 IceCream_ID.pem IceCream_private.pem

tleak: abac_attr.c
	make clean
	@$(MY_ENV) ./setup.sh 1>/dev/null 2>&1
	gcc -g -O1 $(MY_INCLUDES_VAL) -c abac_attr.c -o abac_attr.o
	gcc -g -O1 -o leak_attr abac_attr.o $(MY_LDFLAGS_VAL)  
	gcc -g -O1 $(MY_INCLUDES_VAL) -c abac_prover.c -o abac_prover.o
	gcc -g -O1 -o leak_prover abac_prover.o $(MY_LDFLAGS_VAL)
	$(MY_ENV) ./run_leak_prover 

tt: tbasic.c
	gcc -g $(MY_INCLUDES_VAL) -c tbasic.c -o tbasic.o
	gcc -g -o tt tbasic.o $(MY_LDFLAGS_VAL)
	./tt

clean-local:
	@rm -rf abac_attr.o abac_attr *.pem *.xml abac_prover.o 
	@rm -rf abac_prover *.log 
	@rm -rf tt tbasic.o tbasic

setup2: abac_attr abac_prover abac_attr_partial

attr: 
	echo '---running (c) attr script'
	$(MY_ENV) ./setup.sh 1>/dev/null 2>&1
	make abac_attr
	(rc=`$(MY_ENV) ./abac_attr IceCream_ID.pem  IceCream_private.pem IceCream_attr.xml Chocolate_ID.pem 2>/dev/null 2>/dev/null | grep "attr success"` ; \
	if [ -z "$$rc" ]; then \
	  echo "BAD:example_scripts/c/abac_attr:using libabac c to make attributes"; \
	else \
	  echo "GOOD:example_scripts/c/abac_attr:using libabac c to make attributes"; \
	fi)


prove: abac_prover 
	@echo '---running (c) prover script'
	@$(MY_ENV) ./setup.sh 1>/dev/null 2>&1
	@make abac_attr
	@$(MY_ENV) ./abac_attr IceCream_ID.pem  IceCream_private.pem IceCream_attr.xml Chocolate_ID.pem 1>/dev/null 2>&1
	(rc=`$(MY_ENV) ./run_prover | grep "prover success" ` ; \
	if [ -z "$$rc" ]; then \
	  echo "BAD:example_scripts/c/abac_prover:using libabac c to make a prover"; \
	else \
	  echo "GOOD:example_scripts/c/abac_prover:using libabac c to make a prover"; \
	fi)



mattr: attr.c
	gcc -g -o mattr attr.c $(MY_LDFLAGS_VAL)
mload: loader.c
	gcc -g -o mload loader.c $(MY_LDFLAGS_VAL)
