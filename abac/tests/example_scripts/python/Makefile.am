#
# example_scripts/python
#

include  ../../abac.mk

.PHONY: clean-local

all: run_attr run_id run_id2 run_id3 run_prove

clean:
	@rm -f *.pem *.xml pfile

setup:
	@$(MY_ENV) ./setup.sh 1>/dev/null 2>&1 

run_attr: 
	@echo "---running (python) attr script"
	@make clean
	@make setup
	@(rc=`$(MY_ENV) ./abac_attr.py IceCream_ID.pem IceCream_private.pem IceCream_attr.xml Chocolate_ID.pem |grep success` ; \
	if [ -z "$$rc" ]; then \
   	  echo "BAD:example_scripts/python/abac_attr.py:using libabac to create principal/attrs and make a simple query"; \
	else \
   	  echo "GOOD:example_scripts/python/abac_attr.py:using libabac to create principal/attrs and make a simple query"; \
	fi)

run_id: 
	@echo "---running (python) id script"
	@make clean
	@make setup
	@(rc=`$(MY_ENV) ./abac_keyid.py IceCream_ID.pem | grep okay` ; \
	if [ -z "$$rc" ]; then \
   	  echo "BAD:example_scripts/python/abac_keyid.py:using libabac to extract principal"; \
	else \
   	  echo "GOOD:example_scripts/python/abac_keyid.py:using libabac to extract principal"; \
	fi)


run_id2: 
	@echo "---running (python) id2 script, expected failure"
	@make clean
	@make setup
	@(rc=`$(MY_ENV) ./abac_keyid.py IceCream_private.pem  | grep okay` ; \
	if [ -z "$$rc" ]; then \
   	  echo "GOOD:example_scripts/python/abac_keyid.py:supplied with just a privkey"; \
	else \
   	  echo "BAD:example_scripts/python/abac_keyid.py:supplied with just a privkey, should fail"; \
	fi)


run_id3: 
	@echo "---running (python) id3 script"
	@make clean
	@make setup
	@(rc=`$(MY_ENV) ./abac_keyid2.py IceCream_ID.pem IceCream_private.pem | grep okay` ; \
	if [ -z "$$rc" ]; then \
   	  echo "BAD:example_scripts/python/abac_keyid.py:supplied both id and privkey pem files"; \
	else \
   	  echo "GOOD:example_scripts/python/abac_keyid.py:supplied with id and privkey pem files"; \
	fi)

run_prove:
	@echo "---running (python) prover script"
	@make clean
	@make setup
	@$(MY_ENV) ./abac_attr.py IceCream_ID.pem IceCream_private.pem IceCream_attr.xml Chocolate_ID.pem 1>/dev/null 2>&1
	@(rc=`$(MY_ENV) ./run_prover| grep success` ; \
	if [ -z "$$rc" ]; then \
   	  echo "BAD:example_scripts/python/abac_prover.py:trying out libabac python api to make a prover"; \
	else \
   	  echo "GOOD:example_scripts/python/abac_prover.py:trying out libabac python api to make a prover"; \
	fi)

#this needed to be run by hand (input dumdum twice)...
#echo '---running (python) encrypted key attr script'
#./run_e_prover 1> e_prover.log 2>& 1
#result=`grep success e_prover.log 2>/dev/null |wc -l`
#if [ "$result" = "2" ]; then
#   echo "   PASSED"
#else
#   echo "   ERROR"
#fi
#run_e_attr: 
#	make clean
#	rm -rf e_attr.log pfile
#	echo "dumdum" > pfile
#	openssl genrsa -des3 -out Soda_private.pem -passout file:pfile
#	creddy --generate --cn Soda --key Soda_private.pem --p=pfile
#	creddy --generate --cn Cream
#	./abac_e_attr.py Soda_ID.pem Soda_private.pem Soda_attr.xml pfile Cream_ID.pem 1>e_attr.log 2>&1

