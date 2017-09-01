#
# example_scripts/wiki
#

include  ../../abac.mk

.PHONY: runcheck clean-local

TESTS=id1 id2 id3 id4 id5 attr1 attr2 attr3 attr4 ctxtQuery1 ctxtQuery2 ctxtQuery3 ctxtQuery4

## need to enforce a specific order,
all: $(TESTS)

id1: id1.py
	@make clean
	@echo "---running (wiki) id1.py script"
	@(rc=`$(MY_ENV) ./id1.py |wc -c`; \
	if [ $$rc -eq 41 ] ; then \
	  echo "GOOD:example_scripts/wiki/id.py:making principal"; \
	else \
	  echo "BAD:example_scripts/wiki/id.py:making principal"; \
	fi)

gen_newguy: newguy.sh
	@$(MY_ENV) ./newguy.sh 1>/dev/null 2>&1

id2: id2.py
	make gen_newguy
	@echo "---running (wiki) id2.py script"
	@(rc=`$(MY_ENV) ./id2.py |wc -c` ; \
	if [ $$rc -eq 82 ]; then \
	  echo "GOOD:example_scripts/wiki/id2.py:making principal and chunk"; \
	else \
	  echo "BAD:example_scripts/wiki/id2.py:making principal and chunk"; \
	fi)

id3: id3.py
	@make clean
	@echo "---running (wiki) id3.py script"
	@(rc=`$(MY_ENV) ./id3.py |wc -c` ; \
	if [ $$rc -eq 123 ]; then \
	  echo "GOOD:example_scripts/wiki/id3.py:making principal and chunk"; \
	else \
	  echo "BAD:example_scripts/wiki/id3.py:making principal and chunk"; \
	fi)

id4: id4.py
	@make clean
	@echo "---running (wiki) id4.py script"
	@$(MY_ENV) ./id4.py 1 > id4.out 2>&1   
	@($(MY_ENV) ./id4.ck; \
	if [ $$? -eq 0 ]; then \
	  echo ""; \
	  echo "GOOD:example_scripts/wiki/id4.py:making variety of principals"; \
	else \
	  echo "BAD:example_scripts/wiki/id4.py:making variety of principals"; \
	fi)
	rm id4.out

id5: id5.py
	@make clean
	@echo "---running (wiki) id5.py script"
	@$(MY_ENV) ./id5.py 1 > id5.out 2>& 1 
	@($(MY_ENV) ./id5.ck; \
	if [ $$? -eq 0 ]; then \
	  echo ""; \
	  echo "GOOD:example_scripts/wiki/id5.py:making variety of principals"; \
	else \
	  echo "BAD:example_scripts/wiki/id5.py:making variety of principals"; \
	fi)
	rm id5.out

attr1: attr1.py
	@make clean
	@echo "---running (wiki) attr1.py script"
	@(rc=`$(MY_ENV) ./attr1.py |wc -c` ; \
	if [ $$rc -eq 0 ]; then \
	  echo "GOOD:example_scripts/wiki/attr1.py:making attribute"; \
	else \
	  echo "BAD:example_scripts/wiki/attr1.py:making attribute"; \
	fi)

attr2: attr2.py
	@make clean
	@echo "---running (wiki) attr2.py script"
	@(rc=`$(MY_ENV) ./attr2.py |wc -c` ; \
	if [ $$rc -eq 0 ]; then \
	  echo "GOOD:example_scripts/wiki/attr2.py:making more attribute"; \
	else \
	  echo "BAD:example_scripts/wiki/attr2.py:making more attribute"; \
	fi)

attr3: attr3.py
	@make clean
	@echo "---running (wiki) attr3.py script"
	@(list=`$(MY_ENV) ./attr3.py`; \
	  r1=`grep "&lt;-" V1_attr.xml |wc -l` ; \
	  r2=`grep "<ABACprincipal><keyid>" V1_1_attr.xml V1_1b_attr.xml |wc -l` ; \
	if [ "$$list" != "GENIv1.0GENIv1.1GENIv1.1" -o $$r1 -ne 1 -o $$r2 -ne 4 ]; then \
	  echo "BAD:example_scripts/wiki/attr3.py:different attr rt0 xml format"; \
	else \
	  echo "GOOD:example_scripts/wiki/attr3.py:different attr rt0 xml format"; \
	fi)

attr4: attr4.py
	@make clean
	@echo "---running (wiki) attr4.py script"
	@(rs=`$(MY_ENV) ./attr4_setup.py`; \
	  rc=`$(MY_ENV) ./attr4.py | grep mnemonic |wc -l`; \
	if [ $$rc -ne 6 ]; then \
	  echo "BAD:example_scripts/wiki/attr4.py:setting nickname in attr"; \
	else \
	  echo "GOOD:example_scripts/wiki/attr4.py:setting nickname in attr"; \
	fi)

ctxtQuery1: ctxtQuery1.py
	make clean
	@echo "---running (wiki) ctxtQuery1.py script"
	@(rc=`$(MY_ENV) ./ctxtQuery1.py |grep "ok? 1"` ; \
	if [ "$$rc" = "" ]; then \
	  echo "BAD:example_scripts/wiki/ctxtQuery1.py:prove in context"; \
	else \
	  echo "GOOD:example_scripts/wiki/ctxtQuery1.py:prove in context"; \
	fi)

ctxtQuery2: ctxtQuery2.py
	make clean
	@echo "---running (wiki) ctxtQuery2.py script"
	@(rc=`$(MY_ENV) ./ctxtQuery2.py |grep "ok? 1"` ; \
	if [ "$$rc" = "" ]; then \
	  echo "BAD:example_scripts/wiki/ctxtQuery2.py:prove in contxt"; \
	else \
	  echo "GOOD:example_scripts/wiki/ctxtQuery2.py:prove in contxt"; \
	fi)

ctxtQuery3: ctxtQuery3.py
	make clean
	@echo "---running (wiki) ctxtQuery3.py script"
	@$(MY_ENV) ./ctxtQuery3_setup.py 1>/dev/null 2>&1;
	@(rc=`$(MY_ENV) ./ctxtQuery3.py |grep "self contain, ok? 1"` ; \
	if [ "$$rc" = "" ]; then \
	  echo "BAD:example_scripts/wiki/ctxtQuery3.py:loading self contained attribute"; \
	else \
	  echo "GOOD:example_scripts/wiki/ctxtQuery3.py:loading self contained attribute"; \
	fi)

ctxtQuery4: ctxtQuery4.py
	make clean
	@echo "---running (wiki) ctxtQuery4.py script"
	@$(MY_ENV) ./ctxtQuery4_setup.py 1>/dev/null 2>&1;
	@(rc=`$(MY_ENV) ./ctxtQuery4.py | grep identity1 |wc -l` ; \
	if [ $$rc -eq 1 ]; then \
	  echo "GOOD:example_scripts/wiki/ctxtQuery4.py:trying mnemonic modification names"; \
	else \
	  echo "BAD:example_scripts/wiki/ctxtQuery4.py:trying mnemonic modification names"; \
	fi)


clean:
	@rm -rf *.xml *.pem 

clean-local:
	@rm -rf *.xml *.pem


