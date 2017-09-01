#
# haystack/ralphs_prover
#

include  ../../../abac.mk

TEST=ralphs_0 ralphs_10 ralphs_20
TIMING=ralphs_30 ralphs_40 ralphs_50 ralphs_100 ralphs_150 ralphs_200

.PHONY : test clean timing plot 
all: test

test: $(TEST)

timing: $(TIMING)

ralphs_0 :
	$(MY_ENV) ./run_one 0
ralphs_10 :
	@$(MY_ENV) ./run_one 10
ralphs_20 :
	@$(MY_ENV) ./run_one 20

clean:
	@rm -rf ralphs_* run_plot plot timing dump.file

$(TIMING):
	@$(MY_ENV) ./run_one $(subst ralphs_,,$@)

plot:
	@make clean
	cp ../../plotting/run_plot .
	@make -i -s test
	@make -i -s timing
	@./run_plot ralphs
