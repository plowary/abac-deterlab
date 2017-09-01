
TEST=fruit_0 fruit_10 fruit_20 
TIMING=fruit_30 fruit_40 fruit_50 fruit_100 fruit_150 fruit_200

.PHONY : clean test timing plot

test: $(TEST)
timing: $(TIMING)

clean: 
	@rm -rf fruit_* timing plot run_plot

fruit_0 :
	@./run_one 0
fruit_10 :
	@./run_one 10
fruit_20 :
	@./run_one 20

$(TIMING):
	@./run_one $(subst fruit_,,$@)

plot:
	@make clean
	@cp ../../plotting/run_plot .
	@make test
	@make timing
	@./run_plot fruit

