#
# daisychain/likes_python
#

include  ../../../abac.mk

TEST=likes_0 likes_10 likes_20
TIMING=likes_30 likes_40 likes_50 likes_100 likes_150 likes_200

.PHONY : test clean timing plot 
all: test

test: $(TEST)

timing: $(TIMING)

likes_0 :
	$(MY_ENV) ./run_one 0
likes_10 :
	@$(MY_ENV) ./run_one 10
likes_20 :
	@$(MY_ENV) ./run_one 20

clean:
	@rm -rf likes_* run_plot plot timing

$(TIMING):
	@$(MY_ENV) ./run_one $(subst likes_,,$@)

plot:
	@make clean
	cp ../../plotting/run_plot .
	@make -s test
	@make -s timing
	@./run_plot likes
