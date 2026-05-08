# Pass all targets through to the OpenResty make file.
# $(MAKE) expands to the make command plus any flags passed to the outer invocation.

# Configure adds our module into OpenResty's build system, so we don't need to
# do anything special here.
.PHONY: all clean test test-parallel
all:
	$(MAKE) -C openresty $(MAKECMDGOALS)

clean:
	rm -rf openresty build

test:
	./run-tests.sh

test-parallel:
	./run-tests.sh --parallel

test-only:
	cd "$(dir $(abspath $(lastword $(MAKEFILE_LIST))))" && \
	    "$${LUA54:-/opt/homebrew/opt/lua@5.4/bin/lua5.4}" bin/run_tests

%:
	$(MAKE) -C openresty $@
