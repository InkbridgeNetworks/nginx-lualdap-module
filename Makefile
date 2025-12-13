# Pass all targets through to the OpenResty make file.
# $(MAKE) expands to the make command plus any flags passed to the outer invocation.

# Configure adds our module into OpenResty's build system, so we don't need to
# do anything special here.
.PHONY: all clean
all:
	$(MAKE) -C openresty $(MAKECMDGOALS)

clean:
	rm -rf openresty build

%:
	$(MAKE) -C openresty $@
