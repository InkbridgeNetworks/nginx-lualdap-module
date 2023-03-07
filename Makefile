# $Id: Makefile,v 1.30 2007/03/13 22:07:33 godinho Exp $

T= lualdap
V= 1.1.0
CONFIG= ./make.config

include $(CONFIG)

ifeq "$(LUA_VERSION_NUM)" "500"
COMPAT_O= $(COMPAT_DIR)/compat-5.1.o
endif

OBJS= src/lualdap.o $(COMPAT_O)

src/$(LIBNAME): $(OBJS)
	export MACOSX_DEPLOYMENT_TARGET="13.0"; $(CC) $(CFLAGS) $(LIB_OPTION) -o src/$(LIBNAME) $(OBJS) $(OPENLDAP_LIB)

src/lualdap.o: src/lualdap.c src/lualdap-ngx.c config
	$(CC) -c $(CFLAGS) -o $@ src/lualdap.c

$(COMPAT_DIR)/compat-5.1.o: $(COMPAT_DIR)/compat-5.1.c
	$(CC) -c $(CFLAGS) -o $@ $(COMPAT_DIR)/compat-5.1.c

install: src/$(LIBNAME)
	mkdir -p $(LUA_INSTDIR)
	cp src/$(LIBNAME) $(LUA_INSTDIR)
	cd $(LUA_INSTDIR); ln -f -s $(LIBNAME) $T.so

clean:
	rm -f $(OBJS) src/$(LIBNAME)
