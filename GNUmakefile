SCRIPTS=	$(wildcard *.py)
SYMLINK=	Scripts

ifeq ($(shell uname),Darwin)
SCRIPTS_DIR=	Library/Application Support/Hopper/Scripts
endif
ifeq ($(shell uname),Linux)
SCRIPTS_DIR=	GNUstep/Library/ApplicationSupport/Hopper/Scripts
endif
ifeq ($(SCRIPTS_DIR),)
$(error $(shell uname) unsupported)
endif


all:

install: $(SCRIPTS)
	test -e $(SYMLINK) || ln -sf "$(HOME)/$(SCRIPTS_DIR)" $(SYMLINK)
	cp $^ $(SYMLINK)/

diff: $(SCRIPTS)
	test -e $(SYMLINK) || ln -sf "$(HOME)/$(SCRIPTS_DIR)" $(SYMLINK)
	@for f in $^; do \
		out=`diff -u $$f $(SYMLINK)/$$f`; \
		size=`echo "$$out"|wc -l`; \
		echo "$$out"|{ test $$size -gt `tput lines` && less || cat; }; \
	done

.PHONY: all install diff
