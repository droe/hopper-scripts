SCRIPTS=	$(wildcard *.py)

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
	ln -sf "$(HOME)/$(SCRIPTS_DIR)" Scripts
	cp $^ Scripts/

diff: $(SCRIPTS)
	ln -sf "$(HOME)/$(SCRIPTS_DIR)" Scripts
	@for f in $^; do \
		out=`diff -u $$f Scripts/$$f`; \
		size=`echo "$$out"|wc -l`; \
		echo "$$out"|{ test $$size -gt `tput lines` && less || cat; }; \
	done

.PHONY: all install diff
