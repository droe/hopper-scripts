YARA=		$(shell which yara)
ifeq ($(YARA),)
$(error yara not found in PATH)
endif

ifeq ($(shell uname),Darwin)
SCRIPTS_DIR=	Library/Application Support/Hopper/Scripts
REINPLACE=	sed -i ''
endif
ifeq ($(shell uname),Linux)
SCRIPTS_DIR=	GNUstep/Library/ApplicationSupport/Hopper/Scripts
REINPLACE=	sed -i''
endif
ifeq ($(SCRIPTS_DIR),)
$(error $(shell uname) unsupported)
endif

SCRIPTS=	$(wildcard *.py)
LIBS=		$(wildcard api/*.py)
SYMLINK=	Scripts


all:

install: install-api install-scripts

install-api: $(LIBS)
	test -e $(SYMLINK) || ln -sf "$(HOME)/$(SCRIPTS_DIR)" $(SYMLINK)
	mkdir -p $(SYMLINK)/api
	cp $^ $(SYMLINK)/api/
	rm -f $(SYMLINK)/api/*.pyc

install-scripts: $(SCRIPTS)
	test -e $(SYMLINK) || ln -sf "$(HOME)/$(SCRIPTS_DIR)" $(SYMLINK)
	cp $^ $(SYMLINK)/
	$(REINPLACE) -e s,@@yara@@,$(YARA),g $(SYMLINK)/*Yara*.py

diff: $(SCRIPTS) $(LIBS)
	test -e $(SYMLINK) || ln -sf "$(HOME)/$(SCRIPTS_DIR)" $(SYMLINK)
	@for f in $^; do \
		out=`diff -u $$f $(SYMLINK)/$$f`; \
		size=`echo "$$out"|wc -l`; \
		echo "$$out"|{ test $$size -gt `tput lines` && less || cat; }; \
	done

.PHONY: all install install-api install-scripts diff
