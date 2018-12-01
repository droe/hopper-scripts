SCRIPTS=	$(wildcard *.py)

all:

install: $(SCRIPTS)
	ln -sf '/Users/$(USER)/Library/Application Support/Hopper/Scripts' Scripts
	cp $^ Scripts/

diff: $(SCRIPTS)
	ln -sf '/Users/$(USER)/Library/Application Support/Hopper/Scripts' Scripts
	@for f in $^; do \
		out=`diff -u $$f Scripts/$$f`; \
		size=`echo "$$out"|wc -l`; \
		echo "$$out"|{ test $$size -gt `tput lines` && less || cat; }; \
	done

.PHONY: all install diff
