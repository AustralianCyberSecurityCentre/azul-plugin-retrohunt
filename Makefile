.PHONY: clean bdist compile

TARGETS=bdist

all: $(TARGETS)

# get yara
yara-4.2.3.zip:
	wget -v -O yara-4.2.3.zip https://github.com/VirusTotal/yara/archive/refs/tags/v4.2.3.zip

yara-4.2.3: yara-4.2.3.zip
	unzip -o yara-4.2.3.zip


# patch yara source code, then compile twice - 
# once with large atoms (255 bytes),
# and once with small atoms (6 bytes) - used to check for nocase)
azul_plugin_retrohunt/bigyara/bin/yarac-large: | yara-4.2.3
	cd yara-4.2.3 && \
	patch -p1 < ../patch/print_atoms.patch && \
	./bootstrap.sh && \
	./configure CFLAGS="-DYR_MAX_ATOM_LENGTH=255" LDFLAGS="-static" && \
	make clean && \
	make && \
	cp yarac ../azul_plugin_retrohunt/bigyara/bin/yarac-large

azul_plugin_retrohunt/bigyara/bin/yarac-small: azul_plugin_retrohunt/bigyara/bin/yarac-large
	cd yara-4.2.3 && \
	./configure CFLAGS="-DYR_MAX_ATOM_LENGTH=6" LDFLAGS="-static" && \
	make clean && \
	make && \
	cp yarac ../azul_plugin_retrohunt/bigyara/bin/yarac-small

# get biggrep
biggrep-latest.zip:
	wget -v -O biggrep-latest.zip https://github.com/cmu-sei/BigGrep/archive/master.zip

BigGrep-master: biggrep-latest.zip
	unzip -o biggrep-latest.zip

BigGrep-master/src/bgparse: | BigGrep-master
	cd BigGrep-master && \
	./autogen.sh && \
	./configure && \
	make && \
	make check

azul_plugin_retrohunt/bigyara/bin/bgparse: BigGrep-master/src/bgparse
	cp BigGrep-master/src/bgparse azul_plugin_retrohunt/bigyara/bin/

azul_plugin_retrohunt/bigyara/bin/bgdump: BigGrep-master/src/bgdump
	cp BigGrep-master/src/bgdump azul_plugin_retrohunt/bigyara/bin/

azul_plugin_retrohunt/bigyara/bin/bgindex: BigGrep-master/src/bgindex
	cp BigGrep-master/src/bgindex azul_plugin_retrohunt/bigyara/bin/

compile: azul_plugin_retrohunt/bigyara/bin/yarac-large azul_plugin_retrohunt/bigyara/bin/yarac-small azul_plugin_retrohunt/bigyara/bin/bgparse azul_plugin_retrohunt/bigyara/bin/bgdump azul_plugin_retrohunt/bigyara/bin/bgindex

bdist: compile
	python setup.py bdist_wheel

clean:
	python setup.py clean
	rm -f azul_plugin_retrohunt/bigyara/bin/*
	rm -f *.zip
	rm -rf yara-4.2.3
	rm -rf BigGrep-master

