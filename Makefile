.PHONY: all clean bdist compile

TARGETS = bdist
BIGGREP_DIR = BigGrep-master
BIN_DIR = azul_plugin_retrohunt/bigyara/bin
BIGGREP_TOOLS = bgparse bgdump bgindex
BIGGREP_SOURCE_BINARIES = $(addprefix $(BIGGREP_DIR)/src/,$(BIGGREP_TOOLS))
BIGGREP_BINARIES = $(addprefix $(BIN_DIR)/,$(BIGGREP_TOOLS))
MISSING_BIGGREP_BINARIES := $(filter-out $(wildcard $(BIGGREP_BINARIES)),$(BIGGREP_BINARIES))

all: $(TARGETS)

# Build BigGrep. The modified YARA-X CLI is supplied separately as
# azul_plugin_retrohunt/yr and is not built or removed by this Makefile.
biggrep-latest.zip:
	wget -v -O $@.tmp https://github.com/cmu-sei/BigGrep/archive/master.zip
	mv $@.tmp $@

$(BIGGREP_DIR)/.extracted: biggrep-latest.zip
	unzip -o biggrep-latest.zip
	touch $@

# GNU Make 4.3+ grouped targets: one build produces all three binaries.
# A missing binary triggers the shared build, including under make -j.
$(BIGGREP_SOURCE_BINARIES) &: $(BIGGREP_DIR)/.extracted
	cd $(BIGGREP_DIR) && \
		./autogen.sh && \
		./configure && \
		$(MAKE) && \
		$(MAKE) check
	@for tool in $(BIGGREP_SOURCE_BINARIES); do test -f "$$tool" || exit 1; done

$(BIN_DIR):
	mkdir -p $@

# Existing bundled tools are authoritative. Do not traverse source/download
# prerequisites for them during Hatch or tox builds. Only missing tools need
# source dependencies; use make clean before compile to request a full rebuild.
ifneq ($(strip $(MISSING_BIGGREP_BINARIES)),)
$(MISSING_BIGGREP_BINARIES): $(BIN_DIR)/%: $(BIGGREP_DIR)/src/% | $(BIN_DIR)
	cp $< $@
endif

compile: $(BIGGREP_BINARIES)

bdist: compile
	uv build --wheel

clean:
	rm -f $(BIGGREP_BINARIES) biggrep-latest.zip biggrep-latest.zip.tmp
	rm -rf $(BIGGREP_DIR) build dist
