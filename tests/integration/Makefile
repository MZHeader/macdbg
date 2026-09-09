BUILD := build
FIXTURE := $(BUILD)/analysis_fixture
STRIPPED_FIXTURE := $(BUILD)/analysis_fixture_stripped
LATE_IOKIT_FIXTURE := $(BUILD)/late_iokit_fixture
FRIDA_FIXTURE := $(BUILD)/FridaGadget.dylib
CFLAGS := -arch arm64 -O0 -g -Wall -Wextra
FRAMEWORKS := -framework CoreFoundation -framework IOKit

.PHONY: all clean
all: $(FIXTURE) $(STRIPPED_FIXTURE) $(LATE_IOKIT_FIXTURE) $(FRIDA_FIXTURE)

$(BUILD):
	mkdir -p $@

$(FIXTURE): analysis_fixture.m | $(BUILD)
	clang $(CFLAGS) $(FRAMEWORKS) $< -o $@

$(STRIPPED_FIXTURE): analysis_fixture.m | $(BUILD)
	clang -arch arm64 -O0 -g0 -Wall -Wextra $(FRAMEWORKS) $< -o $@
	strip -S -x $@

$(LATE_IOKIT_FIXTURE): late_iokit_fixture.c | $(BUILD)
	clang -arch arm64 -O0 -g0 -Wall -Wextra $< -o $@
	strip -S -x $@

$(FRIDA_FIXTURE): FridaGadget.c | $(BUILD)
	clang -arch arm64 -dynamiclib -O0 -g -Wall -Wextra $< -o $@

clean:
	rm -rf $(BUILD)
