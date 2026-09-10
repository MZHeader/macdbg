BUILD := build
FIXTURE := $(BUILD)/analysis_fixture
STRIPPED_FIXTURE := $(BUILD)/analysis_fixture_stripped
OPTIMIZED_FIXTURE := $(BUILD)/analysis_fixture_optimized
LATE_IOKIT_FIXTURE := $(BUILD)/late_iokit_fixture
FRIDA_FIXTURE := $(BUILD)/FridaGadget.dylib
SYSCTL_HOST := $(BUILD)/SysctlHost.dylib
CONTROLLED_SYSCTL_FIXTURE := $(BUILD)/analysis_fixture_sysctl_host
CFLAGS := -arch arm64 -O0 -g -Wall -Wextra
FRAMEWORKS := -framework CoreFoundation -framework IOKit

.PHONY: all clean
all: $(FIXTURE) $(STRIPPED_FIXTURE) $(OPTIMIZED_FIXTURE) $(LATE_IOKIT_FIXTURE) $(FRIDA_FIXTURE) $(CONTROLLED_SYSCTL_FIXTURE)

$(BUILD):
	mkdir -p $@

$(FIXTURE): analysis_fixture.m | $(BUILD)
	clang $(CFLAGS) $(FRAMEWORKS) $< -o $@

$(STRIPPED_FIXTURE): analysis_fixture.m | $(BUILD)
	clang -arch arm64 -O0 -g0 -Wall -Wextra $(FRAMEWORKS) $< -o $@
	strip -S -x $@

$(OPTIMIZED_FIXTURE): analysis_fixture.m | $(BUILD)
	clang -arch arm64 -O2 -g -DCLOAK_INLINE_INTEGRITY -Wall -Wextra $(FRAMEWORKS) $< -o $@

$(LATE_IOKIT_FIXTURE): late_iokit_fixture.c | $(BUILD)
	clang -arch arm64 -O0 -g0 -Wall -Wextra $< -o $@
	strip -S -x $@

$(FRIDA_FIXTURE): FridaGadget.c | $(BUILD)
	clang -arch arm64 -dynamiclib -O0 -g -Wall -Wextra $< -o $@

$(SYSCTL_HOST): SysctlHost.c | $(BUILD)
	clang $(CFLAGS) -dynamiclib -Wl,-install_name,@rpath/SysctlHost.dylib $< -o $@

$(CONTROLLED_SYSCTL_FIXTURE): analysis_fixture.m $(SYSCTL_HOST) | $(BUILD)
	clang $(CFLAGS) $< $(SYSCTL_HOST) $(FRAMEWORKS) -Wl,-rpath,@loader_path -o $@

clean:
	rm -rf $(BUILD)
