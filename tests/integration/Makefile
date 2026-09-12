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
all: $(BUILD)/workflow_fixture

$(BUILD)/workflow_fixture: workflow_fixture.c | $(BUILD)
	clang $(CFLAGS) -Wno-deprecated-declarations $< -o $@

all: $(FIXTURE) $(STRIPPED_FIXTURE) $(OPTIMIZED_FIXTURE) $(LATE_IOKIT_FIXTURE) $(FRIDA_FIXTURE) $(CONTROLLED_SYSCTL_FIXTURE) $(BUILD)/timing_fixture $(BUILD)/timing_fixture_optimized $(BUILD)/framework_fixture $(BUILD)/clock_contention_fixture $(BUILD)/ClockWorker.dylib $(BUILD)/constant.scpt $(BUILD)/self_trap_fixture $(BUILD)/script_exec_fixture $(BUILD)/script_exec_late_fixture

$(BUILD)/script_exec_late_fixture: script_exec_late_fixture.c | $(BUILD)
	clang $(CFLAGS) -Wno-deprecated-declarations $< -o $@

$(BUILD)/script_exec_fixture: script_exec_fixture.c | $(BUILD)
	clang $(CFLAGS) -Wno-deprecated-declarations -framework Carbon $< -o $@

$(BUILD)/self_trap_fixture: self_trap_fixture.c | $(BUILD)
	clang $(CFLAGS) $< -o $@

$(BUILD)/constant.scpt: | $(BUILD)
	osacompile -x -e 'return 0' -o $@

$(BUILD)/framework_fixture: framework_fixture.c | $(BUILD)
	clang $(CFLAGS) -Wno-deprecated-declarations -framework Carbon -lobjc $< -o $@

$(BUILD)/ClockWorker.dylib: ClockWorker.c | $(BUILD)
	clang $(CFLAGS) -dynamiclib $< -o $@

$(BUILD)/clock_contention_fixture: clock_contention_fixture.c | $(BUILD)
	clang $(CFLAGS) $< -o $@

$(BUILD)/timing_fixture: timing_fixture.c timing_decisions.S | $(BUILD)
	clang $(CFLAGS) $^ -o $@

$(BUILD)/timing_fixture_optimized: timing_fixture.c timing_decisions.S | $(BUILD)
	clang -arch arm64 -O2 -g -Wall -Wextra $^ -o $@

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
