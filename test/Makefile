CFLAGS  := -O0 -g
LDFLAGS :=

BINS := hello fakemal fakemal_stripped talker

all: $(BINS)

hello: hello.c
	clang $(CFLAGS) $< -o $@

fakemal: fakemal.c
	clang $(CFLAGS) -pthread $< -o $@

# Realistic "malware sample": optimized, no debug info, symbol table stripped.
talker: talker.c
	clang $(CFLAGS) $< -o $@

fakemal_stripped: fakemal.c
	clang -O2 -pthread $< -o $@
	strip -x $@

clean:
	rm -rf $(BINS) *.dSYM

.PHONY: all clean
