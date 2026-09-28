# language: Make, file: Makefile, target: Linux x86_64, requires: gcc 12+
#
# Targets:
#   make            -> conceal, selftest            (default build)
#   make trace      -> trace_bench                  (stderr logging on, 6s self-stop)
#   make pidns      -> conceal_pidns                 (-DUSE_PIDNS, see stage0.c header)
#   make clean
#
# The selftest build bakes in SELFTEST_LIMIT so the ladder unwinds by itself
# after 12s. Never run ./selftest expecting it to stay up -- that is the point
# of it: a concealed process you cannot stop is not a build, it is a mess.

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter -fPIE -pie -D_FORTIFY_SOURCE=2
LDFLAGS ?= -Wl,-z,relro,-z,now

all: conceal selftest

conceal: stage0.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

selftest: stage0.c
	$(CC) $(CFLAGS) -DSELFTEST_LIMIT=12 -o $@ $< $(LDFLAGS)

trace: stage0.c
	$(CC) -O0 -g -DCONCEAL_TRACE -DSELFTEST_LIMIT=6 -o trace_bench $< $(LDFLAGS)

pidns: stage0.c
	$(CC) $(CFLAGS) -DUSE_PIDNS -DSELFTEST_LIMIT=12 -o conceal_pidns $< $(LDFLAGS)

clean:
	rm -f conceal selftest trace_bench conceal_pidns probe probe.c
.PHONY: all clean trace pidns
