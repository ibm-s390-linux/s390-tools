#! /usr/bin/make -f

include ../../common.mak

ALL_CPPFLAGS += -I../include
ALL_CFLAGS   += -g


PROGRAMS = test_afiucv
TEST_PROGRAMS = test_functions test_allow
TEST_PROGRAMS_NORUN = test_auditlog


test_afiucv: test_afiucv.o
test_functions: test_functions.o test_common.o ../src/functions.o
test_allow: test_allow.o test_common.o ../src/functions.o
test_auditlog: test_auditlog.o test_common.o ../src/auditlog.o \
	       ../src/functions.o


all: $(PROGRAMS)
check: $(TEST_PROGRAMS) $(TEST_PROGRAMS_NORUN)
	@for prg in $(TEST_PROGRAMS); do \
		failed=0 ;\
		echo ; echo "=== RUN : $$prg ===" ;\
		./$$prg || failed=$$? ;\
		if test x$$failed = x0; then \
			echo "=== PASS: $$prg ===" ;\
		else \
			echo "=== FAIL: $$prg (rc=$$failed) ===" ;\
		fi ;\
	done

install:

clean:
	-rm -f *.o $(PROGRAMS) $(TEST_PROGRAMS) $(TEST_PROGRAMS_NORUN)


.PHONY: install clean
