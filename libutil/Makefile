include ../common.mak
include ../common_autocomp.mak

lib := libutil.a

sources := $(filter-out %_example.c %_host.c, $(wildcard *.c))
objects := $(patsubst %.c,%.o,$(sources))

autocomp-object := util_autocomp_host.o

examples := $(patsubst %.c,%,$(wildcard *_example.c))

all: $(lib) $(autocomp-object)
examples: $(examples)

$(examples): %: %.o $(lib)

$(lib): $(objects)
$(lib): ALL_CFLAGS += -fPIC

install: all

clean:
	rm -f *.o $(lib) $(examples)
