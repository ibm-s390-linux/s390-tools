include ../common.mak

lib := libutil.a

sources := $(filter-out %_example.c,$(wildcard *.c))
objects := $(patsubst %.c,%.o,$(sources))

examples := $(patsubst %.c,%,$(wildcard *_example.c))

all: $(lib)
examples: $(examples)

$(examples): %: %.o $(lib)

$(lib): $(objects)
$(lib): ALL_CFLAGS += -fPIC

install: all

clean:
	rm -f *.o $(lib) $(examples)
