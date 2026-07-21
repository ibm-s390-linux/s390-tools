include ../common.mak
include ../common_autocomp.mak

lib := libutil.a

sources := $(filter-out %_example.c %_host.c, $(wildcard *.c))
objects := $(patsubst %.c,%.o,$(sources))

autocomp-object := util_autocomp_host.o

$(autocomp-object): $(autocomp-object:.o=.c)
	$(CC_FOR_BUILD) $(CFLAGS_FOR_BUILD) -I $(rootdir)/include -c $< -o $@

examples := $(patsubst %.c,%,$(wildcard *_example.c))

all: $(lib) $(autocomp-object)
examples: $(examples)

$(examples): %: %.o $(lib)

$(lib): $(objects)
$(lib): ALL_CFLAGS += -fPIC

install: all

clean:
	rm -f *.o $(lib) $(examples)
