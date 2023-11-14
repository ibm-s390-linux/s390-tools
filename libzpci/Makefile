include ../common.mak

lib = libzpci.a

all: $(lib)

objects = pci_list.o

examples := $(patsubst %.c,%,$(wildcard *_example.c))

examples: $(examples)
$(examples): %: %.o $(lib) $(rootdir)/libutil/libutil.a

$(lib): ALL_CFLAGS += -fPIC -std=c11
$(lib): $(objects)

install: all

clean:
	rm -f *.o $(lib) $(examples)
