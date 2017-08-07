include ../common.mak

ALL_CFLAGS += -D_FILE_OFFSET_BITS=64

lib = libzds.a

all: $(lib)

objects = libzds.o

$(lib): $(objects)

install: all

clean:
	rm -f *.o $(lib)

.PHONY: all install clean
