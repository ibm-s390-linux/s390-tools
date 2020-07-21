include ../common.mak

ALL_CFLAGS += -D_FILE_OFFSET_BITS=64

ifneq (${HAVE_CURL},0)
ALL_CFLAGS += -DHAVE_CURL
endif

lib = libzds.a

all: $(lib)

objects = libzds.o

$(lib): $(objects)

install: all

clean:
	rm -f *.o $(lib)

.PHONY: all install clean
