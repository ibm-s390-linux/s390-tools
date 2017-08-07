include ../common.mak

lib = libvmdump.a

all: $(lib)

objects = register_content.o dump.o lkcd_dump.o register_content.o \
	  vmdump_convert.o vm_dump.o

$(lib): $(objects)

install: all

clean:
	rm -f *.o $(lib)
