include ../common.mak

lib = libvmcp.a

examples = vmcp_example

all: $(lib) $(examples)

objects = vmcp.o

$(lib): $(objects)

install: all

vmcp_example: vmcp_example.o $(lib) $(rootdir)/libutil/libutil.a

clean:
	rm -f *.o $(lib) $(examples)
