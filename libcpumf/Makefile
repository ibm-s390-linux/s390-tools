include ../common.mak

lib = libcpumf.a

examples = libcpumf_example

all: $(lib)
examples: $(lib) $(examples)

objects = libcpumf_pmutype.o libcpumf_cpuset.o libcpumf_support.o \
	  libcpumf_ctrset.o

$(lib): $(objects)

install: all

libcpumf_example: libcpumf_example.o $(lib) $(rootdir)/libutil/libutil.a

clean:
	rm -f *.o $(lib) $(examples)
