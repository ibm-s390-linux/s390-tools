include ../common.mak

lib = libu2s.a

all: $(lib)

objects = u2s.o

$(lib): $(objects) $(rootdir)/libutil/libutil.a

install: all

clean:
	rm -f *.o $(lib)
