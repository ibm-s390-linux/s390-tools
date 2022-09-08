include ../common.mak

lib = libap.a

check-dep-json:
	touch check-dep-json
ifneq (${HAVE_JSONC},0)
	$(call check_dep, \
		"libap", \
		"json-c/json.h", \
		"json-c-devel", \
		"HAVE_JSONC=0")
ALL_CPPFLAGS += -DHAVE_JSONC
endif

all: $(lib)
objects = ap.o

$(lib): $(objects)

$(objects): check-dep-json

install: all

clean:
	rm -f *.o check-dep-lock check-dep-json $(lib)
