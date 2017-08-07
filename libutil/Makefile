include ../common.mak

lib = libutil.a

examples =	util_base_example \
		util_panic_example \
		util_path_example \
		util_scandir_example \
		util_file_example \
		util_libc_example \
		util_opt_example \
		util_opt_command_example \
		util_prg_example \
		util_rec_example

all: $(lib) $(examples)

objects =	util_base.o \
		util_path.o \
		util_scandir.o \
		util_file.o \
		util_libc.o \
		util_list.o \
		util_opt.o \
		util_panic.o \
		util_part.o \
		util_prg.o \
		util_proc.o \
		util_rec.o

util_base_example: util_base_example.o $(rootdir)/libutil/libutil.a
util_panic_example: util_panic_example.o $(rootdir)/libutil/libutil.a
util_path_example: util_path_example.o $(rootdir)/libutil/libutil.a
util_scandir_example: util_scandir_example.o $(rootdir)/libutil/libutil.a
util_file_example: util_file_example.o $(rootdir)/libutil/libutil.a
util_libc_example: util_libc_example.o $(rootdir)/libutil/libutil.a
util_opt_example: util_opt_example.o $(rootdir)/libutil/libutil.a
util_opt_command_example: util_opt_command_example.o $(rootdir)/libutil/libutil.a
util_panic_example: util_panic_example.o $(rootdir)/libutil/libutil.a
util_prg_example: util_prg_example.o $(rootdir)/libutil/libutil.a
util_rec_example: util_rec_example.o $(rootdir)/libutil/libutil.a

$(lib): $(objects)

install: all

clean:
	rm -f *.o $(lib) $(examples)
