include ../common.mak

ifeq (${HAVE_NCURSES},0)

all:
	$(SKIP) HAVE_NCURSES=0

install:
	$(SKIP) HAVE_NCURSES=0

else

check_dep:
	$(call check_dep, \
		"hyptop", \
		"ncurses.h", \
		"ncurses-devel or libncurses-dev", \
		"HAVE_NCURSES=0")

LDLIBS += -lncurses

all: check_dep hyptop

OBJECTS = hyptop.o opts.o helper.o \
	  sd_core.o sd_sys_items.o sd_cpu_items.o \
	  tbox.o table.o table_col_unit.o \
	  dg_debugfs.o dg_debugfs_lpar.o dg_debugfs_vm.o dg_debugfs_vmd0c.o \
	  win_sys_list.o win_sys.o win_fields.o \
	  win_cpu_types.o win_help.o nav_desc.o

hyptop: $(OBJECTS) $(rootdir)/libutil/libutil.a

install: all
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 hyptop \
		$(DESTDIR)$(USRSBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 hyptop.8 \
		$(DESTDIR)$(MANDIR)/man8

endif

clean:
	rm -f *.o *~ hyptop core

.PHONY: all install clean check_dep
