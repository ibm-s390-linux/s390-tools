# Common definitions
include ../../common.mak

ALL_CPPFLAGS += -I ../include -std=gnu99 -Wno-unused-parameter \
	-Wno-missing-field-initializers

# Core
chzdev_objects += attrib.o chzdev.o device.o devnode.o devtype.o exit_code.o \
		  export.o hash.o inuse.o misc.o namespace.o opts.o path.o \
		  root.o select.o setting.o subtype.o table.o table_attribs.o \
		  table_types.o net.o

# Devtype Helpers
chzdev_objects += blkinfo.o ccw.o ccwgroup.o findmnt.o modprobe.o module.o \
		  udev.o udev_ccw.o udev_ccwgroup.o iscsi.o

# DASD devtype
chzdev_objects += dasd.o

# FCP devtype
chzdev_objects += zfcp.o zfcp_host.o
chzdev_objects += scsi.o udev_zfcp_lun.o zfcp_lun.o

# QETH devtype
chzdev_objects += nic.o qeth.o qeth_auto.o

# CTC devtype
chzdev_objects += ctc.o ctc_auto.o

# LCS devtype
chzdev_objects += lcs.o lcs_auto.o

# Generic CCW devtype
chzdev_objects += generic_ccw.o


# Core
lszdev_objects += attrib.o lszdev.o device.o devnode.o devtype.o exit_code.o \
		  export.o hash.o inuse.o misc.o namespace.o opts.o path.o \
		  root.o select.o setting.o subtype.o table.o table_types.o \
		  net.o

# Devtype Helpers
lszdev_objects += blkinfo.o ccw.o ccwgroup.o findmnt.o modprobe.o module.o \
		  udev.o udev_ccw.o udev_ccwgroup.o iscsi.o

# DASD devtype
lszdev_objects += dasd.o

# FCP devtype
lszdev_objects += zfcp.o zfcp_host.o
lszdev_objects += scsi.o udev_zfcp_lun.o zfcp_lun.o

# QETH devtype
lszdev_objects += nic.o qeth.o qeth_auto.o

# CTC devtype
lszdev_objects += ctc.o ctc_auto.o

# LCS devtype
lszdev_objects += lcs.o lcs_auto.o

# Generic CCW devtype
lszdev_objects += generic_ccw.o

all: chzdev lszdev

chzdev_usage.c: chzdev_usage.txt
	$(SED) $< >$@ -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/^/"/g' \
		      -e 's/$$/\\n"/g'

.chzdev.o.d: chzdev_usage.c

lszdev_usage.c: lszdev_usage.txt
	$(SED) $< >$@ -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/^/"/g' \
		      -e 's/$$/\\n"/g'

.lszdev.o.d: lszdev_usage.c

chzdev.o: chzdev_usage.c
lszdev.o: lszdev_usage.c

libs = $(rootdir)/libutil/libutil.a

chzdev: $(chzdev_objects) $(libs)
lszdev: $(lszdev_objects) $(libs)

install: chzdev
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR)
	$(INSTALL) -c chzdev $(DESTDIR)$(BINDIR)
	$(INSTALL) -c lszdev $(DESTDIR)$(BINDIR)
ifeq ($(HAVE_DRACUT),1)
	$(INSTALL) -m 755 zdev-root-update.dracut \
		$(DESTDIR)$(TOOLS_LIBDIR)/zdev-root-update
endif

clean:
	@rm -f *.o chzdev lszdev chzdev_usage.c lszdev_usage.c gmon.out *.gcda *.gcno

.PHONY: all install clean
