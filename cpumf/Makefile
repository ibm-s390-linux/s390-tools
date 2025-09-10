include ../common.mak

BIN_FILES = lscpumf chcpumf lshwc pai lspai
MAN_FILES = lscpumf.8 chcpumf.8 lshwc.8 pai.8 lspai.8

zsh-completions := $(addprefix _,$(BIN_FILES))
bash-completions := $(addsuffix .bash,$(BIN_FILES))

include ../common_autocomp.mak

all: $(BIN_FILES)

libs =	$(rootdir)/libcpumf/libcpumf.a $(rootdir)/libutil/libutil.a

lscpumf: lscpumf.o $(libs)
chcpumf: chcpumf.o $(libs)
lshwc: lshwc.o $(libs)
pai: pai.o $(libs)
lspai: lspai.o $(libs)

install: all install-man
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man8
	for binf in $(BIN_FILES); do \
	 $(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 $$binf $(DESTDIR)$(BINDIR); \
	done

clean:
	rm -f *.o *~ $(BIN_FILES) core

install-man:
	for man in $(MAN_FILES); do \
		$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 man/$$man \
		$(DESTDIR)$(MANDIR)/man8 ; \
	done

.PHONY: all install clean
