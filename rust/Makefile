include ../common.mak
HAVE_CARGO ?= 1
HAVE_OPENSSL ?= 1
HAVE_LIBCURL ?= 1

INSTALL_TARGETS := skip-build
BUILD_TARGETS := skip-build
PV_BUILD_TARGETS := skip-pv-build
CARGO_TARGETS :=
PV_TARGETS :=
CARGO_TEST_TARGETS :=

ifneq (${HAVE_CARGO},0)
	CARGO_TARGETS :=

	BUILD_TARGETS = $(CARGO_TARGETS)
	INSTALL_TARGETS := install-rust-tools install-man
	CARGO_TEST_TARGETS = $(addsuffix .test, $(CARGO_TARGETS))

ifeq ($(HOST_ARCH),s390x)
	CARGO_TARGETS += cpacfinfo
else
	BUILD_TARGETS += skip-cpacfinfo
endif #HOSTARCH

ifneq (${HAVE_OPENSSL},0)
ifneq (${HAVE_LIBCURL},0)
	PV_TARGETS := pvsecret pvattest

ifeq ($(HOST_ARCH),s390x)
	PV_TARGETS += pvapconfig
else
	BUILD_TARGETS += skip-pvapconfig
endif #HOSTARCH

	PV_BUILD_TARGETS := $(PV_TARGETS)
	CARGO_TEST_TARGETS += $(addsuffix .test,pv $(PV_TARGETS))
endif #LIBCURL
endif #OPENSSL
	TEST_TARGETS := $(addsuffix _build,$(CARGO_TEST_TARGETS))
endif #CARGO

pvimg-bootloaders:
	$(MAKE) -C pvimg/boot/
.PHONY: pvimg-bootloaders

BUILD_TARGETS += $(PV_BUILD_TARGETS) pvimg-bootloaders
INSTALL_TARGETS += pvimg-bootloaders

# build release targets by default
ifeq ("${D}","0")
	ALL_CARGOFLAGS += --release
endif

# the cc crate uses these variables to compile c code. It does not open a shell
# to call the compiler, so no echo etc. allowed here, just a path to a program
$(BUILD_TARGETS) $(TEST_TARGETS) rust-test: CC = $(CC_SILENT)
$(BUILD_TARGETS) $(TEST_TARGETS) rust-test: AR = $(AR_SILENT)

$(PV_TARGETS): .check-dep-pvtools
$(PV_TARGETS) $(CARGO_TARGETS): .check-cargo .no-cross-compile
	$(CARGO_BUILD) --bin $@ $(ALL_CARGOFLAGS)
.PHONY: $(PV_TARGETS) $(CARGO_TARGETS)

$(TEST_TARGETS): ALL_CARGOFLAGS += --no-run
$(CARGO_TEST_TARGETS) $(TEST_TARGETS): .check-cargo .no-cross-compile
	$(CARGO_TEST) --package $(basename $@) --all-features $(ALL_CARGOFLAGS)
.PHONY: $(TEST_TARGETS) $(CARGO_TEST_TARGETS)

skip-build:
	echo "  SKIP    rust-tools due to unresolved dependencies"

skip-pv-build:
	echo "  SKIP    rust-pv-tools due to unresolved dependencies"

skip-pvapconfig:
	echo "  SKIP    pvapconfig due to unsupported architecture (s390x only)"

skip-cpacfinfo:
	echo "  SKIP    cpacfinfo due to unsupported architecture (s390x only)"

all: $(BUILD_TARGETS)
install: $(INSTALL_TARGETS)
	$(INSTALL) -d -m 755 $(DESTDIR)$(USRBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 pvattest/tools/pvextract-hdr $(DESTDIR)$(USRBINDIR)
	$(MAKE) -C pvimg/boot install

print-rust-targets:
	echo $(BUILD_TARGETS)

clean:
ifneq (${HAVE_CARGO},0)
	$(CARGO_CLEAN) ${ALL_CARGOFLAGS}
endif # CARGO
	$(MAKE) -C pvimg/boot/ clean
	$(RM) -- .check-dep-pvtools .detect-openssl.dep.c .check-cargo

rust-test: $(CARGO_TEST_TARGETS)

install-rust-tools: $(BUILD_TARGETS)
	$(INSTALL) -d -m 755 $(DESTDIR)$(USRBINDIR)
	$(foreach target,$(CARGO_TARGETS),\
		$(INSTALL) target/release/$(target) $(DESTDIR)$(USRBINDIR);)
	$(foreach target,$(PV_TARGETS),\
		$(INSTALL) target/release/$(target) $(DESTDIR)$(USRBINDIR);)

install-man:
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man1
	$(foreach target,$(CARGO_TARGETS),\
		$(INSTALL) -m 644 $(target)/man/*.1 -t $(DESTDIR)$(MANDIR)/man1;)
	$(foreach target,$(PV_TARGETS),\
		$(INSTALL) -m 644 $(target)/man/*.1 -t $(DESTDIR)$(MANDIR)/man1;)

.PHONY: all install clean skip-build install-rust-tools print-rust-targets install-man rust-test

.check-cargo:
ifeq ($(shell command -v $(CARGO)),)
	$(call check_dep, \
		"rust/cargo", \
		"invalid-incl", \
		"cargo", \
		"HAVE_CARGO=0")
endif
	touch $@

.no-cross-compile:
ifneq ($(HOST_ARCH), $(BUILD_ARCH))
	$(error Cross compiling is not supported for rust code. Specify HAVE_CARGO=0 to disable rust compilation)
endif
.PHONY: .no-cross-compile

.detect-openssl.dep.c:
	echo "#include <openssl/evp.h>" > $@
	echo "#if OPENSSL_VERSION_NUMBER < 0x10101000L" >> $@
	echo "  #error openssl version 1.1.1 is required" >> $@
	echo "#endif" >> $@
	echo "static void __attribute__((unused)) test(void) {" >> $@
	echo "    EVP_MD_CTX *ctx = EVP_MD_CTX_new();" >> $@
	echo "    EVP_MD_CTX_free(ctx);" >> $@
	echo "}" >> $@

.check-dep-pvtools: .detect-openssl.dep.c
	$(call check_dep, \
		"Rust-pv", \
		$^, \
		"openssl-devel / libssl-dev version >= 1.1.1", \
		"HAVE_OPENSSL=0", \
		"-I.")
	$(call check_dep, \
		"Rust-pv", \
		"curl/curl.h", \
		"libcurl-devel", \
		"HAVE_LIBCURL=0")
	touch $@
