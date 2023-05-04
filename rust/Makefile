include ../common.mak
SHELL := /bin/bash
HAVE_CARGO ?= 1

INSTALL_TARGETS := skip-build
BUILD_TARGETS := skip-build
CARGO_TARGETS :=
CARGO_TEST_TARGETS :=

ifneq (${HAVE_CARGO},0)
	CARGO_TARGETS :=

	BUILD_TARGETS = $(CARGO_TARGETS)
	INSTALL_TARGETS := install-rust-tools install-man
	CARGO_TEST_TARGETS = $(addsuffix, _test, $(CARGO_TARGETS))

endif

# build release targets by default
ifeq ("${D}","0")
	ALL_CARGOFLAGS += --release
endif

# the cc crate uses these variables to compile c code. It does not open a shell
# to call the compiler, so no echo etc. allowed here, just a path to a program
$(BUILD_TARGETS) rust-test: CC = $(CC_SILENT)
$(BUILD_TARGETS) rust-test: AR = $(AR_SILENT)

$(CARGO_TARGETS): .check-cargo .no-cross-compile
	$(CARGO_BUILD) --manifest-path=$@/Cargo.toml $(ALL_CARGOFLAGS)
.PHONY: $(CARGO_TARGETS)


$(CARGO_TEST_TARGETS): .check-cargo .no-cross-compile
	$(CARGO_TEST) --manifest-path=$@/Cargo.toml --all-features $(CARGOFLAGS)
.PHONY: $(CARGO_TEST_TARGETS)

skip-build:
	echo "  SKIP    rust-tools due to unresolved dependencies"

all: $(BUILD_TARGETS)
install: $(INSTALL_TARGETS)

print-rust-targets:
	echo $(BUILD_TARGETS)

clean:
	$(foreach target,$(CARGO_TARGETS),\
		$(CARGO_CLEAN) --manifest-path=$(target)/Cargo.toml ${ALL_CARGOFLAGS} ;)
	$(RM) -- .check-dep-pvtools .detect-openssl.dep.c .check-cargo

rust-test: .check-cargo .no-cross-compile
	$(foreach target,$(CARGO_TEST_TARGETS),\
		$(CARGO_TEST) --manifest-path=$(target)/Cargo.toml --all-features ${ALL_CARGOFLAGS} ;)

install-rust-tools: $(BUILD_TARGETS)
	$(INSTALL) -d -m 755 $(DESTDIR)$(USRBINDIR)
	$(foreach target,$(CARGO_TARGETS),\
		$(INSTALL) $(target)/target/release/$(target) $(DESTDIR)$(USRBINDIR);)

install-man:
	$(foreach target,$(CARGO_TARGETS),\
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
