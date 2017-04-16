# Note: uses GNU Make features

CXXFLAGS ?= -Wall -Wextra -pedantic -O2 -Wno-unused-parameter
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SBINDIR ?= $(PREFIX)/sbin
MANDIR ?= $(PREFIX)/share/man
ENABLE_MAN ?= yes
ENABLE_IFUPDOWN ?= no

# libndp
LIBNDP_CFLAGS ?= $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --cflags libndp)
LIBNDP_LIBS ?= $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --libs libndp)

# CXXFLAGS and LDFLAGS
CXXFLAGS += -std=c++11
CXXFLAGS += $(LIBNDP_CFLAGS)
LDFLAGS += -lrt

# Files
PROGRAMS = rdiscd rdiscd-mkaddress rdiscmon
COMMON_OBJFILES = rdisc.o util.o
DAEMON_OBJFILES = sha256.o rfc7217.o

all: build

#
# Build
#
BUILD_MAN_TARGETS-yes = build-man
BUILD_MAN_TARGETS-no =
BUILD_IFUPDOWN_TARGETS-yes = build-ifupdown
BUILD_IFUPDOWN_TARGETS-no =
BUILD_TARGETS := build-bin $(BUILD_MAN_TARGETS-$(ENABLE_MAN)) $(BUILD_IFUPDOWN_TARGETS-$(ENABLE_IFUPDOWN))

build: $(BUILD_TARGETS)

build-bin: $(PROGRAMS)

rdiscd: rdiscd.o $(DAEMON_OBJFILES) $(COMMON_OBJFILES)
	$(CXX) $(CXXFLAGS) -o $@ rdiscd.o $(DAEMON_OBJFILES) $(COMMON_OBJFILES) $(LDFLAGS) $(LIBNDP_LIBS)

rdiscd-mkaddress: rdiscd-mkaddress.o $(DAEMON_OBJFILES) $(COMMON_OBJFILES)
	$(CXX) $(CXXFLAGS) -o $@ rdiscd-mkaddress.o $(DAEMON_OBJFILES) $(COMMON_OBJFILES) $(LDFLAGS) $(LIBNDP_LIBS)

rdiscmon: rdiscmon.o $(COMMON_OBJFILES)
	$(CXX) $(CXXFLAGS) -o $@ rdiscmon.o $(COMMON_OBJFILES) $(LDFLAGS) $(LIBNDP_LIBS)

build-man:

build-ifupdown:

#
# Clean
#
CLEAN_MAN_TARGETS-yes = clean-man
CLEAN_MAN_TARGETS-no =
CLEAN_IFUPDOWN_TARGETS-yes = clean-ifupdown
CLEAN_IFUPDOWN_TARGETS-no =
CLEAN_TARGETS := clean-bin $(CLEAN_MAN_TARGETS-$(ENABLE_MAN)) $(CLEAN_IFUPDOWN_TARGETS-$(ENABLE_IFUPDOWN))

clean: $(CLEAN_TARGETS)

clean-bin:
	rm -f *.o $(PROGRAMS)

clean-man:

clean-ifupdown:

#
# Install
#
INSTALL_MAN_TARGETS-yes = install-man
INSTALL_MAN_TARGETS-no =
INSTALL_IFUPDOWN_TARGETS-yes = install-ifupdown
INSTALL_IFUPDOWN_TARGETS-no =
INSTALL_TARGETS := install-bin $(INSTALL_MAN_TARGETS-$(ENABLE_MAN)) $(INSTALL_IFUPDOWN_TARGETS-$(ENABLE_IFUPDOWN))

install: $(INSTALL_TARGETS)

install-bin: build-bin
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 rdiscd-mkaddress $(DESTDIR)$(BINDIR)/
	install -d $(DESTDIR)$(SBINDIR)
	install -m 755 rdiscd $(DESTDIR)$(SBINDIR)/
	install -m 755 rdiscd-keygen $(DESTDIR)$(SBINDIR)/
	install -m 755 rdiscmon $(DESTDIR)$(SBINDIR)/

install-man: build-man
	install -d $(DESTDIR)$(MANDIR)/man8
	install -m 644 rdiscd.8 $(DESTDIR)$(MANDIR)/man8/
	install -m 644 rdiscd-keygen.8 $(DESTDIR)$(MANDIR)/man8/
	install -m 644 rdiscmon.8 $(DESTDIR)$(MANDIR)/man8/

install-ifupdown: build-ifupdown
	install -d $(DESTDIR)/etc/network/if-post-down.d
	install -m 755 rdiscd.if-post-down $(DESTDIR)/etc/network/if-post-down.d/000-rdiscd
	install -d $(DESTDIR)/etc/network/if-pre-up.d
	install -m 755 rdiscd.if-pre-up $(DESTDIR)/etc/network/if-pre-up.d/zzz-rdiscd

.PHONY: all \
	build build-bin build-man build-ifupdown \
	clean clean-bin clean-man clean-ifupdown \
	install install-bin install-man install-ifupdown
