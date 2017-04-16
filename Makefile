# Note: uses GNU Make features

CXXFLAGS ?= -Wall -Wextra -pedantic -O2 -Wno-unused-parameter
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SBINDIR ?= $(PREFIX)/sbin
MANDIR ?= $(PREFIX)/share/man
ENABLE_MAN ?= yes

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
BUILD_TARGETS := build-bin $(BUILD_MAN_TARGETS-$(ENABLE_MAN))

build: $(BUILD_TARGETS)

build-bin: $(PROGRAMS)

rdiscd: rdiscd.o $(DAEMON_OBJFILES) $(COMMON_OBJFILES)
	$(CXX) $(CXXFLAGS) -o $@ rdiscd.o $(DAEMON_OBJFILES) $(COMMON_OBJFILES) $(LDFLAGS) $(LIBNDP_LIBS)

rdiscd-mkaddress: rdiscd-mkaddress.o $(DAEMON_OBJFILES) $(COMMON_OBJFILES)
	$(CXX) $(CXXFLAGS) -o $@ rdiscd-mkaddress.o $(DAEMON_OBJFILES) $(COMMON_OBJFILES) $(LDFLAGS) $(LIBNDP_LIBS)

rdiscmon: rdiscmon.o $(COMMON_OBJFILES)
	$(CXX) $(CXXFLAGS) -o $@ rdiscmon.o $(COMMON_OBJFILES) $(LDFLAGS) $(LIBNDP_LIBS)

build-man:

#
# Clean
#
CLEAN_MAN_TARGETS-yes = clean-man
CLEAN_MAN_TARGETS-no =
CLEAN_TARGETS := clean-bin $(CLEAN_MAN_TARGETS-$(ENABLE_MAN))

clean: $(CLEAN_TARGETS)

clean-bin:
	rm -f *.o $(PROGRAMS)

clean-man:

#
# Install
#
INSTALL_MAN_TARGETS-yes = install-man
INSTALL_MAN_TARGETS-no =
INSTALL_TARGETS := install-bin $(INSTALL_MAN_TARGETS-$(ENABLE_MAN))

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

.PHONY: all build clean install
