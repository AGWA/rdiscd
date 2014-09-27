ifneq ($(DEB_HOST_GNU_TYPE),$(DEB_BUILD_GNU_TYPE))
# Cross compiling via dpkg-buildpackage
CXX = $(DEB_HOST_GNU_TYPE)-g++
endif

CXXFLAGS ?= -Wall -ansi -Wno-long-long -O2
CXXFLAGS += $(shell pkg-config --cflags libndp)
LDFLAGS += $(shell pkg-config --libs libndp)
LDFLAGS += -lrt

PROGRAMS = rdiscd rdiscmon
COMMON_OBJFILES = rdisc.o util.o
DAEMON_OBJFILES = sha2.o rfc7217.o

all: $(PROGRAMS)

rdiscd: rdiscd.o $(DAEMON_OBJFILES) $(COMMON_OBJFILES)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

rdiscmon: rdiscmon.o $(COMMON_OBJFILES)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o $(PROGRAMS)

.PHONY: all clean
