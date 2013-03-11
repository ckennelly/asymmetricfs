CC=clang
CXX=clang
RM=rm
WARNINGS := -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-align \
			-Wwrite-strings -Wmissing-declarations -Wredundant-decls \
			-Winline -Wno-long-long -Wuninitialized -Wconversion -Werror
CWARNINGS := $(WARNINGS) -Wmissing-prototypes -Wnested-externs -Wstrict-prototypes
CXXWARNINGS := $(WARNINGS) -Wabi -Wnon-virtual-dtor
CFLAGS := -g -fPIC -std=c11 $(CWARNINGS)
CXXFLAGS := -g -std=c++11 $(CXXWARNINGS)
LDFLAGS := -lfuse -lboost_thread -lboost_program_options

SRCOBJS := $(patsubst %.cpp,%.o,$(wildcard *.cpp)) $(patsubst %.c,%.o,$(wildcard *.c))

all: asymmetricfs

asymmetricfs: $(SRCOBJS)
	$(CXX) -o $@ $^ $(LDFLAGS)

# Blindly depend on all headers
%.o: %.c Makefile  $(wildcard *.h)
	$(CC) $(CFLAGS) -fPIC -MMD -MP -c $< -o $@

%.o: %.cpp Makefile $(wildcard *.h)
	$(CXX) $(CXXFLAGS) -fPIC -MMD -MP -c $< -o $@

test: asymmetricfs
	$(MAKE) -C test

clean:
	-$(RM) -f $(SRCOBJS) $(patsubst %.o,%.d,$(SRCOBJS)) asymmetricfs

.PHONY: all clean
