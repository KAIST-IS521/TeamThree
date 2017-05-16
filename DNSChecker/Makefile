CFLAGS = -Wall
BUILDDIR = ../build

all: $(BUILDDIR)/DNSChecker

$(BUILDDIR)/DNSChecker: DNSChecker.c
	$(CC) $(CFLAGS) -o$@ $<
				
clean:
	rm -rf $(BUILDDIR)

.PHONY: all clean

