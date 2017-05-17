BUILDDIR = build   
subdir = DNSChecker         #The name of the subdirectory you want to build
subdir = web

all: $(BUILDDIR) $compile 

$(BUILDDIR):
	@echo "Building system..."
	mkdir -p $@

$compile:	
	$(foreach dir, $(subdir), cd $(dir) && make; cd ..;)
clean:
	rm -rf $(BUILDDIR)


.PHONY: all clean
