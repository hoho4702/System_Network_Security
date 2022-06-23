LDLIBS=-lpcap

all: tcp-block

tcp-block: main.o ethhdr.o iphdr.o ip.o tcphdr.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tcp-block *.o