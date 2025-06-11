LDLIBS=-lpcap

all: tls-block

main.o: libnet.h mac.h ip.h ethhdr.h main.cpp

block.o: libnet.h block.h block.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

iphdr.o: ip.h iphdr.h iphdr.cpp

tcphdr.o: tcphdr.h tcphdr.cpp

tlshdr.o: tlshdr.h tlshdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

tls-block: main.o block.o ethhdr.o iphdr.o tcphdr.o tlshdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tls-block *.o
