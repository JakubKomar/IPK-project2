all: main.cpp 
	g++ main.cpp -o ipk-sniffer -lpcap

clean: 
	$(RM) ipk-sniffer