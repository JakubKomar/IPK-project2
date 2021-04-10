# build an executable named myprog from myprog.c
all: main.cpp 
	g++ main.cpp -o program -lpcap

clean: 
	$(RM) program