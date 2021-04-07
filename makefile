# build an executable named myprog from myprog.c
all: main.cpp 
	g++ main.cpp -o program

clean: 
	$(RM) program