#include <iostream>
#include <pcap.h>
#include <libnet.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string> 
#include <string.h> 
#include <signal.h>
using namespace std;

int safeStoi(string String);
void debug(string masegge);
void displayInterfaces();
void userExit(int signum);
void startSnifing();