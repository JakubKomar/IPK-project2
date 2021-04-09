#include <iostream>
#include <pcap.h>
#include <libnet.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string> 
#include <string.h> 
#include <signal.h>
#include <time.h>
#include <sys/time.h>   
#include <sstream> 
#include <chrono>


#include <arpa/inet.h>          // inet_ntop()
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

using namespace std;
#define SIZE_ETHERNET 14







int safeStoi(string String);
void debug(string masegge);
void displayInterfaces();
void userExit(int signum);
void startSnifing();
string dec2Ip(int dec);
string filterGen(int port,bool tcp,bool udp,bool arp,bool icmp);
void argParste(bool *udp,bool *tcp,bool *arp,bool *icmp,string *interface,int *n,int *port,int argc,char **argv);
void error(int errCode,string massege);
void RFC3339();
