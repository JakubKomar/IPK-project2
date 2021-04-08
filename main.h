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
string dec2Ip(int dec);
string filterGen(int port,bool tcp,bool udp,bool arp,bool icmp);


	/* Ethernet header */
	struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
	};