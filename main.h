/*
autor:          Jakub Komárek
login:          xkomar33
description:    IPK projekt2-snifer paketů
*/
#include <iostream>         
#include <stdio.h>
#include <string> 
#include <string.h> 
#include <signal.h>
#include <time.h>               //čas
#include <sys/time.h>           //čas v ms

#include <pcap.h>               //knihovna pro zachytávání paketů
#include <netinet/ether.h>      //výpis mac
#include <netinet/if_ether.h>   //struktury pro ethernotovou hlavičku
#include <netinet/ip.h>         //struktury pro IPv4 hlavičku
#include <netinet/ip6.h>        //struktury pro IPv6 hlavičku
#include <netinet/tcp.h>        //struktury pro tcp hlavičku
#include <netinet/udp.h>        //struktury pro udp hlavičku
#include <netinet/ip_icmp.h>    //struktury pro icmp hlavičku




using namespace std;




#define SIZE_ETHERNET 14        //bytová délka ethernetové hlavičky
#define SIZE_IP6 36             //bytová délka záklaní ipv6 hlavičky

int safeStoi(string String);
void debug(string masegge);
void displayInterfaces();
void userExit(int signum);
void startSnifing();
void sniffPacket();
string filterGen(int port,bool tcp,bool udp,bool arp,bool icmp,bool ipv4,bool ipv6);
void argParste(bool *udp,bool *tcp,bool *arp,bool *icmp,string *interface,int *n,int *port,int argc,char **argv,bool *ipv4,bool *ipv6);
void error(int errCode,string massege);
void RFC3339();
