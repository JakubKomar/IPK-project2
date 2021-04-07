/*
autor:          Jakub Komárek
login:          xkomar33
description:    IPK projekt2-snifer paketů
*/
#include <iostream>
#include <pcap.h>
#include<stdio.h>
#include<ctype.h>
#include<stdlib.h>
#include <string> 
#include <string.h>

using namespace std;

int safeStoi(string String){
    int number=0;
    try{
       number=stoi(String);
    }
    catch(const std::exception& e){
        cerr<<"String to Int converzion err\n";
        exit(-1);
    }
    return number;
}

int main(int argc, char **argv) 
{
    string interface="";
    int port=-1,n=-1;
    bool tcp=false, udp=false,arp=false,icmp=false;

    for(int i=1;i<argc;i++){
        if(!(strcmp(argv[i],"--tcp"))||!(strcmp(argv[i],"-t")))
            tcp=true;
        else if(!(strcmp(argv[i],"--udp"))||!(strcmp(argv[i],"-u")))
            udp=true;
        else if(!(strcmp(argv[i],"--icmp")))
            icmp=true;
        else if(!(strcmp(argv[i],"--arp")))
            arp=true;
        else if(!(strcmp(argv[i],"-n"))){
            if(i+1<argc)
                n=safeStoi(argv[i+1]);
            else{
                cerr<<"Missing value after arg, try --help\n";
                exit(-1);
            }
            i++;
        }
        else if(!(strcmp(argv[i],"-i"))||!(strcmp(argv[i],"--interface"))){
            if(i+1<argc)
                interface=argv[i+1];
            else{
                cerr<<"Missing value after arg, try --help\n";
                exit(-1);
            }
            i++;
        }
        else if(!(strcmp(argv[i],"-p"))){
            if(i+1<argc)
                port=safeStoi(argv[i+1]);
            else{
                cerr<<"Missing value after arg, try --help\n";
                exit(-1);
            }
            i++;
        }
        else if(!(strcmp(argv[i],"-h"))||!(strcmp(argv[i],"--help"))){
            cerr<<"Help\n";
            exit(-1);
        }
        else{
            cerr<<"Unrecognizeble parameter, try --help\n";
            exit(-1);
        }
    }
    cout<<"tcp:"<<tcp<<"\n";
    cout<<"udp:"<<udp<<"\n";
    cout<<"arp:"<<arp<<"\n";
    cout<<"icmp:"<<icmp<<"\n";
    cout<<"port:"<<port<<"\n";
    cout<<"interface:"<<interface<<"\n";
    cout<<"n:"<<n<<"\n";
    return 0;
}