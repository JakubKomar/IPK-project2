/*
autor:          Jakub Komárek
login:          xkomar33
description:    IPK projekt2-snifer paketů
*/
#include "main.h"

bool d=false;   //debug var

int main(int argc, char **argv) 
{
    string interface="";
    int port=-1,n=-1;
    bool I=false,tcp=false, udp=false,arp=false,icmp=false;

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
            I=true;
            if(i+1<argc)
                interface=argv[i+1];
            else{
                break;
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
        else if(!(strcmp(argv[i],"-d"))){
            d=true;
        }
        else if(!(strcmp(argv[i],"-h"))||!(strcmp(argv[i],"--help"))){
            cerr<<"./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n";
            exit(-1);
        }
        else{
            cerr<<"Unrecognizeble parameter, try --help\n";
            exit(-1);
        }
    }
    if(!I)
    {
        cerr<<"Missing interface parameter\n";
        exit(-1);
    }
    debug("program runed whith this params:\n");
    debug("tcp:"+std::to_string(tcp)+"\n");
    debug("udp:"+std::to_string(udp)+"\n");
    debug("arp:"+std::to_string(arp)+"\n");
    debug("icmp:"+std::to_string(icmp)+"\n");
    debug("port:"+std::to_string(port)+"\n");
    debug("interface:"+interface+"\n");
    debug("n:"+std::to_string(n)+"\n");
    debug("---------------------------------\n");

    if(interface=="")
        displayInterfaces();


    return 0;
}
void displayInterfaces(){
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    /* Retrieve the device list from the local machine */
    if (pcap_findalldevs(&alldevs,errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }
    
    /* Print the list */
    for(d= alldevs; d != NULL; d= d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
    
    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return;
    }

    /* We don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);
    exit(0);
}

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
void debug(string masegge)
{
    if(d)
        cerr<<masegge;
}