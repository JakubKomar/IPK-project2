/*
autor:          Jakub Komárek
login:          xkomar33
description:    IPK projekt2-snifer paketů
*/
#include "main.h"

bool d=false;   //debug var
pcap_t *handle=NULL; //ukazatel popisovač interfacu
int main(int argc, char **argv) 
{
    signal(SIGINT, userExit);signal(SIGTERM, userExit); //připojení ukončujícíhc signálů

    string interface="";    //rozhraní na kterém se bude zachytávat
    int port=-1,n=1;        //port pro zachytávání, počet paketů na zachycení 
    bool tcp=false, udp=false,arp=false,icmp=false; //jaké protokoly se budou zachytávat
    argParste(&udp,&tcp,&arp,&icmp,&interface,&n,&port,argc,argv);  //parsování vstupních argumentů
    if(interface=="")       //pokud není zadán interface, vypíšou se dostupné interfacy
        displayInterfaces();
    
    char errbuf[PCAP_ERRBUF_SIZE];      
    bpf_u_int32 mask;		//mask of interface
	bpf_u_int32 net;		//ip of interface

    if (pcap_lookupnet(interface.c_str(), &net, &mask, errbuf))
        error(4,"Couldn't get netmask/ip for device\n");

    handle= pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf); 
	if (handle == NULL) 
        error(4,"Couldn't open nework interface\n");

    string filter_exp=filterGen(port,tcp,udp,arp,icmp);     //generování filtru
    struct bpf_program fp;	
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, mask))//spracování filtru 
        error(3,"Couldn't parse filter\n");

    if (pcap_setfilter(handle, &fp))
        error(2,"Couldn't install filter\n");

    for(int i=0;i<n;i++){
        sniffPacket();
    }
	pcap_close(handle);
    return 0;
}
void sniffPacket(){
    struct pcap_pkthdr header;
    const u_char *packet = pcap_next(handle, &header);  //získání

    const struct ether_header *ethernet;
    ethernet= (struct ether_header*)(packet);
    
    RFC3339();  //výpis času
    switch (ntohs(ethernet->ether_type)){
        case 0x0800:    //ipv4
            debug("ipv4\n");
            const struct ip *ip;
            ip = (struct ip*)(packet + SIZE_ETHERNET);
            switch (ip->ip_p){
                case 0x01:
                    debug("icmp packet\n");
                    cout<<inet_ntoa(ip->ip_src)<<" > "<<inet_ntoa(ip->ip_dst);
                    break;
                case 0x11:
                    debug("udp packet\n");
                    const struct udphdr *udpH;
                    udpH = (struct udphdr*)(packet + SIZE_ETHERNET+(ip->ip_hl)*4);
                    cout<<inet_ntoa(ip->ip_src)<<" : "<<ntohs(udpH->uh_sport)<<" > "<<inet_ntoa(ip->ip_dst)<<" : "<<ntohs(udpH->uh_dport);
                    break;
                case 0x06:
                    debug("tcp packet\n");
                    const struct tcphdr *tcpH;
                    tcpH = (struct tcphdr*)(packet + SIZE_ETHERNET+(ip->ip_hl)*4);
                    cout<<inet_ntoa(ip->ip_src)<<" : "<<ntohs(tcpH->th_sport)<<" > "<<inet_ntoa(ip->ip_dst)<<" : "<<ntohs(tcpH->th_dport);
                    break;    
                default:
                    cerr<<"unsuported protokol, snifing next packet...\n";
                    return;break;
            }                     
            break;
        case 0x86DD:    //ipv6
            debug("ipv6 packet\n");
            const struct ip6_hdr *ip6;
            ip6 = (struct ip6_hdr*)(packet + SIZE_ETHERNET);
                                
            break;
        case 0x0806:    //arp
            debug("arp packet\n");
            break;
        default:
            cout<<"unsuported packet type, snifing next packet...\n";
            return;
            break;
    }
    cout<<", length "<<header.caplen<<" bytes\n";
    for(int j=0;j<header.caplen/16+((header.caplen%16)&&1);j++)   //přičte se jendička pokud je zbytek po celočíselném dělení
    {
        printf("x%04x: ",j*16);         //výpis ofsetu
        string assci;                   //řetězec pro assci zápis
        for (int i=0;i<16;i++){         
            int index=j*16+i;
            if(index>=header.caplen)    //ukončující podmínka
                break;
            printf("%02x ",int(packet[index])); //výpis hexadecimální číslice z paketu
            assci.push_back(packet[index]>20&&packet[index]<127?packet[index]:'.'); //uložení hexadecomálního zápisu-pokud je znak netisknutelný ukládá se tečka
        }
        cout<<assci<<"\n";  //výpis ascci reprezentace
        if(j==0||j==2)
            cout<<"\n";
    }
    cout<<"\n";     
}
string filterGen(int port,bool tcp,bool udp,bool arp,bool icmp){        //generuje filter pro zachytávač paketů, podle vstupních argumentů
    string filter_exp;
    if(port>0&&port<65535)
    {
        filter_exp="port "+to_string(port)+" and ";
    }
    if (tcp||udp||arp||icmp)
    {
         filter_exp=filter_exp+"(";
        if(tcp)
            filter_exp=filter_exp+"tcp";
        if(udp){
            if(tcp)
                filter_exp=filter_exp+" or udp";
            else 
                filter_exp=filter_exp+"udp";
        }
        if(arp){
            if(tcp||udp)
                filter_exp=filter_exp+" or arp";
            else 
                filter_exp=filter_exp+"arp";
        }
        if(icmp){
            if(tcp||udp||arp)
                filter_exp=filter_exp+" or icmp";
            else 
                filter_exp=filter_exp+"icmp";
        }
        filter_exp=filter_exp+")";
    }
    else
    {
        filter_exp=filter_exp+"(tcp or udp or arp or icmp)";
    }
    debug("filtering exp::\n"+filter_exp+"\n---------------------------------\n");
    return filter_exp;
}
void startSnifing(){

}
void displayInterfaces(){       //vypisuje všechna dostupné interfacy
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, error_buffer) < 0) {
        cerr<<"Error in pcap_findalldevs()";
        exit(-1);
    }
    int i = 1;
    pcap_if_t *temp;
    cout<<"Active network interfaces: \n";
    for (temp = alldevs; temp!=NULL; temp = temp->next) {
        printf("%-2d:%s\n", i++, temp->name);
    }
    pcap_freealldevs(alldevs);
    exit(0);
}

int safeStoi(string String){        //bezpečná funkce pro převod stringu na int
    int number=0;
    try{
       number=stoi(String);
    }
    catch(const std::exception& e){
        error(2,"String to Int converzion err\n");
    }
    return number;
}
void debug(string masegge){     //pokud je globální proměnná d nastavená na true tiskne debugovací výpisy na stderr
    if(d){cerr<<masegge;}
}
void argParste(bool *udp,bool *tcp,bool *arp,bool *icmp,string *interface,int *n,int *port,int argc,char **argv)    //funkce na parsování argmuntů
{
    bool I=false;
    for(int i=1;i<argc;i++){
        if(!(strcmp(argv[i],"--tcp"))||!(strcmp(argv[i],"-t")))
            *tcp=true;
        else if(!(strcmp(argv[i],"--udp"))||!(strcmp(argv[i],"-u")))
            *udp=true;
        else if(!(strcmp(argv[i],"--icmp")))
            *icmp=true;
        else if(!(strcmp(argv[i],"--arp")))
            *arp=true;
        else if(!(strcmp(argv[i],"-n"))){
            if(i+1<argc)
                *n=safeStoi(argv[i+1]);
            else{
                error(1,"Missing value after arg, try --help\n");
            }
            i++;
        }
        else if(!(strcmp(argv[i],"-i"))||!(strcmp(argv[i],"--interface"))){
            I=true;
            if(i+1<argc)
                *interface=argv[i+1];
            else{
                break;
            }
            i++;
        }
        else if(!(strcmp(argv[i],"-p"))){
            if(i+1<argc)
                *port=safeStoi(argv[i+1]);
            else{
                error(1,"Missing value after arg, try --help\n");
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
            error(1,"Unrecognizeble parameter, try --help\n");
        }
    }
    if(!I)
    {
        error(1,"Missing interface parameter\n");
    }
    debug("program runed whith this params:\n");
    debug("tcp:"+std::to_string(*tcp)+"\n");
    debug("udp:"+std::to_string(*udp)+"\n");
    debug("arp:"+std::to_string(*arp)+"\n");
    debug("icmp:"+std::to_string(*icmp)+"\n");
    debug("port:"+std::to_string(*port)+"\n");
    debug("interface:"+*interface+"\n");
    debug("n:"+std::to_string(*n)+"\n");
    debug("---------------------------------\n");
}
void RFC3339(){     //vypíše časové razítko v RFC3339 formátu
    time_t timer = time(0);
    tm * tm_info = localtime(&timer);
    struct timeval tp;  
    gettimeofday(&tp, NULL);    //čas v ms 
    int ms = tp.tv_usec / 1000;

    printf("%d-%02d-%02d-T%02d:%02d:%02d.%03d ",tm_info->tm_year+1900,tm_info->tm_mon+1,tm_info->tm_mday,tm_info->tm_hour,tm_info->tm_min,tm_info->tm_sec,ms);
    int timezone=(tm_info->tm_hour)-(gmtime(&timer)->tm_hour);  //výpočet časového posunu
    printf("%s%02d:00 ",timezone>0?"+":"-",abs(timezone));
}
void userExit(int signum ){     //pokud uživatel násilně ukončí program
    pcap_close(handle);
    exit(0);
}
void error(int errCode,string massege){ //funkce pro výpis chyby a ukončení programu
    if(handle)
        pcap_close(handle);
    cerr<<massege;
    exit(errCode);
}