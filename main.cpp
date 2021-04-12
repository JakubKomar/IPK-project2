/*
autor:          Jakub Komárek
login:          xkomar33
description:    IPK projekt2-snifer paketů
*/
#include "main.h"

bool d=false;   //debugovací proměnná - povoluje výpisy ladících hlášení
pcap_t *handle=NULL; //ukazatel popisovač interfacu

int main(int argc, char **argv) 
{
    signal(SIGINT, userExit);signal(SIGTERM, userExit); //připojení ukončujícíh signálů

    string interface="";    //rozhraní na kterém se bude zachytávat
    int port=-1,n=1;        //port pro zachytávání, počet paketů na zachycení 
    bool tcp=false, udp=false,arp=false,icmp=false,ipv4=false,ipv6=false; //jaké protokoly se budou zachytávat
    argParste(&udp,&tcp,&arp,&icmp,&interface,&n,&port,argc,argv,&ipv4,&ipv6);  //parsování vstupních argumentů
    if(interface=="")       //pokud není zadán interface, vypíšou se dostupné interfacy
        displayInterfaces();
    
    char errbuf[PCAP_ERRBUF_SIZE];      

    bpf_u_int32 mask;		//maska rozehraní
	bpf_u_int32 net;		//ip rozehraní

    //proces otvírání interfacu je inspirován z výukové stránky https://www.tcpdump.org/pcap.html
    if (pcap_lookupnet(interface.c_str(), &net, &mask, errbuf))
        error(4,"Couldn't get netmask/ip for device\n");

    handle= pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf); 
	if (handle == NULL) 
        error(4,"Couldn't open nework interface\n");
    //konec inspirované části
    string filter_exp=filterGen(port,tcp,udp,arp,icmp,ipv4,ipv6);     //generování filtru
    struct bpf_program fp;	
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, mask))//zpracování filtru 
        error(3,"Couldn't parse filter\n");

    if (pcap_setfilter(handle, &fp))            //aplikace filtru
        error(2,"Couldn't install filter\n");

    for(int i=0;i<n;i++){
        sniffPacket();
    }
	pcap_close(handle);     //uvolnění popisovače
    return 0;
}
void sniffPacket(){
    struct pcap_pkthdr header;      
    const u_char *packet = pcap_next(handle, &header);  //získání paketu

    const struct ether_header *ethernet;        
    ethernet= (struct ether_header*)(packet);       //naplnění eternetové struktury (mac adressy a typ služby)
    
    RFC3339();  //výpis aktuálního času

    /*------------------------begin of ipv4 section---------------------------*/
    if(ntohs(ethernet->ether_type)==0x0800){
        debug("\nselector: ipv4\n");
        const struct ip *ip;
        ip = (struct ip*)(packet + SIZE_ETHERNET);
        switch (ip->ip_p){
            case 0x01:
                debug("\nprotokol selector: icmp packet\n");//icmp-nemá porty->výpis poouze ip adress
                cout<<inet_ntoa(ip->ip_src)<<" > "<<inet_ntoa(ip->ip_dst);
                break;
            case 0x11:
                debug("\nprotokol selector: udp packet\n");
                const struct udphdr *udpH;
                udpH = (struct udphdr*)(packet + SIZE_ETHERNET+(ip->ip_hl)*4);      //délka ipv4 hlavičky je zapsána v násobkách 4
                cout<<inet_ntoa(ip->ip_src)<<" : "<<ntohs(udpH->uh_sport)<<" > "<<inet_ntoa(ip->ip_dst)<<" : "<<ntohs(udpH->uh_dport);
                break;
            case 0x06:
                debug("\nprotokol selector:tcp packet\n");
                const struct tcphdr *tcpH;
                tcpH = (struct tcphdr*)(packet + SIZE_ETHERNET+(ip->ip_hl)*4);   //délka ipv4 hlavičky je zapsána v násobkách 4 
                cout<<inet_ntoa(ip->ip_src)<<" : "<<ntohs(tcpH->th_sport)<<" > "<<inet_ntoa(ip->ip_dst)<<" : "<<ntohs(tcpH->th_dport);
                break;    
            default:
                cerr<<"unsuported protokol, snifing next packet...\n";
                return;break;
        }
    } 
    /*------------------------end of ipv4 section---------------------------*/  
    /*------------------------begin of ipv6 section---------------------------*/    
    else if(ntohs(ethernet->ether_type)==0x86DD){    
        debug("\nselector: ipv6 packet\n");
        const struct ip6_hdr *ip6;
        ip6 = (struct ip6_hdr*)(packet + SIZE_ETHERNET);
        char sourceIp[256];
        char destinationIp[256];
        inet_ntop(AF_INET6, &(ip6->ip6_src), sourceIp, INET6_ADDRSTRLEN); 
        inet_ntop(AF_INET6, &(ip6->ip6_dst), destinationIp, INET6_ADDRSTRLEN);

        int headerShift=SIZE_ETHERNET+6;     //+6 je posun k první hlavičce v paketu    //obecně značí posun v paketu k aktuálně zpracovávané hlavičce
        bool cont=true; //rozhoduje zdali se mají spracovávat další rozšiřující hlavičky 
        bool first=true;//první iterace cyklu na spracování ipv6 hlavičky
        bool udp=false; 
        bool tcp=false;
        bool icmp6=false;
        ip6_ext *extH;
        do {   //rozšiřujících hlaviček může být v paketu neurčité množství a neuspořádaně za sebou-> musíme projít všechny
            extH = (struct ip6_ext*)(packet+headerShift);    //potřeboval jsem pomocnou strukturu pouze na délku a typ další hlavičky, tato byla vhodná...
            switch (extH->ip6e_nxt){
                case 0x11:
                    debug("\nprotokol selector: udp packet\n");  
                    cont=false;
                    udp=true;
                    break;
                case 0x06:  
                    debug("\nprotokol selector: tcp packet\n");
                    tcp=true;
                    cont=false;
                    break;
                case 0x3A:  
                    debug("\nprotokol selector: icmp6 packet\n");
                    icmp6=true;
                    break;    
                case 0x3B:
                    debug("\nno next header\n");
                    cont=false;
                    break;       
            }
            if(first){
                headerShift+= 34;    //+34 =zbytek základní hlavičky ipv6
                first=false;
            }              
            else{                   
                headerShift+=extH->ip6e_len; 
            }
            if(extH->ip6e_len<=0||cont) 
                break;
        } while (cont);   
        //výpis podle protokolu  
        if(tcp){
            const struct tcphdr *tcpH;
            tcpH = (struct tcphdr*)(packet + headerShift);
            cout<<sourceIp<<" : "<<ntohs(tcpH->th_sport)<<" > "<<destinationIp<<" : "<<ntohs(tcpH->th_dport);  
        }
        else if(udp){
            const struct udphdr *udpH;
            udpH = (struct udphdr*)(packet + headerShift);
            cout<<sourceIp<<" : "<<ntohs(udpH->uh_sport)<<" > "<<destinationIp<<" : "<<ntohs(udpH->uh_dport);  
        }
        else if(icmp6)
        {
            cout<<sourceIp<<" > "<<destinationIp;//icmp 6-nemá porty->výpis poouze ip adress
        }
        else
        {
            cout<<"unsuported packet type, snifing next packet...\n";
            return;
        }
    }
    /*------------------------end of ipv6 section---------------------------*/
    else if(ntohs(ethernet->ether_type)==0x0806){    //arp
        debug("\nselector: arp packet\n");
        cout<<ether_ntoa((struct ether_addr*)ethernet->ether_shost)<<" > "<<ether_ntoa((struct ether_addr*)ethernet->ether_dhost);
    }
    else{   //unknow protokol
        cout<<"unsuported packet type, snifing next packet...\n";
        return;
    }

    cout<<", length "<<header.caplen<<" bytes\n";           //výpis celkové délky paketu

    /*------------------------výpis celého paketu---------------------------*/
    for(int j=0;j<header.caplen/16+((header.caplen%16)&&1);j++){   //přičte se jendička pokud je zbytek po celočíselném dělení (přidá iteraci pro plně nenaplněný řádek)
        printf("x%04x: ",j*16);         //výpis ofsetu
        string assci;                   //řetězec pro assci zápis
        int i=0;    
        for (i;i<16;i++){         
            int index=j*16+i;
            if(index>=header.caplen)    //ochrana proti neoprvněnému přístupu do paměti
                break;
            printf("%02x ",int(packet[index])); //výpis hexadecimální číslice z paketu
            assci.push_back(packet[index]>20&&packet[index]<127?packet[index]:'.'); //uložení hexadecomálního zápisu-pokud je znak netisknutelný ukládá se tečka
        }
        for(i;i<16;i++){cout<<"   ";}//padding pro v případě nenaplného řádeku
        cout<<assci<<"\n";  //výpis ascci reprezentace
        if(j==0||j==2)      
            cout<<"\n";
    }
    cout<<"\n";     
}
string filterGen(int port,bool tcp,bool udp,bool arp,bool icmp,bool ipv4,bool ipv6){        //generuje filter pro zachytávač paketů, podle vstupních argumentů
    string filter_exp;
    if(port>0&&port<65535)      //v případě nevalidního portu, se program chová jako by žádný nebyl zadán
        filter_exp="port "+to_string(port)+" and ";
    if(ipv4&&ipv6)
        error(1,"ip verzion selector errr\n");
    if(ipv4)
        filter_exp=filter_exp+"ip and ";
    if(ipv6)
        filter_exp=filter_exp+"ip6 and ";
    if (tcp||udp||arp||icmp)
    {
         filter_exp=filter_exp+"(";
        if(tcp)
            filter_exp=filter_exp+"tcp";
        if(udp){
            if(tcp)
                filter_exp=filter_exp+" or udp";
            else 
                filter_exp=filter_exp+"udp ";
        }
        if(arp){
            if(tcp||udp)
                filter_exp=filter_exp+" or arp";
            else 
                filter_exp=filter_exp+"arp";
        }
        if(icmp){
            if(tcp||udp||arp)
                filter_exp=filter_exp+" or icmp or icmp6";
            else 
                filter_exp=filter_exp+"icmp or icmp6";
        }
        filter_exp=filter_exp+")";
    }
    else
    {
        filter_exp=filter_exp+"(tcp or udp or arp or icmp or icmp6)";
    }
    debug("filtering exp::\n"+filter_exp+"\n---------------------------------\n");
    return filter_exp;
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
void argParste(bool *udp,bool *tcp,bool *arp,bool *icmp,string *interface,int *n,int *port,int argc,char **argv,bool *ipv4,bool *ipv6)    //funkce na parsování argmuntů
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
        else if(!(strcmp(argv[i],"--ipv4"))){
            *ipv4=true;
        }
        else if(!(strcmp(argv[i],"--ipv6"))){
            *ipv6=true;
        }
        else if(!(strcmp(argv[i],"-h"))||!(strcmp(argv[i],"--help"))){
            cerr<<"./ipk-sniffer [-i interfaceName | --interface interfaceName] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp]  [--ipv4]  [--ipv6] } {-n num}\n";
            cerr<<"This program snifing packet on ethernet interface, you can select which types of packet you want snif. \n";
            cerr<<"After packet is snifed program prints few infos about packet and print whole packet in hexadecimal form\n";
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