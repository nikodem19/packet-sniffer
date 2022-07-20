#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <time.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

//callback funkce pro zpracovani dat packetu
void callback_for_packet(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    char CAS[100];
    int x = pkthdr->len;
    time_t ttime = pkthdr->ts.tv_sec;
    struct tm *tmp = localtime(&ttime);
    char format[] = "%H:%M:%S";
    strftime(CAS,sizeof(CAS), format,tmp);
    unsigned int sourceIP2[4] = {packet[26], packet[27], packet[28], packet[29] };
    unsigned int destinationIP[4] = {packet[30], packet[31], packet[32], packet[33] };
    unsigned int sourcePort = packet[34] << 8 | packet[35];
    unsigned int destPort = packet[36] << 8 | packet[37];
    char sourceIP[300], destIP[300];
    sprintf(sourceIP, "%d.%d.%d.%d",sourceIP2[0],sourceIP2[1],sourceIP2[2],sourceIP2[3]);
    sprintf(destIP, "%d.%d.%d.%d",destinationIP[0],destinationIP[1],destinationIP[2],destinationIP[3]);
    struct sockaddr_in srcHOST;
    srcHOST.sin_family = AF_INET;
    srcHOST.sin_port = sourcePort;
    inet_aton(sourceIP, &srcHOST.sin_addr);
    char SRChostt[200];
    int SRC = getnameinfo((struct sockaddr *)&srcHOST,sizeof(srcHOST),&SRChostt[0],200,NULL,0,0);
    struct sockaddr_in destHOST;
    destHOST.sin_family = AF_INET;
    destHOST.sin_port = destPort;
    inet_aton(destIP, &destHOST.sin_addr);
    char DSThostt[200];
    int DST = getnameinfo((struct sockaddr *)&destHOST,sizeof(destHOST),&DSThostt[0],200,NULL,0,0);

    if(SRC == 0 && DST == 0)
        printf("%s.%06ld %s : %d > %s : %d\n length: %d\n",CAS,pkthdr->ts.tv_usec,SRChostt,sourcePort,DSThostt,destPort,x);
    else if(SRC == 0 && DST)
        printf("%s.%06ld %s : %d > %s : %d\n length: %d\n",CAS,pkthdr->ts.tv_usec,SRChostt,sourcePort,destIP,destPort,x);
    else if(SRC && DST == 0)
        printf("%s.%06ld %s : %d > %s : %d\n length: %d\n",CAS,pkthdr->ts.tv_usec,sourceIP,sourcePort,DSThostt,destPort,x);
    else
        printf("%s.%06ld %s : %d > %s : %d\n length: %d\n",CAS,pkthdr->ts.tv_usec,sourceIP,sourcePort,destIP,destPort,x);


    unsigned char *output;
    output = malloc(x*sizeof(unsigned char));
    if (output == NULL)
        exit(1);
    printf(" ");
    for (int q = 0; q < x; ++q)
    {
        if(q % 8 == 0 && q != 0) printf(" ");
        if(q % 16 == 0 && q != 0)
        {
            printf(" ");
            for(int d = q-16; d < q; ++d)
            {
                if(d % 8 == 0) printf(" ");
                printf("%c", output[d]);
            }
            printf("\n");
        }
        if (q > 0) printf(" ");
        if(q % 16 == 0) printf("0x%04X: ",q);
        printf("%02x",packet[q]);
        //0xff
        if((int)packet[q] >= 32 && (int)packet[q] <= 127)
        {
            output[q] =(unsigned char) packet[q];
        }
        else
        {
            output[q] = '.';
        }
        if(q + 1 == x && q % 16 != 0)
        {
            printf("  ");
            for(int d = x - (q % 16) - 1; d < x; ++d)
            {
                if(d % 8 == 0 && d != 0) printf(" ");
                printf("%c", output[d]);
            }
            printf("\n");
        }
    }
    free(output);
    return;
}

int main(int argc, char *argv[])
{
        int snaplen = 65535;
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *open_dev = NULL;
        pcap_if_t *alldevs = NULL;
        int count = 1;
        char *port = NULL;
        char *interface = NULL;
        struct pcap_pkthdr header;
        static struct option long_options[] = {{"tcp", 0, NULL, 'x'}, {"udp", 0, NULL, 'y'}};
        int argument = getopt_long(argc, argv, "i:p:n:tu", long_options ,NULL);
        bool tcp = false, udp = false;
        char *protokol = NULL;
        struct ether_header *ether_ptr;
        bpf_u_int32 maska;
        bpf_u_int32 netip;


        while(argument != -1)
        {
            switch (argument)
            {
                case 't':
                case 'x': // tcp
                    tcp = true;
                    break;
                case 'y':
                case 'u': // udp
                    udp = true;
                    break;
                case 'i':
                    printf("%s\n",optarg);
                    interface = optarg;
                    break;
                case 'p':
                    port = optarg;
                    break;
                case 'n':
                    count = atoi(optarg);
                    break;
                case '?':
                    break;
                default:
                    fprintf(stderr, "Error: wrong argument\n");
                    return 1 ;
            }
            argument = getopt_long(argc, argv, "i::p:n:tu", long_options ,NULL);
        }
        //najdi vsechna dostupna rozhrani
        if(interface == NULL)
        {
            if(pcap_findalldevs(&alldevs, errbuf))
            {
                fprintf(stderr, "Nastal error: %s\n", errbuf);
                return(1);
            }
            printf("Zoznam dostupnych rozhrani:\n");
            //vypis vsech rozhrani
            while(alldevs)
            {
                printf("%s\n", alldevs->name);
                alldevs = alldevs->next;
            }
            return 0;
        }
        //printf("DEBUG: %s\n",interface);

        //ziska handle
        open_dev = pcap_open_live(interface, snaplen, 1, 0, errbuf);
        if (open_dev == NULL)
        {
            fprintf(stderr, "Error: %s\n", errbuf);
            return(1);
        }

        if( pcap_lookupnet(interface,&netip,&maska,errbuf) < 0 )
        {
            printf("pcap_lookupnet: %s\n", errbuf);
            return 1;
        }
        //proces nastaveni filteru
        struct bpf_program fp;
        if(tcp == true)
        {
            char ppp[4] = "tcp";
            protokol = realloc(protokol, sizeof(protokol) + sizeof(ppp));
            if (protokol == NULL) return 1;
            protokol = strcat(protokol, ppp);
        }
        if(udp == true)
        {
            if(protokol == NULL)
            {
                char ppp[4] = "udp";
                protokol = realloc(protokol, sizeof(protokol) + sizeof(ppp));
                if (protokol == NULL) return 1;
                protokol = strcat(protokol, ppp);
            }
            else
            {
                free(protokol);
                char ppp[14] = "(tcp or udp)";
                protokol = realloc(protokol, sizeof(protokol) + sizeof(ppp));
                if (protokol == NULL) return 1;
                protokol = strcat(protokol, ppp);
            }
        }

        if(port != NULL)
        {
            if(protokol == NULL)
            {
                char ppp[9] = "port ";
                protokol = realloc(protokol,sizeof(protokol)+sizeof(ppp)+sizeof(port));
                if (protokol == NULL) return 1;
                protokol = strcat(protokol, ppp);
                protokol = strcat(protokol, port);
            }
            else
            {
                char ppp[12] = " and port ";
                protokol = realloc(protokol,sizeof(protokol)+sizeof(ppp)+sizeof(port));
                if (protokol == NULL) return 1;
                protokol = strcat(protokol, ppp);
                protokol = strcat(protokol, port);
            }

        }
        //printf("DEBUG: %s\n", protokol);

        if(pcap_compile(open_dev, &fp, protokol, 0, maska) == -1)
        {
            pcap_perror(open_dev,"prefix:");
            printf("%s\n", pcap_geterr(open_dev));
            fprintf(stderr, "Error: chyba pri kompilovani\n");
            return 1;
        }
        if(pcap_setfilter(open_dev, &fp) < 0)
        {
            fprintf(stderr, "Error: nefunkcny filter\n");
            return 1;
        }

        pcap_loop(open_dev,count,callback_for_packet,NULL);
        pcap_close(open_dev);
        free(protokol);
        return(0);
}
