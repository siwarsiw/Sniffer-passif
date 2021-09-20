#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<features.h>
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include<errno.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
//#include<linux/ip.h>
//#include<linux/tcp.h>
#include<netinet/in.h>

// protocol_to_sniff est le protocole niveau liaison. ça sera le protocole ETHERNET
// car nous allons faire du sniffing sur un réseau local de type ETHERNET
int Creation_socket(int protocol_to_sniff)
{
        int rawsock;
// rawsock est un type d’un socket  qui est compatible avec les deux protocoles tcp/ip
//aAinsi que avec le protocole ethernet
        if((rawsock= socket(PF_PACKET, SOCK_RAW, htons(protocol_to_sniff)))== -1)
        {
                printf("Erreur de creation de socket!! ");
                exit(-1);
        }

        return rawsock;//sinon on a créé le rawsocket 
}
int liaison_Socket_a_interface(char *device, int i, int protocol)
{
        struct sockaddr_ll sock;
        struct ifreq ifr;

        bzero(&sock, sizeof(sock));
//La fonction bzero() met à 0 les n premiers octets du bloc pointé par sock ;
        bzero(&ifr, sizeof(ifr));
//La fonction bzero() met à 0 les n premiers octets du bloc pointé par ifr ;
/*premiérement il faut trouver l’index de l’interface*/ 
   
      strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
        if((ioctl(i, SIOCGIFINDEX, &ifr)) == -1)
        {
                printf("Erreur d'obtenir l'index interface \n");
                exit(-1);
        }

//on a lier rawsocket avec notre nouvel interface  
        sock.sll_family = AF_PACKET;
        sock.sll_ifindex = ifr.ifr_ifindex;
        sock.sll_protocol = htons(protocol);
        if((bind(i, (struct sockaddr *)&sock, sizeof(sock)))== -1)
        {
                printf("Erreur de lier socket à l'interface !");
                exit(-1);
        }

        return 1;

}
// vous ne recevrez que les paquets arrivant sur cette interface, sinon vous devriez recevoir les paquets de toutes les interfaces locales configurées * /
void afficher_paquet_en_hexa( char *p, int a)
{
        
        char *pq = p;
        printf("Packet de début \n \n");

        while(a--)
        {
                printf("%.2x ", *pq);
                pq++;
        }
        printf("\npaquet terminé \n\n");
}


void Afficher_en_hex(char *ch, char *p, int a)
{
        printf("%s",ch);
        while(a--)
        {
                printf("%.2X ", *p);
              printf("%c",*p);
                p++;
        }
}


Analyser_entete_ethernet(char *packet, int a)
{
        struct ethhdr *entete_ethernet;

        if(a > sizeof(struct ethhdr))
        {
                entete_ethernet= (struct ethhdr *)packet;
                /* Le premier ensemble de 6 octets est MAC de destination */
	 //MAC :media acess controle
                Afficher_en_hex("Destination MAC: ", entete_ethernet->h_dest, 6);
                printf("\n");
                /* le deuxieme ensemble de 6 octets est MAC de source*/
                Afficher_en_hex("Source MAC: ", entete_ethernet->h_source, 6);
                printf("\n");
/* Les 2 derniers octets de l'en-tête Ethernet correspondent au protocole qu'il transporte. */
                Afficher_en_hex("Protocol: ",(void *)&entete_ethernet->h_proto, 2);
                printf("\n");
        }
        else
        {
                printf("taille de packet est insuffisant! \n");
        }
}




Analyser_entete_ip(char *packet, int a)
{
        struct ethhdr *entete_ethernet;
        struct iphdr *entete_ip;
/* Vérifie si le paquet contient un en-tête IP en utilisant l'en-tête Ethernet */
        entete_ethernet = (struct ethhdr *)packet;
        if(ntohs(entete_ethernet->h_proto) == ETH_P_IP)
        {
                // * L'en-tête IP est après l'en-tête Ethernet * /
                if(a >= (sizeof(struct ethhdr) + sizeof(struct iphdr)))
                {
                        entete_ip = (struct iphdr*)(packet + sizeof(struct ethhdr));
	/*afficher la source et la destination de l’adresse ip*/
                printf("TTL: %d \n",entete_ip->ttl);
                printf("Adresse de Destination IP: %s\n", inet_ntoa( *(struct in_addr*)&entete_ip->daddr));
                printf("Adresse de Source IP : %s\n", inet_ntoa( *(struct in_addr*)&entete_ip->saddr));
                }
                else
                {
                        printf("Le paquet IP n'a pas d'en-tête complet !\n");
                }
        }
        else
        {
               printf(" Pas un paquet IP! \n");
        }
}
Analyser_entete_TCP( char *packet , int a)
{
        struct ethhdr *entete_ethernet;
        struct iphdr *entete_ip;
        struct tcphdr *entete_tcp;
/* Vérifie s'il y a suffisamment d'octets pour l'en-tête TCP */
        if(a>= (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)))
        {
/* Est-ce que toutes les vérifications: 1. Est-ce un pkt IP? 2. est-ce que c'est TCP? */
                entete_ethernet = (struct ethhdr *)packet;
                if(ntohs(entete_ethernet->h_proto) == ETH_P_IP)
                {
                        entete_ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
                        if(entete_ip->protocol == IPPROTO_TCP)
                        {
                           printf("TCP num:%d\n",entete_ip->protocol);
                                entete_tcp = (struct tcphdr*)(packet + sizeof(struct ethhdr) + entete_ip->ihl*4 );
/* Affiche les ports Destination et Source */
                                printf("Source Port: %d\n", ntohs(entete_tcp->source));
                                printf("Destination Port: %d\n", ntohs(entete_tcp->dest));
                        }
                        else
                        {
                                printf("Pas un paquet TCP\n");
                        }
                }
                else
                {
                        printf("Pas un paquet IP\n");
                }
        }
        else
        {
                printf("En-tête TCP non présent\n");
        }
}
int ParseData(char *packet, int a)
{
        struct ethhdr *entete_ethernet;
        struct iphdr *entete_ip;
        struct tcphdr *entete_tcp;
        char *data;
        int len;
/* Vérifie s'il y a des données */
        if(a > (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)))
        {
                entete_ip = (struct iphdr*)(packet + sizeof(struct ethhdr));
                data = (packet + sizeof(struct ethhdr) + entete_ip->ihl*4 +sizeof(struct tcphdr));
                len = ntohs(entete_ip->tot_len) - entete_ip->ihl*4 - sizeof(struct tcphdr);
                if(len)
                {
                        printf("Data Len : %d\n", len);
                        printf("%s\n",(char*)data);
                        printf("\n");
                        Afficher_en_hex("Data : ", data,len);
                        printf("\n");
                        return 1;
                }
                else
                {
                        printf("Aucune donnée dans le paquet! \n");
                        return 0;
                }
        }
        else
        {
                printf("Aucune donnée dans le paquet!! \n");
                return 0;
        }
}
int ip_and_tcp_paquet(unsigned char *packet, int len)
{
        struct ethhdr *entete_ethernet;
        struct iphdr *entete_ip;
        entete_ethernet = (struct ethhdr *)packet;
        if(ntohs(entete_ethernet->h_proto) == ETH_P_IP)
        {
                entete_ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
                if(entete_ip->protocol == IPPROTO_TCP)
                        return 1;
                else
                        return -1;
        }
        else
        {
                return -1;
        }
}

main(int argc, char **argv)
{
        int raw;
        char packet_buffer[2048];
        int len;
        int packets_to_sniff;
        struct sockaddr_ll packet_info;
        int packet_info_size = sizeof(packet_info);

        if (argc < 3 )
        {
                printf("\n");
                printf("Usage: ./sniffer <Interface> <Nbr of packets to sniff>\n");
                printf("\n");
                return (EINVAL);
        }
        /* creation de la rawsocket*/
        raw = Creation_socket(ETH_P_IP);

        /* lier le socket a l’interface*/
        liaison_Socket_a_interface(argv[1], raw, ETH_P_IP);
/* Récupère le nombre de paquets à renifler de l'utilisateur */
        packets_to_sniff = atoi(argv[2]);
/* Commencez à sniffer et imprimez Hex de chaque paquet */
        while(packets_to_sniff--)
        {
                if((len = recvfrom(raw, packet_buffer, 2048, 0, (struct sockaddr*)&packet_info, (socklen_t*)&packet_info_size)) == -1)
                {
                        perror("Recv de retour -1: ");
                        exit(-1);
                }
                else
                {
                      //* Le paquet a été reçu avec succès /

afficher_paquet_en_hexa(packet_buffer, len);
                  /*afficher entete ethernet */
                  //analyser_entete_ethernet(packet_buffer, len);
                  /* analyser entete ip */
                  //analyser_entete_ip(packet_buffer, len);
                  /* analyser entete tcp */
                  //analyser_entete_tcp(packet_buffer, len);
                  /* analyser entete udp */
                  //ParseUdpHeader(packet_buffer, len);
                  /*if(ip_and_tcp_paquet(packet_buffer, len))
{
if(!ParseData(packet_buffer, len))
packets_to_sniff++;
}*/	
}
     }
      return 0;
}
