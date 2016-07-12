#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "pcap.h"
#include <stdio.h>
#include <winsock2.h>

#pragma comment (lib, "wpcap.lib")
#pragma comment (lib, "ws2_32.lib" )


struct ip_header
{
	unsigned char ip_header_len : 4;
	unsigned char ip_version : 4;
	unsigned char ip_tos;
	unsigned short ip_total_length;
	unsigned short ip_id;
	unsigned char ip_frag_offset : 5;
	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;
	unsigned char ip_frag_offset1;
	unsigned char ip_ttl;
	unsigned char ip_protocol;
	unsigned short ip_checksum;
	struct in_addr ip_srcaddr;
	struct in_addr ip_destaddr;
};

struct tcp_header
{
	unsigned short source_port;
	unsigned short dest_port;
	unsigned int sequence;
	unsigned int acknowledge;
	unsigned char ns : 1;
	unsigned char reserved_part1 : 3;
	unsigned char data_offset : 4;
	unsigned char fin : 1;
	unsigned char syn : 1;
	unsigned char rst : 1;
	unsigned char psh : 1;
	unsigned char ack : 1;
	unsigned char urg : 1;
	unsigned char ecn : 1;
	unsigned char cwr : 1;
	unsigned short window;
	unsigned short checksum;
	unsigned short urgent_pointer;
};

struct ether_addr
{
	unsigned char ether_addr_octet[6];
};

struct ether_header
{
	struct  ether_addr ether_dhost;
	struct  ether_addr ether_shost;
	unsigned short ether_type;
};


void print_ether_header(const unsigned char *data)
{
	struct  ether_header *eh;              
	unsigned short ether_type;
	eh = (struct ether_header *)data;       
	ether_type = ntohs(eh->ether_type);      

	if (ether_type != 0x0800) // 이더넷 형태 체크 
	{
		printf("ETHER TYPE WRONG\n");
		return;
	}
	// 이더넷 헤더 출력
	printf("\n=========ETHERNET HEADER==========\n");
	printf("DMAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", 
		eh->ether_dhost.ether_addr_octet[0],
		eh->ether_dhost.ether_addr_octet[1],
		eh->ether_dhost.ether_addr_octet[2],
		eh->ether_dhost.ether_addr_octet[3],
		eh->ether_dhost.ether_addr_octet[4],
		eh->ether_dhost.ether_addr_octet[5]);
	printf("SMAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n",
		eh->ether_shost.ether_addr_octet[0],
		eh->ether_shost.ether_addr_octet[1],
		eh->ether_shost.ether_addr_octet[2],
		eh->ether_shost.ether_addr_octet[3],
		eh->ether_shost.ether_addr_octet[4],
		eh->ether_shost.ether_addr_octet[5]);
}

void print_ip_header(const unsigned char *data)
{
	struct  ip_header *ih;
	ih = (struct ip_header *)data;  

	printf("\n============IP HEADER=============\n");

	//printf("IPv%d ver \n", ih->ip_version); // IPV4 IPV6 판단

	if (ih->ip_version!=4 || ih->ip_protocol != 0x06)  // IPV4, tcp일 경우에만 진행
	{
		printf("NOT IPV4 OR NOT TCP");
		return;
	}

	// SIP DIP 출력 
	printf("SIP Addr : %s\n", inet_ntoa(ih->ip_srcaddr));
	printf("DIP Addr : %s\n", inet_ntoa(ih->ip_destaddr));

	return;
}

void print_tcp_header(const unsigned char *data)
{
	struct  tcp_header *th;
	th = (struct tcp_header *)data;

	// SPORT DPORT 출력
	printf("\n============TCP HEADER============\n");
	printf("SPort Num : %d\n", ntohs(th->source_port));
	printf("DPort Num : %d\n", ntohs(th->dest_port));
	printf("\n\n");

	return;
}


int main(){
	pcap_if_t *alldevs = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	int offset = 0;

	// device 찾기 
	if (pcap_findalldevs(&alldevs, errbuf) == -1){
		printf("dev find failed\n");
		return -1;
	}
	if (alldevs == NULL){
		printf("no devs found\n");
		return -1;
	}

	// device 선택 유선1, 무선4
	pcap_if_t *d; int i;
	for (d = alldevs, i = 0; d != NULL; d = d->next)
		printf("%d dev: %s \n", ++i, d->name);

	int inum;

	printf("SELECT DEVICE NUMBER: ");
	scanf("%d", &inum);
	for (d = alldevs, i = 0; i<inum - 1; d = d->next, i++);

	// PCAP OPEN
	pcap_t  *fp;
	if ((fp = pcap_open_live(d->name,      // name of the device
		80,                   // capture size
		1,  // promiscuous mode
		1,                    // read timeout
		errbuf
		)) == NULL){
		printf("pcap open failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("pcap open successful\n");

	// free devices 
	pcap_freealldevs(alldevs); 

	// 선언된 헤더 구조체
	struct pcap_pkthdr *header;
	const unsigned char *pkt_data;
	int res;

	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0){
		if (res == 0) continue;

		print_ether_header(pkt_data);   // 이더넷 헤더 출력
		pkt_data = pkt_data + 14;       // 이더넷 + 14
		print_ip_header(pkt_data);      // 아이피 헤더 출력
		pkt_data = pkt_data + 20;       // IP + 20 
		print_tcp_header(pkt_data);     // tcp 헤더 출력
	}
	return 0;

}

